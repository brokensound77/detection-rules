# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Load rule metadata transform between rule and api formats."""
import os
import re
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List

import click
import pytoml

from .mappings import RtaMappings
from .rule import RULES_DIR, Rule
from .schemas import CurrentSchema
from .utils import get_path, cached

# backwards compat to 3.7 - typing.OrderedDict was added in 3.7.2
try:
    from typing import OrderedDict as OrderedDictType
except ImportError:
    from typing import MutableMapping
    OrderedDictType = MutableMapping


RTA_DIR = get_path("rta")


@cached
def get_non_required_defaults_by_type(rule_type: str) -> dict:
    """Get list of fields which are not required for a specified rule type."""
    schema = CurrentSchema.get_schema(rule_type)
    properties = schema['properties']
    non_required_defaults = {prop: properties[prop].get('default') for prop in properties
                             if prop not in schema['required'] and 'default' in properties[prop]}
    return non_required_defaults


def find_unneeded_defaults_from_rule(rule: Rule) -> dict:
    """Remove values that are not required in the schema which are set with default values."""
    unrequired_defaults = get_non_required_defaults_by_type(rule.type)
    default_matches = {p: rule.contents[p] for p, v in unrequired_defaults.items()
                       if p in rule.contents and rule.contents[p] == v}
    return default_matches


class RuleLoader:
    """Support class for loading rules."""

    FILE_PATTERN = r'^([a-z0-9_])+\.(json|toml)$'

    @classmethod
    def reset(cls):
        """Clear all rule caches."""
        cls.load_rule_files.clear()
        cls.load_rules.clear()
        cls.get_rule.clear()
        cls.filter_rules.clear()

    @classmethod
    @cached
    def load_rule_files(cls, paths: List[Path] = None, verbose=False) -> Dict[str, dict]:
        """Load the rule YAML files, but without parsing the query portion."""
        file_lookup = {}

        if paths is None:
            paths = sorted(Path(RULES_DIR).rglob('*.toml'))

        if verbose:
            print("Loading rules from {}".format(paths))

        for rule_file in paths:
            try:
                # use pytoml instead of toml because of annoying bugs
                # https://github.com/uiri/toml/issues/152
                # might also be worth looking at https://github.com/sdispater/tomlkit
                file_lookup[str(rule_file)] = pytoml.loads(rule_file.read_text())
            except Exception:
                print(f"Error loading: {rule_file}")
                raise

        if verbose:
            print(f"Loaded {len(file_lookup)} rules")

        return file_lookup

    @classmethod
    @cached
    def load_rules(cls, file_lookup: Dict[str, dict] = None, verbose=False, error=True) -> OrderedDictType[str, Rule]:
        """Load all the rules from toml files."""
        file_lookup = file_lookup or cls.load_rule_files(verbose=verbose)

        failed = False
        rules: List[Rule] = []
        errors = []
        queries = []
        query_check_index = []
        rule_ids = set()
        rule_names = set()

        for rule_file, rule_contents in file_lookup.items():
            try:
                rule = Rule(rule_file, rule_contents)

                if rule.id in rule_ids:
                    existing = next(r for r in rules if r.id == rule.id)
                    raise KeyError(f'{rule.path} has duplicate ID with \n{existing.path}')

                if rule.name in rule_names:
                    existing = next(r for r in rules if r.name == rule.name)
                    raise KeyError(f'{rule.path} has duplicate name with \n{existing.path}')

                parsed_query = rule.parsed_query
                if parsed_query is not None:
                    # duplicate logic is ok across query and threshold rules
                    threshold = rule.contents.get('threshold', {})
                    duplicate_key = (parsed_query, rule.type, threshold.get('field'), threshold.get('value'))
                    query_check_index.append(rule)

                    if duplicate_key in queries:
                        existing = query_check_index[queries.index(duplicate_key)]
                        raise KeyError(f'{rule.path} has duplicate query with \n{existing.path}')

                    queries.append(duplicate_key)

                if not re.match(cls.FILE_PATTERN, os.path.basename(rule.path)):
                    raise ValueError(f'{rule.path} does not meet rule name standard of {cls.FILE_PATTERN}')

                rules.append(rule)
                rule_ids.add(rule.id)
                rule_names.add(rule.name)

            except Exception as e:
                failed = True
                err_msg = f"Invalid rule file in {rule_file}\n{click.style(e.args[0], fg='red')}"
                errors.append(err_msg)
                if error:
                    if verbose:
                        print(err_msg)
                    raise e

        if failed:
            if verbose:
                for e in errors:
                    print(e)

        return OrderedDict([(rule.id, rule) for rule in sorted(rules, key=lambda r: r.name)])

    @classmethod
    @cached
    def load_github_pr_rules(cls, labels: list = None, repo: str = 'elastic/detection-rules', token=None, threads=50,
                             verbose=False):
        """Load all rules active as a GitHub PR."""
        import requests
        import pytoml
        from multiprocessing.pool import ThreadPool
        from pathlib import Path
        from .misc import GithubClient

        github = GithubClient(token=token)
        repo = github.client.get_repo(repo)
        labels = set(labels or [])
        open_prs = [r for r in repo.get_pulls() if not labels.difference(set(list(lbl.name for lbl in r.get_labels())))]

        new_rules: List[Rule] = []
        modified_rules: List[Rule] = []
        errors: Dict[str, list] = {}

        existing_rules = cls.load_rules(verbose=False)
        pr_rules = []

        if verbose:
            click.echo('Downloading rules from GitHub PRs')

        def download_worker(pr_info):
            pull, rule_file = pr_info
            response = requests.get(rule_file.raw_url)
            try:
                raw_rule = pytoml.loads(response.text)
                rule = Rule(rule_file.filename, raw_rule)
                rule.gh_pr = pull

                if rule.id in existing_rules:
                    modified_rules.append(rule)
                else:
                    new_rules.append(rule)

            except Exception as e:
                errors.setdefault(Path(rule_file.filename).name, []).append(str(e))

        for pr in open_prs:
            pr_rules.extend([(pr, f) for f in pr.get_files()
                             if f.filename.startswith('rules/') and f.filename.endswith('.toml')])

        pool = ThreadPool(processes=threads)
        pool.map(download_worker, pr_rules)
        pool.close()
        pool.join()

        new = OrderedDict([(rule.id, rule) for rule in sorted(new_rules, key=lambda r: r.name)])
        modified = OrderedDict()

        for modified_rule in sorted(modified_rules, key=lambda r: r.name):
            modified.setdefault(modified_rule.id, []).append(modified_rule)

        return new, modified, errors

    @classmethod
    @cached
    def get_rule(cls, rule_id=None, rule_name=None, file_name=None, verbose=False) -> Rule:
        """Get a rule based on its id."""
        rules_lookup: Dict[str, Rule] = cls.load_rules(verbose=verbose)
        if rule_id is not None:
            return rules_lookup.get(rule_id)

        for rule in rules_lookup.values():
            if rule.name == rule_name:
                return rule
            elif rule.path == file_name:
                return rule

    @classmethod
    def get_rule_name(cls, rule_id, verbose=False) -> str:
        """Get the name of a rule given the rule id."""
        rule = cls.get_rule(rule_id, verbose=verbose)
        if rule:
            return rule.name

    @classmethod
    def get_file_name(cls, rule_id, verbose=False) -> str:
        """Get the file path that corresponds to a rule."""
        rule = cls.get_rule(rule_id, verbose=verbose)
        if rule:
            return rule.path

    @classmethod
    def get_rule_contents(cls, rule_id, verbose=False) -> dict:
        """Get the full contents for a rule_id."""
        rule = cls.get_rule(rule_id, verbose=verbose)
        if rule:
            return rule.contents

    @classmethod
    @cached
    def filter_rules(cls, rules, metadata_field, value) -> List[Rule]:
        """Filter rules based on the metadata."""
        return [rule for rule in rules if rule.metadata.get(metadata_field, '') == value]

    @classmethod
    def get_production_rules(cls, verbose=False) -> List[Rule]:
        """Get rules with a maturity of production."""
        return cls.filter_rules(cls.load_rules(verbose=verbose).values(), 'maturity', 'production')


rta_mappings = RtaMappings()


__all__ = (
    "RuleLoader",
    "get_non_required_defaults_by_type",
    "rta_mappings",
    "find_unneeded_defaults_from_rule"
)
