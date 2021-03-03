# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Schemas for the global rules-changelog."""

import dataclasses
import time
from typing import Dict, List

import marshmallow_dataclass
from marshmallow import validate

from .definitions import BaseMarshmallowDataclass, Date, PR_PATTERN, SemVer, Sha256 as Sha256Field, Uuid


@marshmallow_dataclass.dataclass
class Change(BaseMarshmallowDataclass):
    """Changelog entry changes."""

    message: str = dataclasses.field(metadata=dict(validates=validate.Length(min=1)))
    pull_request: str = dataclasses.field(metadata=dict(validates=validate.Regexp(PR_PATTERN)))
    sha256: Sha256Field
    date: Date = dataclasses.field(default=lambda: time.strftime('%Y/%m/%d'))


@marshmallow_dataclass.dataclass
class ChangelogEntry(BaseMarshmallowDataclass):
    """Schema for a changelog entry in the global changelog."""

    changes: List[Change] = dataclasses.field(metadata=dict(validates=validate.Length(min=1)))
    minimum_kibana_version: SemVer
    rule_version: int = dataclasses.field(metadata=dict(validates=validate.Range(min=1)))
    date: Date = dataclasses.field(default=lambda: time.strftime('%Y/%m/%d'))


@marshmallow_dataclass.dataclass
class Changelog(BaseMarshmallowDataclass):
    """Schema for a changelog in the global changelog."""

    changelog: Dict[Uuid, List[ChangelogEntry]]
