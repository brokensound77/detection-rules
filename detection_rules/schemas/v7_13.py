# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

"""Definitions for rule metadata and schemas."""

from .v7_12 import ApiSchema712


class ApiSchema713(ApiSchema712):
    """Schema for siem rule in API format."""

    STACK_VERSION = "7.13"
