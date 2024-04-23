# coding: utf-8
# Copyright (c) 2024 OceanBase.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import List
from enum import Enum

from model.version import Version


class AgentInfo:

    def __init__(self, identity: str, version: str, auth_version: str, supported_auth: List[str]):
        self.identity = Agentidentity(identity)
        self.version = Version(version)
        self.auth_version = auth_version
        self.supported_auth = supported_auth

    def is_supported_auth(self, auth_type: str) -> bool:
        return auth_type in self.supported_auth


class Agentidentity(Enum):
	MASTER              = "MASTER"
	FOLLOWER            = "FOLLOWER"
	SINGLE              = "SINGLE"
	CLUSTER_AGENT       = "CLUSTER AGENT"
	TAKE_OVER_MASTER    = "TAKE OVER MASTER"
	TAKE_OVER_FOLLOWER  = "TAKE OVER FOLLOWER"
	SCALING_OUT         = "SCALING OUT"
	UNIDENTIFIED        = "UNIDENTIFIED"
