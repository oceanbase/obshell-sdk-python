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

from .format import model_str
from obshell.model.version import Version
from obshell.auth.base import AuthVersion


class AgentInfo:

    def __init__(self,
                 identity: str,
                 version: str,
                 supported_auth: List[str]):
        self.identity = Agentidentity(identity)
        self.version = Version(version)
        self.supported_auth = [AuthVersion(version)
                               for version in supported_auth]

    def is_supported_auth(self, auth_type: str) -> bool:
        return auth_type in self.supported_auth


class Agentidentity(Enum):
    MASTER = "MASTER"
    FOLLOWER = "FOLLOWER"
    SINGLE = "SINGLE"
    CLUSTER_AGENT = "CLUSTER AGENT"
    TAKE_OVER_MASTER = "TAKE OVER MASTER"
    TAKE_OVER_FOLLOWER = "TAKE OVER FOLLOWER"
    SCALING_OUT = "SCALING OUT"
    UNIDENTIFIED = "UNIDENTIFIED"


class ServerConfig:

    def __init__(self, data: dict):
        self.svr_ip = data.get("svr_ip", 0)
        self.svr_port = data.get("svr_port", 0)
        self.sql_port = data.get("sql_port", 0)
        self.agent_port = data.get("agent_port", 0)
        self.with_rootserver = data.get("with_rootserver", "")
        self.status = data.get("status", "")
        self.build_version = data.get("build_version", "")

    @classmethod
    def from_dict(cls, data: dict):
        return ServerConfig(data)

    def __str__(self) -> str:
        return model_str(self)


class ClusterConfig:

    def __init__(self, data: dict):
        self.cluster_id = data.get("id")
        self.cluster_name = data.get("name")
        self.version = data.get("version")
        self.zone_config = {}
        if data.get("topology"):
            self.zone_config = {zone: [ServerConfig.from_dict(item) for item in server]
                                for zone, server in data.get("topology", {}).items()}

    @classmethod
    def from_dict(cls, data: dict):
        return ClusterConfig(data)

    def __str__(self) -> str:
        return model_str(self)


class AgentInstance:

    def __init__(self, data: dict):
        self.identity = data.get("identity")
        self.version = data.get("version")
        self.zone = data.get("zone")
        self.ip = data.get("ip")
        self.port = data.get("port")

    @classmethod
    def from_dict(cls, data: dict):
        return AgentInstance(data)

    def __str__(self) -> str:
        return model_str(self)


class ObInfo:

    def __init__(self, data: dict):
        self.agents = []
        if data.get("agent_info"):
            self.agents = ([AgentInstance.from_dict(agent)
                            for agent in data.get("agent_info", [])])

        self.cluster = (ClusterConfig.from_dict(data.get("obcluster_info"))
                        if data.get("obcluster_info") else None)

    @classmethod
    def from_dict(cls, data: dict):
        return ObInfo(data)

    def __str__(self) -> str:
        return model_str(self)


class AgentInfoWithIdentity:

    def __init__(self, data: dict):
        self.ip = data.get("ip")
        self.port = data.get("port")
        self.identity = data.get("identity")

    @classmethod
    def from_dict(cls, data: dict):
        return AgentInfoWithIdentity(data)

    def __str__(self) -> str:
        return model_str(self)


class AgentStatusWithOb:

    def __init__(self, data: dict):
        self.agent = AgentInfoWithIdentity.from_dict(data.get("agent"))
        self.state = data.get("state")
        self.version = data.get("version")
        self.pid = data.get("pid")
        self.start_at = data.get("start_at")
        self.ob_state = data.get("obState")
        self.under_maintenance = data.get("under_maintenance")

    @classmethod
    def from_dict(cls, data: dict):
        return AgentStatusWithOb(data)

    def __str__(self) -> str:
        return model_str(self)


class AgentStatusWithZone:

    def __init__(self, data: dict):
        self.zone = data.get("zone", "")
        self.state = data.get("state", 0)
        self.version = data.get("version", "")
        self.pid = data.get("pid", 0)
        self.start_at = data.get("startAt", "")
        self.identity = data.get("identity", "")
        self.home_path = data.get("homePath", "")
        self.ip = data.get("ip", "")
        self.port = data.get("port", 0)

    @classmethod
    def from_dict(cls, data: dict):
        return AgentStatusWithZone(data)

    def __str__(self) -> str:
        return model_str(self)
