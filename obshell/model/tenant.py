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

from .format import model_str, CustomPage
from .resource_pool import ResourcePoolWithUnit


class ZoneParam:
    """The properties of the zone and the replica on the zone.

    Used by create_tenant/add_tenant_replica.

    Attributes:
        name (str): The name of the zone.

        unit_config_name (str): 
            The name of the unit config used for creating resource pool on the zone.
        unit_num (str): The number of the unit on the zone.
        replica_type (str, optional): The type of the replica, "FULL" or "READONLY".
    """

    def __init__(self, zone_name: str, unit_config_name: str, unit_num: int, replica_type: str = None):
        """Init the ZoneParam with the given parameters.

        Args:
            zone_name (str): The name of the zone.

            unit_config_name (str):
                The name of the unit config used for creating resource pool on the zone.
            unit_num (str): The number of the unit on the zone.
            replica_type (str, optional): The type of the replica, "FULL" or "READONLY".
        """
        self.name = zone_name
        self.unit_config_name = unit_config_name
        self.unit_num = unit_num
        if replica_type is not None:
            self.replica_type = replica_type


class ModifyReplicaParam:
    """The properties of the zone and the replica on the zone.

    Used by modify_tenant_replcia.
    The attributes are the targets you want to modify for
    replica.

    Attributes:
        name (str): The name of the zone.

        unit_config_name (str, optional): 
            The name of the unit config used for creating resource pool on the zone.
        unit_num (str, optional): The number of the unit on the zone.
        replica_type (str, optional): The type of the replica, "FULL" or "READONLY".
    """

    def __init__(self, zone_name: str, unit_config_name: str = None, unit_num: int = None, replica_type: str = None):
        if zone_name is not None:
            self.zone_name = zone_name
        if unit_config_name is not None:
            self.unit_config_name = unit_config_name
        if unit_num is not None:
            self.unit_num = unit_num
        if replica_type is not None:
            self.replica_type = replica_type


class VariableInfo:

    def __init__(self, data: dict):
        self.name = data["name"]
        self.value = data["value"]
        self.info = data["info"]

    @classmethod
    def from_dict(cls, data: dict):
        return VariableInfo(data)

    def __str__(self):
        return model_str(self)


class ParameterInfo:

    def __init__(self, data: dict):
        self.name = data["name"]
        self.value = data["value"]
        self.data_type = data["data_type"]
        self.info = data["info"]
        self.edit_level = data["edit_level"]

    @classmethod
    def from_dict(cls, data: dict):
        return ParameterInfo(data)

    def __str__(self):
        return model_str(self)


class TenantOverView:

    def __init__(self, data: dict):
        self.name = data["tenant_name"]
        self.id = data["tenant_id"]
        self.created_time = data["created_time"]
        self.mode = data["mode"]
        self.status = data["status"]
        self.locked = data["locked"]
        self.primary_zone = data["primary_zone"]
        self.locality = data["locality"]
        self.in_recyclebin = data["in_recyclebin"]

    @classmethod
    def from_dict(cls, data: dict):
        return TenantOverView(data)

    def __str__(self):
        return model_str(self)


class TenantInfo(TenantOverView):

    def __init__(self, data: dict):
        super().__init__(data)
        if "charset" in data:
            self.charset = data["charset"]
        if "collation" in data:
            self.collation = data["collation"]
        self.white_list = data["whitelist"]
        self.pools = [ResourcePoolWithUnit.from_dict(
            pool) for pool in data["pools"]]

    @classmethod
    def from_dict(cls, data: dict):
        return TenantInfo(data)

    def __str__(self):
        return model_str(self)


class DeadLockNode:
    """Represents a node in a deadlock graph."""

    def __init__(self, data: dict):
        self.raw_data = data

    @classmethod
    def from_dict(cls, data: dict):
        return DeadLockNode(data)

    def __str__(self):
        return model_str(self)


class DeadLock:
    """Represents a deadlock event."""

    def __init__(self, data: dict):
        self.event_id = data.get("event_id", "")
        self.report_time = data.get("report_time", "")
        self.size = data.get("size", 0)
        nodes_data = data.get("nodes", [])
        self.nodes = [DeadLockNode.from_dict(node) for node in nodes_data]

    @classmethod
    def from_dict(cls, data: dict):
        return DeadLock(data)

    def __str__(self):
        return model_str(self)


class PaginatedDeadLockResponse:
    """Paginated dead lock response model.

    Attributes:
        contents (list): List of DeadLock objects.
        page (CustomPage): Pagination information.
    """

    def __init__(self, data: dict):
        contents_data = data.get("contents")
        self.contents = [DeadLock.from_dict(content) for content in contents_data] if contents_data else []
        page_data = data.get("page")
        self.page = CustomPage(page_data) if page_data else None

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self):
        return model_str(self)