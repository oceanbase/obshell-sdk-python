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

from .format import model_str
from .unit import UnitConfig


class ResourcePoolWithUnit:

    def __init__(self, data: dict):
        self.name = data["pool_name"]
        self.id = data["pool_id"]
        self.zone_list = data["zone_list"]
        self.unit_num = data["unit_num"]
        self.unit = UnitConfig.from_dict(data["unit_config"])

    @classmethod
    def from_dict(cls, data: dict):
        return ResourcePoolWithUnit(data)

    def __str__(self):
        return model_str(self)


class ResourcePoolInfo:

    def __init__(self, data: dict):
        self.name = data["name"]
        self.id = data["id"]
        self.zone_list = data["zone_list"]
        self.unit_num = data["unit_num"]
        self.unit_config_id = data["unit_config_id"]
        self.tenant_id = data["tenant_id"]

    @classmethod
    def from_dict(cls, data: dict):
        return ResourcePoolInfo(data)

    def __str__(self):
        return model_str(self)
