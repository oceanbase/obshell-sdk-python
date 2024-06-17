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

from .info import model_str


class UnitConfig:
    def __init__(self, data: dict):
        self.gmt_create = data["gmt_create"]
        self.gmt_modified = data["gmt_modified"]
        self.unit_config_id = data["unit_config_id"]
        self.name = data["name"]
        self.max_cpu = data["max_cpu"]
        self.min_cpu = data["min_cpu"]
        self.memory_size = data["memory_size"]
        self.log_disk_size = data["log_disk_size"]
        self.max_iops = data["max_iops"]
        self.min_iops = data["min_iops"]

    @classmethod
    def from_dict(cls, data: dict):
        return UnitConfig(data)

    def __str__(self):
        return model_str(self)
