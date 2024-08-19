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
        for key in ["create_time", "modify_time", "unit_config_id", "name", "max_cpu",
                    "min_cpu", "memory_size", "log_disk_size", "max_iops", "min_iops"]:
            if key in data:
                setattr(self, key, data[key])

    @classmethod
    def from_dict(cls, data: dict):
        return UnitConfig(data)

    def __str__(self):
        return model_str(self)
