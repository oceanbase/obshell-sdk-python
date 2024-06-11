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


class UpgradePkgInfo:

    def __init__(self, data: dict):
        self.pkg_id = data.get("pkg_id")
        self.name = data.get("name")
        self.version = data.get("version")
        self.release_distribution = data.get("release_distribution")
        self.distributioin = data.get("distributioin")
        self.architecture = data.get("architecture")
        self.size = data.get("size")
        self.payload_size = data.get("payload_size")
        self.chunk_count = data.get("chunk_count")
        self.md5 = data.get("md5")
        self.upgrade_dep_yaml = data.get("upgrade_dep_yaml")
        self.gmt_modify = data.get("gmt_modify")

    @classmethod
    def from_dict(cls, data: dict):
        return UpgradePkgInfo(data)

    def __str__(self) -> str:
        return model_str(self)
