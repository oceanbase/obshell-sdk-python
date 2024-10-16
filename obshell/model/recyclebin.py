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


class RecyclebinTenantInfo:

    def __init__(self, data: dict):
        self.object_name = data["object_name"]
        self.original_tenant_name = data["original_tenant_name"]
        self.can_undrop = data["can_undrop"]
        self.can_purge = data["can_purge"]

    @classmethod
    def from_dict(cls, data: dict):
        return RecyclebinTenantInfo(data)

    def __str__(self):
        return model_str(self)
