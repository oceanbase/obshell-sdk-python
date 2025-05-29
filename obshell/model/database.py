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

class ObproxyAndConnectionString:
    def __init__(self, data: dict):
        self.type = data["type"]
        self.obproxy_address = data["obproxy_address"]
        self.obproxy_port = data["obproxy_port"]
        self.connection_string = data["connection_string"]

    @classmethod
    def from_dict(cls, data: dict):
        return ObproxyAndConnectionString(data)

    def __str__(self):
        return model_str(self)


class Database:
    def __init__(self, data: dict):
        self.db_name = data["db_name"]
        self.charset = data["charset"]
        self.collation = data["collation"]
        self.read_only = data["read_only"]
        self.create_time = data["create_time"]
        self.connection_urls = [
            ObproxyAndConnectionString.from_dict(item) for item in data["connection_urls"]]

    @classmethod
    def from_dict(cls, data: dict):
        return Database(data)

    def __str__(self):
        return model_str(self)
