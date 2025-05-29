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


class DbPrivilege:
    def __init__(self, data: dict):
        self.db_name = data["db_name"]
        self.privileges = data["privileges"]

    @classmethod
    def from_dict(cls, data: dict):
        return DbPrivilege(data)

    def __str__(self):
        return model_str(self)


class ObUserSessionStats:
    def __init__(self, data: dict):
        self.total = data["total"]
        self.active = data["active"]

    @classmethod
    def from_dict(cls, data: dict):
        return ObUserSessionStats(data)

    def __str__(self):
        return model_str(self)


class ObUserStats:
    def __init__(self, data: dict):
        self.session = ObUserSessionStats.from_dict(
            data["session"]) if data.get("session") else None

    @classmethod
    def from_dict(cls, data: dict):
        return ObUserStats(data)

    def __str__(self):
        return model_str(self)


class ObUser:
    def __init__(self, data: dict):
        self.user_name = data["user_name"]
        self.is_locked = data["is_locked"]
        self.connection_strings = data["connection_strings"]
        self.accessible_databases = data["accessible_databases"]
        self.granted_roles = data["granted_roles"]
        self.global_privileges = data["global_privileges"]
        self.db_privileges = [DbPrivilege.from_dict(
            db_privilege) for db_privilege in data.get("db_privileges", [])]

    @classmethod
    def from_dict(cls, data: dict):
        return ObUser(data)

    def __str__(self):
        return model_str(self)
