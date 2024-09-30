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

from enum import Enum
from typing import List

from obshell.model.version import Version


class AuthError(Exception):

    pass


class AuthVersion(Enum):

    V1 = "v1"
    V2 = "v2"

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented


class AuthType(Enum):

    PASSWORD = 1


class OBShellVersion:

    V422 = Version("4.2.2.0")
    V423 = Version("4.2.3.0")
    V424 = Version("4.2.4.0")

    def __contains__(self, item) -> bool:
        return item in self.__dict__


class Auth:

    def __init__(self, auth_type: AuthType, support_vers: List[AuthVersion]) -> None:
        if auth_type not in AuthType:
            raise ValueError("Invalid auth type")
        self._select_version = None
        self._auto_select_version = True
        self._auth_type = auth_type
        self._support_vers = support_vers
        self._method = None

    @property
    def type(self):
        return self._auth_type

    @property
    def is_auto_select_version(self) -> bool:
        return self._auto_select_version

    def auth(self, request):
        raise NotImplementedError

    def is_support(self, version: AuthVersion) -> bool:
        if not isinstance(version, AuthVersion):
            version = AuthVersion(version)
        return version in self._support_vers

    def set_version(self, version: AuthVersion):
        version = AuthVersion(version)
        if not self.is_support(version):
            raise ValueError("Version not supported")
        self._select_version = version
        self._auto_select_version = False

    def get_version(self):
        return self._select_version

    def auto_select_version(self, vers: List[AuthVersion] = None) -> bool:
        if not vers:
            vers = []
        for ver in vers:
            ver = AuthVersion(ver)
            if self.is_support(ver):
                self._select_version = ver
                self._auto_select_version = True
                return True
        return False

    def reset(self):
        self._method = None

    def reset_method(self):
        if self._method:
            self._method.reset()
