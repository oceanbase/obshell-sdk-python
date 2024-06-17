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

from obshell.auth.password import PasswordAuth
from obshell.service.client_v1 import ClientV1


class ClientSet:

    DEFAULT_REQUEST_TIMEOUT = 600

    def __init__(self, host: str,
                 port: int = 2886,
                 auth=PasswordAuth(""),
                 timeout=DEFAULT_REQUEST_TIMEOUT):
        self._v1 = ClientV1(host, port, auth, timeout)

    @property
    def v1(self) -> ClientV1:
        return self._v1

    @property
    def v2(self):
        raise NotImplementedError
