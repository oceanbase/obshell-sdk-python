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
import urllib


class BaseRequest:
    def __init__(self, uri: str,
                 method: str,
                 host: str,
                 port: int = 2886,
                 protocol: str = "http",
                 need_auth: bool = False,
                 data: dict = None,
                 query_param: dict = None,
                 headers: dict = None,
                 task_type: str = "ob",
                 timeout: int = 100000):
        if data is None:
            data = {}
        if headers is None:
            headers = {}
        if query_param is None:
            query_param = {}
        self.uri = urllib.parse.quote(uri)
        self.method = method
        self.host = host
        self.port = port
        self.protocol = protocol
        self.need_auth = need_auth
        self.data = data
        self.query_param = query_param
        self.original_data = data
        self.headers = headers
        self.timeout = timeout
        self.task_type = task_type

    @property
    def url(self):
        if len(self.query_param) == 0:
            return f"{self.protocol}://{self.server}{self.uri}"
        return f"{self.protocol}://{self.server}{self.uri}?{urllib.parse.urlencode(self.query_param)}"

    @property
    def is_ipv6(self):
        return ":" in self.host

    @property
    def server(self):
        if self.is_ipv6:
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"
