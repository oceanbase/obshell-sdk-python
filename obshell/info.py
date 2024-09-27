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


import requests

from obshell.model.info import AgentInfo

DEFAULT_TIMEOUT = 1000


def get_info(server: str) -> AgentInfo:
    url = f"http://{server}/api/v1/info"
    resp = requests.get(url, timeout=DEFAULT_TIMEOUT)
    if resp.status_code != 200:
        raise Exception(f"Failed to get version from {server}, "
                        f"status code: {resp.status_code}")
    data = resp.json().get("data", {})
    if not data:
        raise Exception(f"Failed to get version from {server}, no data")
    identity = data.get("identity")
    version = data.get("version")
    supported_auth = data.get("supportedAuth", [])
    info = AgentInfo(identity, version, supported_auth)
    return info


def get_public_key(server: str) -> str:
    url = f"http://{server}/api/v1/secret"
    resp = requests.get(url, timeout=DEFAULT_TIMEOUT)
    if resp.status_code != 200:
        raise Exception(f"Failed to get public key from {server}, "
                        f"status code: {resp.status_code}")

    data = resp.json().get("data", {})
    if not data:
        raise Exception(f"Failed to get version from {server}, no data")

    return data.get("public_key")
