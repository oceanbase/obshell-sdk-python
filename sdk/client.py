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

from sdk.request.request import BaseRequest
from sdk.auth.password import PasswordAuth
from sdk.auth.base import AuthType, Auth
from sdk.auth.base import AuthVersion, OBShellVersion
from utils.info import get_info


DECRYPT_ERROR_CODE = 1     # decrypt error
INCOMPATIBLE_ERROR_CODE = 2     # incompatible
UNAUTHORIZED_ERROR_CODE = 10008  # unauthorized


class Client:

    def __init__(self,
                 host: str,
                 port: int = 2886,
                 auth=PasswordAuth(""),
                 timeout=None) -> None:
        """
        Initialize a new Client instance.

        Args:
            host (str): The hostname or IP address of the server to connect to.
            port (int, optional): The port number of the server. Defaults to 2886.
        """
        self.host = host
        self.port = port
        self.task_queue = []
        self.is_syncing = False
        self.auth = auth
        self.timeout = timeout
        self.candidate_auth = None

    @property
    def server(self):
        return f"{self.host}:{self.port}"

    def get_auth(self):
        return self.auth

    def set_candidate_auth(self, auth: Auth):
        if auth.is_auto_select_version() and auth.type == AuthType.PASSWORD:
            if self.auth.is_auto_select_version():
                auth.auto_select_version([self.auth.get_version()])
            else:
                auth.set_version(self.auth.get_version())
        self.candidate_auth = auth

    def try_candidate_auth(self, req):
        if not self.candidate_auth:
            return False
        try:
            agent = get_info(f"{self.host}:{self.port}")
            if (agent.version == OBShellVersion.V422 or
                    agent.version == OBShellVersion.V423):
                self.reset_auth()  # to confirm the pk and auth version is right
                resp = self._real_execute(req)
                if resp.status_code == 200:
                    return resp
            self.adopt_candidate_auth()
            return self._real_execute(req)
        except Exception:
            return False

    def discard_candidate_auth(self):
        self.candidate_auth = None

    def adopt_candidate_auth(self):
        if not self.candidate_auth:
            return
        self.auth = self.candidate_auth
        self.candidate_auth = None

    def _set_auth(self, auth):
        self.auth = auth
        self.candidate_auth = None

    def set_auth(self, auth):
        auth.reset_method()
        self._set_auth(auth)

    def check_specified_auth(self):
        auth = self.auth
        agent = get_info(f"{self.host}:{self.port}")
        if not auth.is_support(auth.get_version()):
            raise Exception(
                f"Auth version {auth.get_version()} is not supported ")
        if len(agent.supported_auth) == 0:
            if not (auth.get_version() == AuthVersion.V1 and
                    agent.version == OBShellVersion.V422 or
                    auth.get_version() == AuthVersion.V2 and
                    agent.version == OBShellVersion.V423):
                raise Exception((f"Auth version {auth.get_version()} "
                                 f"is not supported by agent {agent.version}"))

    def execute(self, req: BaseRequest):
        """Executes a request.

        Args:
            req (BaseRequest): The request to execute.

        Returns:
            BaseReponse: The response to the request.
        """
        if not self.auth.get_version():
            self.confirm_auth_version()
        elif not self.auth.is_auto_select_version():
            self.check_specified_auth()

        resp = self._real_execute(req)
        if resp.status_code != 200:
            err = resp.json().get("error")
            if err is None:  # network error
                raise Exception(
                    f"Request failed with status code {resp.status_code}")
            errcode = err.get("code")
            if errcode == DECRYPT_ERROR_CODE:
                self.auth.reset_method()
            elif err == INCOMPATIBLE_ERROR_CODE:
                return resp
            else:
                if errcode == UNAUTHORIZED_ERROR_CODE:
                    ret = self.try_candidate_auth(req)
                    if ret:
                        return ret
                    if self.auth.get_version() > AuthVersion.V2:
                        return resp
                    self.reset_auth()  # obshell-sdk-go is wrong
            return self._real_execute(req)
        return resp

    def reconfirm_auth_version(self):
        self.auth.reset()
        self.confirm_auth_version()

    def reset_auth(self):
        if not self.auth.is_auto_select_version():
            self.auth.reset_method()
        else:
            self.auth.reset()
            self.confirm_auth_version()

    def confirm_auth_version(self):
        auth = self.auth
        agent = get_info(f"{self.host}:{self.port}")
        supported_auth = []
        if agent.version == OBShellVersion.V422:
            supported_auth.append(AuthVersion.V1)
        elif agent.version == OBShellVersion.V423:
            supported_auth.append(AuthVersion.V2)
        else:
            if len(agent.supported_auth) == 0:
                raise Exception("No supported auth methods")
            supported_auth = agent.supported_auth

        if not auth.auto_select_version(supported_auth):
            raise Exception("No supported auth methods")

    def _real_execute(self, req: BaseRequest):
        if req.need_auth:
            self.auth.auth(req)
        resp = requests.request(req.method, req.url, data=req.data,
                                headers=req.headers, timeout=req.timeout)
        return resp
