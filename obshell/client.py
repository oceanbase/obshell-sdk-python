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

from obshell.request import BaseRequest
from obshell.auth.password import PasswordAuth
from obshell.auth.base import AuthType, Auth
from obshell.auth.base import AuthVersion, OBShellVersion
from obshell.info import get_info


DECRYPT_ERROR_CODE = 1     # decrypt error
INCOMPATIBLE_ERROR_CODE = 2     # incompatible
UNAUTHORIZED_ERROR_CODE = 10008  # unauthorized


class Client:

    def __init__(self,
                 host: str,
                 port: int = 2886,
                 auth=None,
                 timeout=None) -> None:
        """
        Initialize a new Client instance.

        Args:
            host (str): The hostname or IP address of the server to connect to.
            port (int, optional): The port number of the server. Defaults to 2886.
        """
        self._host = host
        self._port = port
        if auth is None:
            auth = PasswordAuth()
        self._auth = auth
        self._timeout = timeout
        self.__candidate_auth = None

    @property
    def server(self):
        return f"{self.host}:{self.port}"

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def timeout(self):
        return self._timeout

    def _execute(self, req: BaseRequest):
        """Executes a request.

        Args:
            req (BaseRequest): The request to execute.

        Returns:
            BaseReponse: The response to the request.
        """
        if not self._auth.get_version():
            self.__confirm_auth_version()
        elif not self._auth.is_auto_select_version:
            self.__check_specified_auth()

        resp = self.__real_execute(req)
        if resp.status_code >= 400:
            err = resp.json().get("error")
            if err is None:  # network error
                raise Exception(
                    f"Request failed with status code {resp.status_code}")
            errcode = err.get("code")
            if errcode == DECRYPT_ERROR_CODE:
                self._auth.reset_method()
                self.__real_execute(req)
            elif err == INCOMPATIBLE_ERROR_CODE:
                return resp
            else:
                if errcode == UNAUTHORIZED_ERROR_CODE:
                    ret = self.__try_candidate_auth(req)
                    if ret:
                        return ret
                    if self._auth.get_version() > AuthVersion.V2:
                        return resp
                    self._reset_auth()
            return self.__real_execute(req)
        return resp

    def _get_auth(self):
        return self._auth

    def _set_candidate_auth(self, auth: Auth):
        if auth.is_auto_select_version and auth.type == AuthType.PASSWORD:
            if self._auth.is_auto_select_version:
                auth.auto_select_version([self._auth.get_version()])
            else:
                auth.set_version(self._auth.get_version())
        self.__candidate_auth = auth

    def _set_auth(self, auth):
        auth.reset_method()
        self.__set_auth(auth)

    def __set_auth(self, auth):
        self._auth = auth
        self.__candidate_auth = None

    def __try_candidate_auth(self, req):
        if not self.__candidate_auth:
            return False
        try:
            agent = get_info(f"{self.host}:{self.port}")
            if agent.version <= OBShellVersion.V424:
                self._reset_auth()  # to confirm the pk and auth version is right
                resp = self.__real_execute(req)
                if resp.status_code == 200:
                    return resp
            self.__adopt_candidate_auth()
            return self.__real_execute(req)
        except Exception:
            return False

    def __adopt_candidate_auth(self):
        if not self.__candidate_auth:
            return
        self._auth = self.__candidate_auth
        self.__candidate_auth = None

    def __check_specified_auth(self):
        auth = self._auth
        agent = get_info(f"{self.host}:{self.port}")
        if not auth.is_support(auth.get_version()):
            raise Exception(
                f"Auth version {auth.get_version()} is not supported ")
        if len(agent.supported_auth) == 0:
            if not (auth.get_version() == AuthVersion.V1 and
                    agent.version == OBShellVersion.V422 or
                    auth.get_version() == AuthVersion.V2 and
                    agent.version >= OBShellVersion.V423):
                raise Exception((f"Auth version {auth.get_version()} "
                                 f"is not supported by agent {agent.version}"))
        else:
            if auth.get_version() not in agent.supported_auth:
                raise Exception((f"Auth version {auth.get_version()} "
                                 f"is not supported by agent {agent.version}"))

    def _reset_auth(self):
        if not self._auth.is_auto_select_version:
            self._auth.reset_method()
        else:
            self._auth.reset()
            self.__confirm_auth_version()

    def __confirm_auth_version(self):
        auth = self._auth
        agent = get_info(f"{self.host}:{self.port}")
        supported_auth = []
        if len(agent.supported_auth) != 0:
            supported_auth = agent.supported_auth
        elif agent.version == OBShellVersion.V422:
            supported_auth.append(AuthVersion.V1)
        elif agent.version >= OBShellVersion.V423:
            supported_auth.append(AuthVersion.V2)
        else:
            raise Exception("No supported auth methods")

        if not auth.auto_select_version(supported_auth):
            raise Exception("No supported auth methods")

    def __real_execute(self, req: BaseRequest):
        if req.need_auth:
            self._auth.auth(req)
        resp = requests.request(req.method, req.url, data=req.data,
                                headers=req.headers, timeout=req.timeout)
        return resp
