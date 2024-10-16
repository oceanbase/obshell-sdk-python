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

import json
import time
import base64
from urllib.parse import urlparse
import requests

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher


from obshell.auth import base
from obshell.model.info import Agentidentity
from obshell.info import get_public_key, get_info


class PasswordAuth(base.Auth):
    """Password-based authentication method."""

    def __init__(self, password: str = "", version=None) -> None:
        """Initialize a new PasswordAuth instance.

        Args:
            password (str, optional):
                The password to use for authentication, should be the same as
                the password of root@sys of obcluster.
                When the identity is SINGLE, the password is unuse.
                Defaults to "".
            version (AuthVersion, optional): The version of the authentication method to use.
                If not provided, the version will be determined by the version of the OBShell.
                Defaults to None.

                - "v1": supported by OBShell version 4.2.2.0.
                - "v2": supported by OBShell version 4.2.3.0 or later.
        """
        super().__init__(base.AuthType.PASSWORD,
                         [base.AuthVersion.V1, base.AuthVersion.V2])
        self.password = password
        if version is not None:
            if version not in _AUTHS_VERSION:
                raise ValueError("Version not supported")
            super().set_version(_AUTHS_VERSION[version])

    def auth(self, request) -> None:
        if self._method is None:
            version = self.get_version()
            if version not in _AUTHS:
                raise base.AuthError(f"Unsupported auth version: {version}")
            self._method = _AUTHS[version](self.password)
        self._method.auth(request)


class PasswordAuthMethod:

    def __init__(self, password: str) -> None:
        self.password = password
        self.pk = None
        self.check_identity = False

    def reset(self) -> None:
        self.pk = None
        self.check_identity = False

    def _init_pk(self, server: str):
        if self.pk is None:
            self.pk = get_public_key(server)

    def _check(self, server: str):
        if not self.check_identity:
            info = get_info(server)
            if info.identity == Agentidentity.SINGLE:
                self.password = ""
            self.check_identity = True

    def auth(self, req) -> None:
        raise NotImplementedError


class PasswordAuthMethodV1(PasswordAuthMethod):

    def auth(self, req: requests.Request) -> None:
        self._check(req.server)
        self._init_pk(req.server)
        auth_json = json.dumps(
            {'password': self.password, 'ts': int(time.time()) + 5})
        key = RSA.import_key(base64.b64decode(self.pk))
        cipher = PKCS1_cipher.new(key)
        req.headers['X-OCS-Auth'] = base64.b64encode(
            cipher.encrypt(bytes(auth_json.encode('utf8')))
        ).decode('utf8')
        if not req.original_data:
            req.original_data = req.data
        if req.original_data:
            if isinstance(req.original_data, dict):
                req.data = json.dumps(req.original_data)
            elif isinstance(req.original_data, str):
                req.data = req.original_data


class PasswordAuthMethodV2(PasswordAuthMethod):

    max_chunk_size = 53

    def encrypt_header(self, headers: str) -> str:
        key = RSA.import_key(base64.b64decode(self.pk))
        cipher = PKCS1_cipher.new(key)
        auth_json = json.dumps(headers)
        data_to_encrypt = bytes(auth_json.encode('utf8'))
        chunks = [data_to_encrypt[i:i + self.max_chunk_size]
                  for i in range(0, len(data_to_encrypt), self.max_chunk_size)]
        encrypted_chunks = [cipher.encrypt(chunk) for chunk in chunks]
        encrypted = b''.join(encrypted_chunks)
        return base64.b64encode(encrypted).decode('utf-8')

    def auth(self, req: requests.Request) -> None:
        self._check(req.server)
        self._init_pk(req.server)
        aes_key = get_random_bytes(16)
        aes_iv = get_random_bytes(16)
        uri = urlparse(req.url).path if not urlparse(
            req.url).query else urlparse(req.url).path + "?" + urlparse(req.url).query
        headers = {
            'auth': self.password,
            'ts': str(int(time.time()) + 5),
            'uri': uri,
            'keys': base64.b64encode(aes_key+aes_iv).decode('utf-8')
        }
        req.headers['X-OCS-Header'] = self.encrypt_header(headers)

        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        if not req.original_data:
            req.original_data = req.data

        if req.original_data:
            body = None
            if isinstance(req.original_data, dict):
                body = json.dumps(req.original_data).encode('utf8')
            elif isinstance(req.original_data, str):
                body = req.original_data.encode('utf8')
            elif isinstance(req.original_data, bytes):
                body = req.original_data
            else:
                raise Exception(
                    f"Unsupported data type: {type(req.original_data)}")
            req.data = base64.b64encode(
                cipher.encrypt(pad(bytes(body), AES.block_size))
            ).decode('utf8')
        return


_AUTHS = {
    base.AuthVersion.V1: PasswordAuthMethodV1,
    base.AuthVersion.V2: PasswordAuthMethodV2,
}

_AUTHS_VERSION = {
    "v1": base.AuthVersion.V1,
    "v2": base.AuthVersion.V2,
}
