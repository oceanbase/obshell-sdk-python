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

import sdk.auth.base as base
from model.info import Agentidentity
from utils.info import get_public_key, get_info


class PasswordAuth(base.Auth):
    
    def __init__(self) -> None:
        super().__init__(base.AuthType.PASSWORD, [base.AuthVersion.V1, base.AuthVersion.V2])

    def auth(self, request) -> None:
        if self.method is None:
            if self.version not in _AUTHS:
                raise base.AuthError(f"Unsupported auth version: {self.version}")
            self.method = _AUTHS[self.version]()

        self.method.auth(request)



class PasswordAuthMethod:

    def __init__(self, password: str) -> None:
        self.password = password
        self.pk = None
        self.check_identity = False

    def reset(self) -> None:
        self.pk = None

    def _init_pk(self, server:str):
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

    max_chunk_size = 53

    def auth(self, req: requests.Request) -> None:
        self._check()
        self._init_pk()
        auth_json = json.dumps({'password': self.password, 'ts': int(time.time()) + 5})
        key = RSA.import_key(base64.b64decode(self.pk))
        cipher = PKCS1_cipher.new(key)
        req.headers['X-OCS-Auth'] = base64.b64encode(cipher.encrypt(bytes(auth_json.encode('utf8')))).decode('utf8')


class PasswordAuthMethodV2(PasswordAuthMethod):

    def encrypt_header(self, headers: str) -> str:
        key = RSA.import_key(base64.b64decode(self.pk))
        cipher = PKCS1_cipher.new(key)
        auth_json = json.dumps(headers)
        data_to_encrypt = bytes(auth_json.encode('utf8'))
        chunks = [data_to_encrypt[i:i + self.max_chunk_size] for i in range(0, len(data_to_encrypt), self.max_chunk_size)]
        encrypted_chunks = [cipher.encrypt(chunk) for chunk in chunks]
        encrypted = b''.join(encrypted_chunks)
        return base64.b64encode(encrypted).decode('utf-8')
    
    def auth(self, req: requests.Request) -> None:
        self._check()
        self._init_pk()
        aes_key = get_random_bytes(16)
        aes_iv = get_random_bytes(16)
        headers = {
            'auth': self.password,
            'ts': int(time.time()) + 5,
            'uri': urlparse(req.url).path,
            'keys': base64.b64encode(aes_key+aes_iv).decode('utf-8')
        }
        req.headers['X-OCS-Header'] = self.encrypt_header(headers)

        body = json.dumps(req.data)
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        req.body = base64.b64encode(cipher.encrypt(pad(bytes(body.encode('utf8')), AES.block_size))).decode('utf8')
        req.data = None
        return


_AUTHS = {
    base.AuthVersion.V1: PasswordAuthMethodV1,
    base.AuthVersion.V2: PasswordAuthMethodV2,
}

