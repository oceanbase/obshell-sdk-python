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
from typing import Optional, Tuple, Union

_VALID_PROTOCOLS = ("http", "https")


def _validate_tls_options(verify_cert: Union[bool, str],
                          client_cert: Optional[Union[str, Tuple[str, str]]]) -> None:
    if not isinstance(verify_cert, (bool, str)):
        raise ValueError(
            "verify_cert must be bool or a path to a CA bundle (str), "
            "same as requests' verify argument.")
    if client_cert is None:
        return
    if isinstance(client_cert, str):
        return
    if (isinstance(client_cert, tuple) and len(client_cert) == 2 and
            isinstance(client_cert[0], str) and isinstance(client_cert[1], str)):
        return
    raise ValueError(
        "client_cert must be None, a path to a combined PEM (str), or "
        "(cert_path, key_path), same as requests' cert argument.")


class ProtocolOptions:
    def __init__(self, protocol: str,
                 verify_cert: Union[bool, str] = True,
                 client_cert: Optional[Union[str, Tuple[str, str]]] = None):
        if protocol not in _VALID_PROTOCOLS:
            raise ValueError(
                f"protocol must be one of {_VALID_PROTOCOLS}, got {protocol!r}")
        _validate_tls_options(verify_cert, client_cert)
        self._protocol = protocol
        self._verify_cert = verify_cert
        self._client_cert = client_cert

    @staticmethod
    def http():
        """Build options for plain HTTP (no TLS).
        Use when OBShell is served over ``http://``. No certificate verification
        or client certificate applies.
        Returns:
            ProtocolOptions: ``protocol`` is ``http``, default TLS fields unused.
        """
        return ProtocolOptions(protocol="http")

    @staticmethod
    def https_insecure():
        """Build options for HTTPS without verifying the server certificate.
        Equivalent to ``requests`` with ``verify=False``. Suitable only for
        non-production (e.g. self-signed certs in a lab); do not use on
        untrusted networks.
        Returns:
            ProtocolOptions: ``protocol`` is ``https``, ``verify_cert`` is
            ``False``, no client certificate.
        """
        return ProtocolOptions(protocol="https", verify_cert=False)

    def https(verify_cert: Union[bool, str] = True, client_cert: Optional[Union[str, Tuple[str, str]]] = None):
        """Build options for HTTPS with configurable server trust and optional mTLS.
        Maps to ``requests`` ``verify`` and ``cert`` for outbound calls.
        Args:
            verify_cert: How to verify the server certificate. ``True`` uses the
                default CA bundle; ``False`` disables verification; a ``str`` is a
                path to a CA bundle or certificate chain (PEM).
            client_cert: Client certificate for mutual TLS. ``None`` means no
                client cert. A ``str`` is a path to a PEM containing cert (and
                often key); a ``(cert_path, key_path)`` tuple uses separate files.
        Returns:
            ProtocolOptions: ``protocol`` is ``https`` with the given
            ``verify_cert`` and ``client_cert``.
        """
        return ProtocolOptions(protocol="https", verify_cert=verify_cert, client_cert=client_cert)

    @property
    def protocol(self):
        return self._protocol

    @property
    def verify_cert(self):
        return self._verify_cert

    @property
    def client_cert(self):
        return self._client_cert


class BaseRequest:
    def __init__(self, uri: str,
                 method: str,
                 host: str,
                 port: int = 2886,
                 protocol_options: ProtocolOptions = None,
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
        if protocol_options is None:
            protocol_options = ProtocolOptions.http()
        self.uri = urllib.parse.quote(uri)
        self.method = method
        self.host = host
        self.port = port
        self._protocol_options = protocol_options
        self.need_auth = need_auth
        self.data = data
        self.query_param = query_param
        self.original_data = data
        self.headers = headers
        self.timeout = timeout
        self.task_type = task_type

    @property
    def protocol_options(self) -> ProtocolOptions:
        return self._protocol_options

    @property
    def protocol(self) -> str:
        return self._protocol_options.protocol

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
