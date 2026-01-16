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


class Credential:
    """Credential model for storing SSH credential information.

    Attributes:
        credential_id (int): Unique identifier for the credential.
        name (str): Name of the credential.
        description (str): Description of the credential.
        target_type (str): Target type, e.g., "HOST".
        ssh_secret (SshSecret): SSH secret information.
        create_time (str): Creation time of the credential.
        update_time (str): Last update time of the credential.
    """

    def __init__(self, data: dict):
        self.credential_id = data.get("credential_id")
        self.name = data.get("name")
        self.description = data.get("description")
        self.target_type = data.get("target_type")
        ssh_secret_data = data.get("ssh_secret")
        self.ssh_secret = SshSecret(ssh_secret_data) if ssh_secret_data else None
        self.create_time = data.get("create_time")
        self.update_time = data.get("update_time")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class SshSecret:
    """SSH secret model for storing SSH authentication information.

    Attributes:
        type (str): Authentication type, currently only supports "PASSWORD".
        username (str): Username for SSH connection.
        targets (list): List of Target objects containing host information.
    """

    def __init__(self, data: dict):
        self.type = data.get("type")
        self.username = data.get("username")
        targets_data = data.get("targets")
        self.targets = [SshTarget(t) for t in targets_data] if targets_data else []

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class SshTarget:
    """SshTarget model for storing host information.

    Attributes:
        ip (str): IP address of the target host.
        port (int): Port number for SSH connection.
    """

    def __init__(self, data: dict):
        self.ip = data.get("ip")
        self.port = data.get("port")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port
        }

    def __str__(self) -> str:
        return model_str(self)


class ValidationResult:
    """Validation result model for credential validation.

    Attributes:
        credential_id (int): Credential ID, indicates which credential's validation result.
        target_type (str): Target type, e.g., "HOST", "OB".
        succeeded_count (int): Number of successfully validated targets for this credential.
        failed_count (int): Number of failed validated targets for this credential.
        details (list): List of ValidationDetail objects containing validation details.
    """

    def __init__(self, data: dict):
        self.credential_id = data.get("credential_id")
        self.target_type = data.get("target_type")
        self.succeeded_count = data.get("succeeded_count")
        self.failed_count = data.get("failed_count")
        details_data = data.get("details")
        self.details = [ValidationDetail(d) for d in details_data] if details_data else []

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class ValidationDetail:
    """Validation detail model for storing per-target validation result.

    Attributes:
        target (SshTarget): SshTarget information, contains ip and port.
        connection_result (str): Connection result, e.g., SUCCESS, CONNECT_FAILED.
        message (str): Error message (empty string when validation succeeds).
    """

    def __init__(self, data: dict):
        target_data = data.get("target")
        self.target = SshTarget(target_data) if target_data else None
        self.connection_result = data.get("connection_result")
        self.message = data.get("message")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class PaginatedCredentialResponse:
    """Paginated credential response model.

    Attributes:
        contents (list): List of Credential objects.
        page (CustomPage): Pagination information.
    """

    def __init__(self, data: dict):
        contents_data = data.get("contents")
        self.contents = [Credential(c) for c in contents_data] if contents_data else []
        page_data = data.get("page")
        self.page = CustomPage(page_data) if page_data else None

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class CustomPage:
    """Custom page model for pagination.

    Attributes:
        number (int): Current page number.
        size (int): Page size.
        total_pages (int): Total number of pages.
        total_elements (int): Total number of elements.
    """

    def __init__(self, data: dict):
        self.number = data.get("number")
        self.size = data.get("size")
        self.total_pages = data.get("total_pages")
        self.total_elements = data.get("total_elements")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class SshCredentialProperty:
    """SSH credential property model for storing SSH authentication details.

    Attributes:
        type (str): Authentication type, currently only supports "PASSWORD".
        username (str): Username for SSH connection.
        passphrase (str): Password for SSH connection (plain text, will be encrypted before storage).
        targets (list): List of Target objects containing host information.
    """

    def __init__(self, type: str, username: str, targets: list, passphrase: str = None):
        self.type = type
        self.username = username
        self.passphrase = passphrase
        self.targets = targets

    def to_dict(self) -> dict:
        def convert_target(t):
            if isinstance(t, SshTarget):
                return t.to_dict()
            elif hasattr(t, 'to_dict'):
                return t.to_dict()
            return t
        
        data = {
            "type": self.type,
            "username": self.username,
            "targets": [convert_target(t) for t in self.targets]
        }
        if self.passphrase is not None:
            data["passphrase"] = self.passphrase
        return data
