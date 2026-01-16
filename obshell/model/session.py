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


class TenantSession:
    """Tenant session model for storing database session information.

    Attributes:
        id (int): Session ID.
        tenant (str): Tenant name.
        user (str): Database user.
        host (str): Client host.
        db (str): Database name.
        svr_ip (str): Server IP.
        svr_port (int): Server port.
        proxy_ip (str): Proxy IP (parsed from host when ProxySessId is not null).
        proxy_sess_id (int): Proxy session ID.
        sql_port (int): SQL port.
        state (str): Session state.
        action (str): Current action.
        command (str): Current command.
        time (float): Time in seconds.
        memory_usage (int): Memory usage.
        total_cpu_time (int): Total CPU time.
        level (int): Session level.
        sql_id (str): SQL ID.
        info (str): Session info.
        client_info (str): Client info.
        module (str): Session module.
        record_policy (str): Record policy.
        sample_percentage (int): Sample percentage.
    """

    def __init__(self, data: dict):
        self.id = data.get("id")
        self.tenant = data.get("tenant")
        self.user = data.get("user")
        self.host = data.get("host")
        self.db = data.get("db")
        self.svr_ip = data.get("svr_ip")
        self.svr_port = data.get("svr_port")
        self.proxy_ip = data.get("proxy_ip")
        self.proxy_sess_id = data.get("proxy_sess_id")
        self.sql_port = data.get("sql_port")
        self.state = data.get("state")
        self.action = data.get("action")
        self.command = data.get("command")
        self.time = data.get("time")
        self.memory_usage = data.get("memory_usage")
        self.total_cpu_time = data.get("total_cpu_time")
        self.level = data.get("level")
        self.sql_id = data.get("sql_id")
        self.info = data.get("info")
        self.client_info = data.get("client_info")
        self.module = data.get("module")
        self.record_policy = data.get("record_policy")
        self.sample_percentage = data.get("sample_percentage")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class TenantSessionStats:
    """Tenant session statistics model.

    Attributes:
        total_count (int): Total number of sessions.
        active_count (int): Number of active sessions.
        max_active_time (float): Maximum active time.
        user_stats (list): List of TenantSessionUserStats objects.
        db_stats (list): List of TenantSessionDbStats objects.
        client_stats (list): List of TenantSessionClientStats objects.
    """

    def __init__(self, data: dict):
        self.total_count = data.get("total_count")
        self.active_count = data.get("active_count")
        self.max_active_time = data.get("max_active_time")
        user_stats_data = data.get("user_stats")
        self.user_stats = [TenantSessionUserStats(s) for s in user_stats_data] if user_stats_data else []
        db_stats_data = data.get("db_stats")
        self.db_stats = [TenantSessionDbStats(s) for s in db_stats_data] if db_stats_data else []
        client_stats_data = data.get("client_stats")
        self.client_stats = [TenantSessionClientStats(s) for s in client_stats_data] if client_stats_data else []

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class TenantSessionUserStats:
    """Tenant session user statistics model.

    Attributes:
        user_name (str): Username.
        total_count (int): Total number of sessions for this user.
        active_count (int): Number of active sessions for this user.
    """

    def __init__(self, data: dict):
        self.user_name = data.get("user_name")
        self.total_count = data.get("total_count")
        self.active_count = data.get("active_count")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class TenantSessionDbStats:
    """Tenant session database statistics model.

    Attributes:
        db_name (str): Database name.
        total_count (int): Total number of sessions for this database.
        active_count (int): Number of active sessions for this database.
    """

    def __init__(self, data: dict):
        self.db_name = data.get("db_name")
        self.total_count = data.get("total_count")
        self.active_count = data.get("active_count")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class TenantSessionClientStats:
    """Tenant session client statistics model.

    Attributes:
        client_ip (str): Client IP address.
        total_count (int): Total number of sessions from this client.
        active_count (int): Number of active sessions from this client.
    """

    def __init__(self, data: dict):
        self.client_ip = data.get("client_ip")
        self.total_count = data.get("total_count")
        self.active_count = data.get("active_count")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class PaginatedTenantSessions:
    """Paginated tenant sessions response model.

    Attributes:
        contents (list): List of TenantSession objects.
        page (CustomPage): Pagination information.
    """

    def __init__(self, data: dict):
        contents_data = data.get("contents")
        self.contents = [TenantSession(c) for c in contents_data] if contents_data else []
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
