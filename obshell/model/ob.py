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


class UpgradePkgInfo:

    def __init__(self, data: dict):
        self.pkg_id = data.get("pkg_id")
        self.name = data.get("name")
        self.version = data.get("version")
        self.release_distribution = data.get("release_distribution")
        self.distributioin = data.get("distributioin")
        self.architecture = data.get("architecture")
        self.size = data.get("size")
        self.payload_size = data.get("payload_size")
        self.chunk_count = data.get("chunk_count")
        self.md5 = data.get("md5")
        self.upgrade_dep_yaml = data.get("upgrade_dep_yaml")
        self.gmt_modify = data.get("gmt_modify")

    @classmethod
    def from_dict(cls, data: dict):
        return UpgradePkgInfo(data)

    def __str__(self) -> str:
        return model_str(self)


class CdbObBackupTask:

    def __init__(self, data: dict):
        self.tenant_id = data.get("tenant_id")
        self.task_id = data.get("task_id")
        self.job_id = data.get("job_id")
        self.incarnation = data.get("incarnation")
        self.backup_set_id = data.get("backup_set_id")
        self.start_timestamp = data.get("start_timestamp")
        self.end_timestamp = data.get("end_timestamp")
        self.status = data.get("status")
        self.start_scn = data.get("start_scn")
        self.end_scn = data.get("end_scn")
        self.user_ls_start_scn = data.get("user_ls_start_scn")
        self.encryption_mode = data.get("encryption_mode")
        self.input_bytes = data.get("input_bytes")
        self.output_bytes = data.get("output_bytes")
        self.output_rate_bytes = data.get("output_rate_bytes")
        self.extra_meta_bytes = data.get("extra_meta_bytes")
        self.tablet_count = data.get("tablet_count")
        self.finish_tablet_count = data.get("finish_tablet_count")
        self.macro_block_count = data.get("macro_block_count")
        self.finish_macro_block_count = data.get("finish_macro_block_count")
        self.file_count = data.get("file_count")
        self.meta_turn_id = data.get("meta_turn_id")
        self.data_turn_id = data.get("data_turn_id")
        self.result = data.get("result")
        self.comment = data.get("comment")
        self.path = data.get("path")

    @classmethod
    def from_dict(cls, data: dict):
        return CdbObBackupTask(data)

    def __str__(self) -> str:
        return model_str(self)


class CdbObBackupResponse:

    def __init__(self, data: dict):
        if data.get("statuses"):
            self.statuses = [CdbObBackupTask.from_dict(
                task) for task in data.get('statuses', [])]
        if data.get("status"):
            self.status = data.get("status")

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data)

    def __str__(self) -> str:
        return model_str(self)


class RestoreOverview:

    def __init__(self, data: dict):
        self.tenant_id = data.get("tenant_id")
        self.job_id = data.get("job_id")
        self.restore_tenant_name = data.get("restore_tenant_name")
        self.restore_tenant_id = data.get("restore_tenant_id")
        self.backup_tenant_name = data.get("backup_tenant_name")
        self.backup_tenant_id = data.get("backup_tenant_id")
        self.backup_cluster_name = data.get("backup_cluster_name")
        self.backup_dest = data.get("backup_dest")
        self.restore_option = data.get("restore_option")
        self.restore_scn = data.get("restore_scn")
        self.restore_scn_display = data.get("restore_scn_display")
        self.status = data.get("status")
        self.start_timestamp = data.get("start_timestamp")
        self.backup_set_list = data.get("backup_set_list")
        self.backup_piece_list = data.get("backup_piece_list")
        self.tablet_count = data.get("tablet_count")
        self.total_bytes = data.get("total_bytes")
        self.description = data.get("description")
        self.finish_tablet_count = data.get("finish_tablet_count")
        self.finish_bytes = data.get("finish_bytes")
        self.finish_bytes_display = data.get("finish_bytes_display")
        self.total_bytes_display = data.get("total_bytes_display")
        self.recover_scn = data.get("recover_scn")
        self.recover_scn_display = data.get("recover_scn_display")
        self.recover_progress = data.get("recover_progress")
        self.restore_progress = data.get("restore_progress")
        self.backup_cluster_version = data.get("backup_cluster_version")
        self.ls_count = data.get("ls_count")
        self.finish_ls_count = data.get("finish_ls_count")
        self.comment = data.get("comment")
        self.finish_timestamp = data.get("finish_timestamp")

    @classmethod
    def from_dict(cls, data: dict):
        return RestoreOverview(data)

    def __str__(self) -> str:
        return model_str(self)


class RestoreWindow:

    def __init__(self, data: dict):
        self.start_time = data.get("start_time")
        self.end_time = data.get("end_time")

    @classmethod
    def from_dict(cls, data: dict):
        return RestoreWindow(data)

    def __str__(self) -> str:
        return model_str(self)


class RestoreWindows:

    def __init__(self, data: dict):
        self.restore_windows = [RestoreWindow.from_dict(
            window) for window in data.get("restore_windows", [])]

    def __iter__(self):
        return iter(self.restore_windows)

    def __item__(self, index):
        return self.restore_windows[index]

    @classmethod
    def from_dict(cls, data: dict):
        return RestoreWindows(data)

    def __str__(self) -> str:
        return model_str(self)


class ClusterParameter:

    def __init__(self, data: dict):
        self.name = data.get("name")
        self.scope = data.get("scope")
        self.edit_level = data.get("edit_level")
        self.default_value = data.get("default_value")
        self.section = data.get("section")
        self.data_type = data.get("data_type")
        self.info = data.get("info")
        self.server_value = [ObParameterValue.from_dict(
            item) for item in data.get("ob_parameters", [])]
        self.tenant_value = [TenantParameterValue.from_dict(
            item) for item in data.get("tenant_value", [])]
        self.values = data.get("values", [])
        self.is_single_value = data.get("is_single_value", False)

    @classmethod
    def from_dict(cls, data: dict):
        return ClusterParameter(data)

    def __str__(self) -> str:
        return model_str(self)


class ObParameterValue:

    def __init__(self, data: dict):
        self.svr_ip = data.get("svr_ip")
        self.svr_port = data.get("svr_port")
        self.zone = data.get("zone")
        self.tenant_id = data.get("tenant_id")
        self.tenant_name = data.get("tenant_name")
        self.value = data.get("value")

    @classmethod
    def from_dict(cls, data: dict):
        return ObParameterValue(data)

    def __str__(self) -> str:
        return model_str(self)


class TenantParameterValue:

    def __init__(self, data: dict):
        self.tenant_id = data.get("tenant_id")
        self.tenant_name = data.get("tenant_name")
        self.value = data.get("value")

    @classmethod
    def from_dict(cls, data: dict):
        return TenantParameterValue(data)

    def __str__(self) -> str:
        return model_str(self)


class SetClusterParametersParam:
    """
    A structure used to be the param of set cluster parameters.

    Attr:
        name: The name of the parameter.
        value: The value of the parameter.
        scope: The scope of the parameter. It can only be "TENANT" or "CLUSTER".
        data: 
            A dictionary containing additional data such as servers, tenants, zones, and all_user_tenant.
            - servers: A list of server IPs and ports. such as ["11.11.11.1:2882", "11.11.11.2:2882"]
                Cannot be set together with zones.
            - zones: A list of zone names. such as ["zone1", "zone2"]
                Cannot be set together with servers.
            - tenants: A list of tenant names. such as ["tenant1", "tenant2"]
                Only can be set when scope is "TENANT".
                Cannot be set together with all_user_tenant.
            - all_user_tenant: A boolean value indicating whether to apply the parameter to all user tenants.
                Only can be set when scope is "TENANT".
                Cannot be set together with tenants.
    """

    def __init__(self, name: str, value: str, scope: str, data: dict = {}):
        self.name = name
        self.scope = scope
        self.value = value
        self.servers = data.get("servers", [])
        self.tenants = data.get("tenants", [])
        self.zones = data.get("zones", [])
        self.all_user_tenant = data.get("all_user_tenant", False)
