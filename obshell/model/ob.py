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
