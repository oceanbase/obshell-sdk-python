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

import time
import base64
import os
import requests

from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.PublicKey import RSA

from utils.info import get_info, get_public_key
from sdk.client import Client
from sdk.auth.base import OBShellVersion, AuthType
from sdk.auth.password import PasswordAuth
from sdk.request.request import BaseRequest
from model.task import DagDetailDTO, Operator, NodeDetailDTO, TaskDetailDTO
from model.ob import UpgradePkgInfo
from model.info import ObInfo, AgentStatusWithOb, AgentStatusWithZone, Agentidentity


class OBShellHandleError(Exception):
    def __init__(self, err: dict) -> None:
        super().__init__()
        self.code = err.get("code", 0)
        self.message = err.get("message", "")

    def __str__(self) -> str:
        return f"Error code: {self.code}, message: {self.message}"

class TaskExecuteFailedError(Exception):
    def __init__(self, message, dag):
        super().__init__()
        self.message = message
        self.dag = dag

    def __str__(self) -> str:
        return f"Task '{self.dag.name}' execution failed: {self.message}"

class UsageError(Exception):
    pass

class ClientV1(Client):

    DEFAULT_REQUEST_TIMEOUT = 600

    def __init__(self, host: str, port: int = 2886, auth=PasswordAuth(""), timeout=DEFAULT_REQUEST_TIMEOUT):
        super().__init__(host, port, auth=auth, timeout=timeout)

    def _set_password_candidate_auth(self, password: str):
        if self.get_auth().type == AuthType.PASSWORD:
            self.set_candidate_auth(PasswordAuth(password))

    def _encrypt_password(self, pwd: str) -> str:
        agent = get_info(self.server)
        if OBShellVersion.V422 in agent.version or OBShellVersion.V423 in agent.version:
            pk = get_public_key(self.server)
            key = RSA.import_key(base64.b64decode(pk))
            cipher = PKCS1_cipher.new(key)
            data_to_encrypt = bytes(pwd.encode('utf8'))
            chunks = [data_to_encrypt[i:i + 53]
                    for i in range(0, len(data_to_encrypt), 53)]
            encrypted_chunks = [cipher.encrypt(chunk) for chunk in chunks]
            encrypted = b''.join(encrypted_chunks)
            return base64.b64encode(encrypted).decode('utf-8')

    def _parse_pkg(self, pkg_path: str):
        file_name = os.path.basename(pkg_path)
        with open(pkg_path, "rb") as f:
            file = {'file': (file_name, f)}
            req = requests.Request('POST', f"http://{self.server}/api/v1/ob/pkg/upload", files=file)
            prepared = req.prepare()
            return prepared.body, prepared.headers

    def _handle_ret_from_content_request(self, req, cls=None):
        resp = self.execute(req)
        if resp.status_code == 200:
            if cls is None:
                return True
            else:
                return [cls.from_dict(data) for data in resp.json().get('data').get('contents', [])]
        else:
            raise OBShellHandleError(resp.json()['error'])

    def _handle_ret_request(self, req, cls=None):
        resp = self.execute(req)
        if resp.status_code == 200:
            if cls is None:
                return True
            else:
                return cls.from_dict(resp.json()['data'])
        else:
            raise OBShellHandleError(resp.json()['error'])

    def _get_failed_dag_last_log(self, dag: DagDetailDTO):
        nodes = dag.nodes
        logs = ""
        for node in nodes:
            if not node.is_failed():
                continue
            if node.operator == Operator.CANCEL_STR.value:
                return f"Task {dag.name} canceled."
            for sub_task in node.sub_tasks:
                if sub_task.is_failed():
                    logs = logs + (f"{sub_task.execute_agent} {sub_task.task_logs[len(sub_task.task_logs) - 1]}\n")
            return logs

    def create_request(self, uri: str, method: str, data=None, need_auth = True):
        return BaseRequest(uri, method, self.host, self.port, data=data, need_auth=need_auth, timeout=self.timeout)

    def handle_task_ret_request(self, req):
        return self._handle_ret_request(req, DagDetailDTO)

    # Function for OpenAPI
    def join(self, ip: str, port: int, zone: str) -> DagDetailDTO:
        c = ClientV1(ip, port)
        c.set_auth(self.get_auth())
        req = c.create_request("/api/v1/agent/join", "POST",
                               data={"agentInfo": {"ip": self.host, "port": self.port},"zoneName": zone})
        return c.handle_task_ret_request(req)

    def join_sync(self, ip: str, port: int, zone: str) -> DagDetailDTO:
        c = ClientV1(ip, port)
        c.set_auth(self.get_auth())
        req = c.create_request("/api/v1/agent/join", "POST",
                               data={"agentInfo": {"ip": self.host, "port": self.port},"zoneName": zone})
        dag = c.handle_task_ret_request(req)
        return self.wait_dag_succeed(dag.generic_id)

    def remove(self, ip: str, port: int) -> DagDetailDTO:
        req = self.create_request("/api/v1/agent/remove", "POST", data={"ip": ip, "port": port})
        return self.handle_task_ret_request(req)

    def remove_sync(self, ip: str, port: int) -> DagDetailDTO:
        dag = self.remove(ip, port)
        return self.wait_dag_succeed(dag.generic_id)

    def config_observer(self, configs: dict, level: str, target: list, restart=True) -> DagDetailDTO:
        req = self.create_request("/api/v1/observer/config", "POST",
                                  data={
                                      "observerConfig": configs,
                                      "scope": {
                                          "type": level,
                                          "target": target
                                        },
                                      "restart": restart
                                    })
        return self.handle_task_ret_request(req)

    def config_observer_sync(self, configs: dict, level: str, target: list, restart=True) -> DagDetailDTO:
        dag = self.config_observer(configs, level, target, restart)
        return self.wait_dag_succeed(dag.generic_id)

    def config_obcluster(self, cluster_name: str, cluster_id: int, root_pwd: str) -> DagDetailDTO:
        req = self.create_request("/api/v1/obcluster/config", "POST",
                                  data={
                                      "clusterName": cluster_name,
                                      "clusterId": cluster_id,
                                      "rootPwd": self._encrypt_password(root_pwd)
                                    })
        dag = self.handle_task_ret_request(req)
        self._set_password_candidate_auth(root_pwd)
        return dag

    def config_obcluster_sync(self, cluster_name: str, cluster_id: int, root_pwd: str) -> DagDetailDTO:
        dag = self.config_obcluster(cluster_name, cluster_id, root_pwd)
        self._set_password_candidate_auth(root_pwd)
        return self.wait_dag_succeed(dag.generic_id)

    def init(self) -> DagDetailDTO:
        req = self.create_request("/api/v1/ob/init", "POST")
        return self.handle_task_ret_request(req)

    def init_sync(self) -> DagDetailDTO:
        dag = self.init()
        return self.wait_dag_succeed(dag.generic_id)

    def start(self, level: str, target: list, force_pass_dag=None) -> DagDetailDTO:
        """ start specified observer
        Args:
            level (str, "GLOBAL", "ZONE" or "SERVER"): The level of the target
            target (list): The targets of the observer to start.
                            when level is "SERVER", target is the list of ip:port
                            when level is "ZONE", target is the list of zone name
                            when level is "GLOBAL", target is []
            force_pass_dag (list, optional): The dags that need to be forced to pass. Defaults to None.
        
        Returns:
            DagDetailDTO: task detail
            
        Raises:
            OBShellHandleError: error message
        """
        if force_pass_dag is None:
            force_pass_dag = []
        req = self.create_request("/api/v1/ob/start", "POST",
                                data={"scope": {"type": level, "target": target}, 
                                      "forcePassDag": {
                                          "id": force_pass_dag
                                      }})
        return self.handle_task_ret_request(req)

    def start_sync(self, level: str, target: list, force_pass_dag=None) -> DagDetailDTO:
        dag = self.start(level, target, force_pass_dag)
        return self.wait_dag_succeed(dag.generic_id)

    def stop(self, level: str, target: list, force=False, terminate=False, force_pass_dag=None) -> DagDetailDTO:
        """ stop specified observer
        Args:
            level (str, "GLOBAL", "ZONE" or "SERVER"): The level of target
            target (list): The targets of the observer to stop.
                            when level is "SERVER", target is the list of ip:port
                            when level is "ZONE", target is the list of zone name
                            when level is "GLOBAL", target is []
            force (bool, optional): Whether to forcely stop. Defaults to False.
            terminate (bool, optional): Whether to execute "MINOR FREEZE" before stop the observer. Defaults to False.
            force_pass_dag (list, optional): The dags that need to be forced to pass. Defaults to None.
        
        Returns:
            DagDetailDTO: task detail
        
        Raises:
            UsageError: force and terminate cannot be set at the same time
            OBShellHandleError: error message
        """
        if force_pass_dag is None:
            force_pass_dag = []
        if force and terminate:
            raise UsageError("force and terminate cannot be set at the same time")
        req = self.create_request("/api/v1/ob/stop", "POST",
                                  data={
                                      "scope": {"type": level, "target": target}, 
                                      "force": force, "terminate": terminate,   
                                      "forcePassDag": {
                                          "id": force_pass_dag
                                      }
                                    })
        return self.handle_task_ret_request(req)

    def stop_sync(self, level: str, target: list, force=False, terminate=False, force_pass_dag=None) -> DagDetailDTO:
        dag = self.stop(level, target, force, terminate, force_pass_dag)
        return self.wait_dag_succeed(dag.generic_id)

    def scale_out(self, ip: str, port: int, zone: str, ob_configs: dict) -> DagDetailDTO:
        req = self.create_request("/api/v1/ob/scale_out", "POST",
                                  data={
                                      "agentInfo": {"ip": ip, "port": port},
                                      "zone": zone,
                                      "obConfigs": ob_configs,
                                    })
        return self.handle_task_ret_request(req)

    def scale_out_sync(self, ip: str, port: str, zone: str, ob_configs: dict) -> DagDetailDTO:
        dag = self.scale_out(ip, port, zone, ob_configs)
        return self.wait_dag_succeed(dag.generic_id)

    def upload_pkg(self, pkg_path: str) -> UpgradePkgInfo:
        req = self.create_request("/api/v1/upgrade/package", "POST")
        data, headers = self._parse_pkg(pkg_path)
        req.data = data
        req.headers = headers
        return self._handle_ret_request(req, UpgradePkgInfo)

    def upgrade_agent_check(self, version: str, release: str, upgrade_dir=None):
        req = self.create_request("/api/v1/agent/upgrade/check", "POST",
                                  data={"version": version, "release": release, "upgradeDir": upgrade_dir})
        return self.handle_task_ret_request(req)

    def upgrade_agent_check_sync(self, version: str, release: str, upgrade_dir=None):
        dag = self.upgrade_agent_check(version, release, upgrade_dir)
        return self.wait_dag_succeed(dag.generic_id)

    def upgrade_agent(self, version: str, release: str, upgrade_dir=None) -> DagDetailDTO:
        req = self.create_request("/api/v1/agent/upgrade", "POST",
                                  data={"version": version, "release": release, "upgradeDir": upgrade_dir})
        return self.handle_task_ret_request(req)

    def upgrade_agent_sync(self, version: str, release: str, upgrade_dir=None):
        dag = self.upgrade_agent(version, release, upgrade_dir)
        return self.wait_dag_succeed(dag.generic_id)

    def upgrade_ob_check(self, version: str, release: str, upgrade_dir=None):
        """ check before upgrading ob
        Args:
            version (str): The version of the observer to be upgraded to
            release (str): The release of the observer to be upgraded to
            upgrade_dir (str, optional): the temp dir to store the upgrade package
        
        Returns:
            DagDetailDTO: task detail
        
        Raises:
            OBShellHandleError: error message
        """
        req = self.create_request("/api/v1/ob/upgrade/check", "POST",
                                  data={"version": version, "release": release, "upgradeDir": upgrade_dir})
        return self.handle_task_ret_request(req)

    def upgrade_ob_check_sync(self, version: str, release: str, upgrade_dir=None):
        dag = self.upgrade_ob_check(version, release, upgrade_dir)
        return self.wait_dag_succeed(dag.generic_id)

    def upgrade_ob(self, version: str, release: str, mode: str, upgrade_dir=None) -> DagDetailDTO:
        """ upgrade ob
        Args:
            version (str): The version of the observer to be upgraded to
            release (str): The release of the observer to be upgraded to
            mode (str): uUpgrade mode("ROLLING" or "STOPSERVICE")
            upgrade_dir (str, optional): the temp dir to store the upgrade package
        
        Returns:
            DagDetailDTO: task detail
        
        Raises:
            OBShellHandleError: error message
        """
        req = self.create_request("/api/v1/ob/upgrade", "POST",
                                data={"version": version, "release": release, "mode": mode, "upgradeDir": upgrade_dir})
        return self.handle_task_ret_request(req)

    def upgrade_ob_sync(self, version: str, release: str, mode: str, upgrade_dir=None) -> DagDetailDTO:
        """ upgrade ob and wait for the task to succeed
        Args:
            version (str): The version of the observer to be upgraded to
            release (str): The release of the observer to be upgraded to
            mode (str): uUpgrade mode("ROLLING" or "STOPSERVICE")
            upgrade_dir (str, optional): the temp dir to store the upgrade package
        
        Returns:
            DagDetailDTO: task detail
        
        Raises:
            OBShellHandleError: error message
            TaskExecuteFailedError: task failed, with the failed task detail and logs
        """
        dag = self.upgrade_ob(version, release, mode, upgrade_dir)
        return self.wait_dag_succeed(dag.generic_id)

    def get_dag(self, generic_id: str, show_detail=True) -> DagDetailDTO:
        req = self.create_request(f"/api/v1/task/dag/{generic_id}", "GET", data={"showDetail": show_detail})
        return self._handle_ret_request(req, DagDetailDTO)

    def operate_dag(self, generic_id: str, operator: str) -> DagDetailDTO:
        req = self.create_request(f"/api/v1/task/dag/{generic_id}", "POST", data={"operator": operator})
        return self._handle_ret_request(req)

    def operate_dag_sync(self, generic_id: str, operator: str):
        self.operate_dag(generic_id, operator)
        dag = None
        try:
            dag = self.wait_dag_succeed(generic_id)
        except TaskExecuteFailedError as e:
            dag = e.dag
        if operator == Operator.ROLLBACK_STR.value:
            if dag.is_succeed() and dag.is_rollback():
                return True
        elif operator == Operator.CANCEL_STR.value:
            if dag.is_failed() and dag.is_cancel():
                return True
        elif operator == Operator.RETRY_STR.value:
            if dag.is_succeed() and dag.is_run():
                return True
        raise TaskExecuteFailedError(f"Failed to {operator} task {generic_id}", dag)

    def get_node(self, generic_id: str, show_detail=True) -> NodeDetailDTO:
        req = self.create_request(f"/api/v1/task/node/{generic_id}", "GET", data={"showDetail": show_detail})
        return self._handle_ret_request(req, NodeDetailDTO)

    def get_sub_task(self, generic_id: str, show_detail=True) -> TaskDetailDTO:
        req = self.create_request(f"/api/v1/task/subtask/{generic_id}", "GET", data={"showDetail": show_detail})
        return self._handle_ret_request(req, TaskDetailDTO)

    def get_agent_last_maintenance_dag(self, show_detail=True) -> DagDetailDTO:
        req = self.create_request("/api/v1/task/dag/maintain/agent", "GET", data={"showDetail": show_detail})
        return self._handle_ret_request(req, DagDetailDTO)

    def get_agent_unfinished_dag(self, show_detail=True):
        req = self.create_request("/api/v1/task/dag/agent/unfinish", "GET", data={"showDetail": show_detail})
        return self._handle_ret_from_content_request(req, DagDetailDTO)

    def get_all_agent_last_maintenance_dag(self, show_detail=True):
        req = self.create_request("/api/v1/task/dag/maintain/agents", "GET", data={"showDetail": show_detail})
        return self._handle_ret_from_content_request(req, DagDetailDTO)

    def get_cluster_unfinished_dag(self, show_detail=True):
        req = self.create_request("/api/v1/task/dag/ob/unfinish", "GET", data={"showDetail": show_detail})
        return self._handle_ret_from_content_request(req, DagDetailDTO)

    def get_ob_last_maintenance_dag(self, show_detail=True):
        req = self.create_request("/api/v1/task/dag/maintain/ob", "GET", data={"showDetail": show_detail})
        return self._handle_ret_from_content_request(req, DagDetailDTO)

    def get_unfinished_dags(self, show_detail=True):
        req = self.create_request("/api/v1/task/dag/unfinish", "GET", data={"showDetail": show_detail})
        return self._handle_ret_from_content_request(req, DagDetailDTO)

    def get_ob_info(self):
        req = self.create_request("/api/v1/ob/info", "GET")
        return self._handle_ret_request(req, ObInfo)

    def get_status(self):
        req = self.create_request("/api/v1/status", "GET", need_auth=False)
        return self._handle_ret_request(req, AgentStatusWithOb)

    def get_info(self):
        req = self.create_request("/api/v1/info", "GET", need_auth=False)
        return self._handle_ret_request(req, AgentStatusWithZone)

    def wait_dag_succeed(self, generic_id: str, retry_time=60) -> DagDetailDTO:
        while True:
            try:
                dag = self.get_dag(generic_id)
                if dag.is_succeed():
                    return dag
                if dag.is_failed():
                    logs = self._get_failed_dag_last_log(dag)
                    raise TaskExecuteFailedError(f"{logs}", dag)
                time.sleep(3)
            except requests.exceptions.ConnectionError as e:
                if retry_time == 0:
                    raise e
                else:
                    time.sleep(3)
                    retry_time -= 1
            except OBShellHandleError as e:
                if e.code == 2300 and retry_time != 0:
                    time.sleep(3)
                    retry_time -= 1
                else:
                    raise e

    # Aggregation function
    def aggregate_upgrade_agent(self, pkg: str, version: str, release: str, upgrade_dir=None) -> DagDetailDTO:
        """ aggregate upgrade agent
        Args:
            pkg (str): The path of the upgrade package
            version (str): The version of the agent to be upgraded to
            release (str): The release of the agent to be upgraded to
            upgrade_dir (str, optional): the temp dir to store the upgrade package
        
        Returns:
            DagDetailDTO: task detail
        
        Raises:
            OBShellHandleError: error message
            TaskExecuteFailedError: task failed, with the failed task detail and logs
        """
        self.upload_pkg(pkg)
        self.upgrade_agent_check(version, release, upgrade_dir)
        return self.upgrade_agent(version, release, upgrade_dir)

    def clear_uninitialized_agent(self):
        agent = get_info(self.server)
        dag = self.get_agent_last_maintenance_dag()
        need_remove = False
        if agent.identity == Agentidentity.FOLLOWER  or agent.identity == Agentidentity.MASTER:
            need_remove = True
        if dag.name == "Initialize cluster":
            if not dag.is_finished():
                raise UsageError("Cluster initialization is not finished.")
            if dag.is_succeed() and dag.is_run():
                raise UsageError("The 'Initialize Cluster' task is already succeeded")
            if dag.is_failed():
                self.operate_dag_sync(dag.generic_id, Operator.ROLLBACK_STR.value)
            need_remove = True
        if need_remove:
            self.remove_sync(self.host, self.port)
        return True
        