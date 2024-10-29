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
import copy
from typing import List

from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.PublicKey import RSA

from obshell.info import get_info, get_public_key
from obshell.client import Client
from obshell.auth.base import OBShellVersion, AuthType
from obshell.auth.password import PasswordAuth
from obshell.model import ob
from obshell.request import BaseRequest
from obshell.model.ob import UpgradePkgInfo
import obshell.model.task as task
import obshell.model.info as info
import obshell.model.unit as unit
import obshell.model.tenant as tenant
import obshell.model.resource_pool as pool
import obshell.model.recyclebin as recyclebin


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


class IllegalOperatorError(Exception):
    pass


class ClientV1(Client):
    """Client V1 for OBShell.

    The ClientV1 class provides a set of methods to interact with OBShell server:
        - Methods for OpenAPI:
            Some of OpenAPI provided by OBShell will create a task.
            For these APIs, ClientV1 provides tow method for each API:
                - One method will return as soon as the request is successfully
                  and the task is created. such as join.
                  For these methods, you can use wait_dag_succeed to wait for
                  the task to succeed.
                - The other method will wait for the task to succeed. such as join_sync.
        - Aggregation methods:
            Methods that aggregate multiple requests to achieve a specific goal.
            such as agg_clear_uninitialized_agent.
        - Other methods:
            such as wait_dag_succeed.
    """
    DEFAULT_REQUEST_TIMEOUT = 600

    def __init__(self, host: str,
                 port: int = 2886,
                 auth=None,
                 timeout=DEFAULT_REQUEST_TIMEOUT):
        """Initialize a new ClientV1 instance.

        Args:
            host (str): The hostname or IP address of the server to connect to.
            port (int, optional): The port number of the server. Defaults to 2886.
            auth (Auth, optional): The authentication method. Defaults to PasswordAuth("").
            timeout (int, optional): The timeout of the request. Defaults to 600.
        """
        if auth is None:
            auth = PasswordAuth()
        super().__init__(host, port, auth=auth, timeout=timeout)

    def _set_password_candidate_auth(self, password: str):
        if self._get_auth().type == AuthType.PASSWORD:
            self._set_candidate_auth(PasswordAuth(password))

    def _encrypt_password(self, pwd: str) -> str:
        agent = get_info(self.server)
        if agent.version < OBShellVersion.V424:
            pk = get_public_key(self.server)
            key = RSA.import_key(base64.b64decode(pk))
            cipher = PKCS1_cipher.new(key)
            data_to_encrypt = bytes(pwd.encode('utf8'))
            chunks = [data_to_encrypt[i:i + 53]
                      for i in range(0, len(data_to_encrypt), 53)]
            encrypted_chunks = [cipher.encrypt(chunk) for chunk in chunks]
            encrypted = b''.join(encrypted_chunks)
            return base64.b64encode(encrypted).decode('utf-8')
        return pwd

    def _parse_pkg(self, pkg_path: str):
        file_name = os.path.basename(pkg_path)
        with open(pkg_path, "rb") as f:
            file = {'file': (file_name, f)}
            req = requests.Request('POST',
                                   f"http://{self.server}/api/v1/ob/pkg/upload",
                                   files=file)
            prepared = req.prepare()
            return prepared.body, prepared.headers

    def _handle_ret_from_content_request(self, req, cls=None):
        resp = self._execute(req)
        if resp.status_code == 200:
            if cls is None:
                return True
            else:
                contents = resp.json().get('data', {}).get('contents', [])
                if not contents:
                    return []
                return [cls.from_dict(data)
                        for data in resp.json().get('data', {}).get('contents', [])]
        else:
            raise OBShellHandleError(resp.json()['error'])

    def _handle_ret_request(self, req, cls=None):
        resp = self._execute(req)
        if resp.status_code == 200:
            if cls is None:
                return True
            else:
                return cls.from_dict(resp.json()['data'])
        elif resp.status_code == 204:
            return None
        elif resp.status_code >= 400:
            raise OBShellHandleError(resp.json()['error'])
        else:
            raise Exception(f"Unknown error: {resp.json()}")

    def _get_failed_dag_last_log(self, dag: task.DagDetailDTO):
        nodes = dag.nodes
        logs = ""
        for node in nodes:
            if not node.is_failed():
                continue
            if node.operator == task.Operator.CANCEL_STR.value:
                return f"Task {dag.name} canceled."
            for sub_task in node.sub_tasks:
                if sub_task.is_failed():
                    logs = logs + (f"{sub_task.execute_agent} "
                                   f"{sub_task.task_logs[len(sub_task.task_logs) - 1]}\n")
            return logs

    def __handle_task_ret_request(self, req):
        return self._handle_ret_request(req, task.DagDetailDTO)

    def create_request(self, uri: str, method: str, data=None, query_param=None, need_auth=True):
        return BaseRequest(uri, method,
                           self.host, self.port, query_param=query_param,
                           data=data, need_auth=need_auth, timeout=self._timeout)

    # Function for OpenAPI
    def join(self, ip: str, port: int, zone: str) -> task.DagDetailDTO:
        """Joins a new agent to the uninitialized cluster.

        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the join task to succeed or
        use join_sync to join synchronously instead.

        Args:
            ip (str): The ip of the agent to be joined.
            port (int): The port of the agent to be joined.
            zone (str): The zone of the agent to be joined.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: Error message return by OBShell server.
        """
        try:
            c = ClientV1(ip, port)
            auth = self._get_auth()
            c._set_auth(auth)
            req = c.create_request("/api/v1/agent/join", "POST",
                                   data={
                                       "agentInfo": {"ip": self.host, "port": self.port},
                                       "zoneName": zone
                                   })
            dag = c.__handle_task_ret_request(req)
        finally:
            auth.reset_method()
        return dag

    def join_sync(self, ip: str, port: int, zone: str) -> task.DagDetailDTO:
        """Joins a new agent to the uninitialized cluster synchronously.

        Seealso join.
        Waits for the join task to succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.join(ip, port, zone)
        return self.wait_dag_succeed(dag.generic_id)

    def remove(self, ip: str, port: int) -> task.DagDetailDTO:
        """Removes an agent from the uninitialized cluster.

        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the remove task to succeed or
        use remove_sync to remove synchronously instead.

        Args:
            ip (str): The ip of the agent to be removed.
            port (int): The port of the agent to be removed.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request("/api/v1/agent/remove", "POST",
                                  data={"ip": ip, "port": port})
        return self.__handle_task_ret_request(req)

    def remove_sync(self, ip: str, port: int) -> task.DagDetailDTO:
        """Removes an agent from the uninitialized cluster synchronously.

        Seealso remove.
        Waits for the remove task to succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.remove(ip, port)
        return self.wait_dag_succeed(dag.generic_id)

    def config_observer(self,
                        configs: dict,
                        level: str,
                        target: list,
                        restart=True) -> task.DagDetailDTO:
        """Sets the configuration of the observer.

        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the configure observer task to succeed or
        use config_observer_sync to configure synchronously instead.

        Args:
            configs (dict): The configuration of the observer.
            level (str): The level of target.

                - 'SERVER'. target is the list of 'ip:port'.
                - 'ZONE'. target is the list of zone name.
                - 'GLOBAL'. target is empty.

            target (list): The target OBShells to be configured. seealso level.
            restart (bool, optional): Whether to restart the observer after configuration.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request("/api/v1/observer/config", "POST",
                                  data={
                                      "observerConfig": configs,
                                      "scope": {
                                          "type": level,
                                          "target": target
                                      },
                                      "restart": restart
                                  })
        return self.__handle_task_ret_request(req)

    def config_observer_sync(self,
                             configs: dict,
                             level: str,
                             target: list,
                             restart=True) -> task.DagDetailDTO:
        """Sets the configuration of the observer synchronously.

        Seealso config_observer.
        Waits for the configure observer task to succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.config_observer(configs, level, target, restart)
        return self.wait_dag_succeed(dag.generic_id)

    def config_obcluster(self,
                         cluster_name: str,
                         cluster_id: int,
                         root_pwd: str) -> task.DagDetailDTO:
        """Sets the configuration of the obcluster.

        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the configure obcluster task to succeed or
        use config_obcluster_sync to configure synchronously instead.

        Args:
            cluster_name (str): The name of the obcluster.
            cluster_id (int): The id of the obcluster.
            root_pwd (str): The password of root@sys user.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request("/api/v1/obcluster/config", "POST",
                                  data={
                                      "clusterName": cluster_name,
                                      "clusterId": cluster_id,
                                      "rootPwd": self._encrypt_password(root_pwd)
                                  })
        dag = self.__handle_task_ret_request(req)
        self._set_password_candidate_auth(root_pwd)
        return dag

    def config_obcluster_sync(self,
                              cluster_name: str,
                              cluster_id: int,
                              root_pwd: str) -> task.DagDetailDTO:
        """Sets the configuration of the obcluster synchronously.

        Seealso config_obcluster.
        Waits for the configure obcluster task to succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.config_obcluster(cluster_name, cluster_id, root_pwd)
        self._set_password_candidate_auth(root_pwd)
        return self.wait_dag_succeed(dag.generic_id)

    def init(self, import_script=False) -> task.DagDetailDTO:
        """Initializes the cluster.

        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the init task to succeed or
        use init_sync to initialize synchronously instead.

        Args:
            import_script (bool, optional): 
                Whether need to import the observer's script. Defaults to False.
                Support from OBShell V4.2.4.2.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request(
            "/api/v1/ob/init", "POST", data={"import_script": import_script})
        return self.__handle_task_ret_request(req)

    def init_sync(self, import_script=False) -> task.DagDetailDTO:
        """Initializes the cluster synchronously.

        Seealso init.
        Waits for the init task to succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.init(import_script)
        return self.wait_dag_succeed(dag.generic_id)

    def start(self, level: str, target: list, force_pass_dag=None) -> task.DagDetailDTO:
        """Starts specified observer.

        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the start observer task to succeed or
        use start_sync to start synchronously instead.

        Args:
            level (str): The level of target.

                - 'SERVER'. target is the list of ip:port.
                - 'ZONE'. target is the list of zone name.
                - 'GLOBAL'. target is empty.

            target (list): The targets of the observer to be started. seealso level.
            force_pass_dag (list, optional):
                The dags that need to be forced to pass. Defaults to None.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        if force_pass_dag is None:
            force_pass_dag = []
        req = self.create_request("/api/v1/ob/start", "POST",
                                  data={
                                      "scope": {"type": level, "target": target},
                                      "forcePassDag": {"id": force_pass_dag}
                                  })
        return self.__handle_task_ret_request(req)

    def start_sync(
            self, level: str, target: list, force_pass_dag=None) -> task.DagDetailDTO:
        """Starts specified observer synchronously.

        Seealso start.
        Waits for the start observer task to succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.start(level, target, force_pass_dag)
        return self.wait_dag_succeed(dag.generic_id)

    def stop(self,
             level: str,
             target: list,
             force=False,
             terminate=False,
             force_pass_dag=None) -> task.DagDetailDTO:
        """Stops specified observer

        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the stop observer task to succeed or
        use stop_sync to stop synchronously instead.

        Args:
            level (str): The level of target.

                - 'SERVER'. target is the list of ip:port.
                - 'ZONE'. target is the list of zone name.
                - 'GLOBAL'. target is empty.

            target (list): The targets of the observer to be stopped. seealso level.
            force (bool, optional):
                Whether to forcely stop. Defaults to False.
            terminate (bool, optional):
                Whether to execute "MINOR FREEZE" before stop the observer.
                Defaults to False.
            force_pass_dag (list, optional):
                The dags that need to be forced to pass.
                Defaults to None.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        if force_pass_dag is None:
            force_pass_dag = []
        req = self.create_request("/api/v1/ob/stop", "POST",
                                  data={
                                      "scope": {"type": level, "target": target},
                                      "force": force,
                                      "terminate": terminate,
                                      "forcePassDag": {"id": force_pass_dag}
                                  })
        return self.__handle_task_ret_request(req)

    def stop_sync(self,
                  level: str,
                  target: list,
                  force=False,
                  terminate=False,
                  force_pass_dag=None) -> task.DagDetailDTO:
        """Stops specified observer synchronously.

        Seealso stop.
        Waits for the stop observer task to succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.stop(level, target, force, terminate, force_pass_dag)
        return self.wait_dag_succeed(dag.generic_id)

    def scale_out(
            self, ip: str, port: int, zone: str, ob_configs: dict) -> task.DagDetailDTO:
        """Scales out the cluster.

        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the scale_out task to succeed or
        use scale_out_sync to scale out synchronously instead.

        Args:
            ip (str): The ip of the agent to added.
            port (int): The port of the agent to added.
            zone (str): The zone of the agent to be added.
            ob_configs (dict): The configuration of the observer.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request("/api/v1/ob/scale_out", "POST",
                                  data={
                                      "agentInfo": {"ip": ip, "port": port},
                                      "zone": zone,
                                      "obConfigs": ob_configs,
                                  })
        return self.__handle_task_ret_request(req)

    def scale_out_sync(self,
                       ip: str,
                       port: int,
                       zone: str,
                       ob_configs: dict) -> task.DagDetailDTO:
        """Scales out the cluster synchronously.

        Seealso scale_out.
        Waits for the scale_out task to succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.scale_out(ip, port, zone, ob_configs)
        return self.wait_dag_succeed(dag.generic_id)

    def upload_pkg(self, pkg_path: str) -> UpgradePkgInfo:
        """upload package to obcluster

        uploads the neccssary packages before upgrading OBShell or observer.

        Args:
            pkg_path (str): The absolute path of the package.

        Returns:
            UpgradePkgInfo: package information.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request("/api/v1/upgrade/package", "POST")
        data, headers = self._parse_pkg(pkg_path)
        req.data = data
        req.headers = headers
        return self._handle_ret_request(req, UpgradePkgInfo)

    def upgrade_agent_check(
            self, version: str, release: str, upgrade_dir=None) -> task.DagDetailDTO:
        """Checks before upgrading agent

        Checks if the upgrade conditions are met, such as target package has been
        uploaded, the target version and release are valid.
        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the check task to succeed or
        use upgrade_agent_check_sync to check synchronously instead.

        Args:
            version (str): The version of the agent to be upgraded to.
            release (str): The release of the agent to be upgraded to.
            upgrade_dir (str, optional): the temp dir to used by the task.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request("/api/v1/agent/upgrade/check", "POST",
                                  data={
                                      "version": version,
                                      "release": release,
                                      "upgradeDir": upgrade_dir
                                  })
        return self.__handle_task_ret_request(req)

    def upgrade_agent_check_sync(
            self, version: str, release: str, upgrade_dir=None) -> task.DagDetailDTO:
        """Checks before upgrading agent synchronously

        Seealso upgrade_agent_check.
        Waits for the check task to succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.upgrade_agent_check(version, release, upgrade_dir)
        return self.wait_dag_succeed(dag.generic_id)

    def upgrade_agent(
            self, version: str, release: str, upgrade_dir=None) -> task.DagDetailDTO:
        """Upgrades agent

        Upgrades the agent to the target version and release.
        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the upgrade task to succeed or
        use upgrade_agent_sync to upgrade synchronously instead.

        Args:
            version (str): The version of the agent to be upgraded to.
            release (str): The release of the agent to be upgraded to.
            upgrade_dir (str, optional): the temp dir to used by the upgrade task.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request("/api/v1/agent/upgrade", "POST",
                                  data={
                                      "version": version,
                                      "release": release,
                                      "upgradeDir": upgrade_dir
                                  })
        return self.__handle_task_ret_request(req)

    def upgrade_agent_sync(
            self, version: str, release: str, upgrade_dir=None) -> task.DagDetailDTO:
        """Upgrades agent synchronously.

        Seealso upgrade_agent.
        Waits for the upgrade task to succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.upgrade_agent(version, release, upgrade_dir)
        return self.wait_dag_succeed(dag.generic_id)

    def upgrade_ob_check(
            self, version: str, release: str, upgrade_dir=None) -> task.DagDetailDTO:
        """Checks before upgrading ob.

        Checks if the upgrade conditions are met, such as target package has been
        uploaded, the target version and release are valid.
        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the check task to succeed or
        use upgrade_ob_check_sync to check synchronously instead.

        Args:
            version (str): The version of the observer to be upgraded to.
            release (str): The release of the observer to be upgraded to.
            upgrade_dir (str, optional): the temp dir used by the task.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request("/api/v1/ob/upgrade/check", "POST",
                                  data={
                                      "version": version,
                                      "release": release,
                                      "upgradeDir": upgrade_dir
                                  })
        return self.__handle_task_ret_request(req)

    def upgrade_ob_check_sync(
            self, version: str, release: str, upgrade_dir=None) -> task.DagDetailDTO:
        """Checks before upgrading ob synchronously.

        Seealso upgrade_ob_check.

        Waits for the check task to succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.upgrade_ob_check(version, release, upgrade_dir)
        return self.wait_dag_succeed(dag.generic_id)

    def upgrade_ob(self,
                   version: str,
                   release: str,
                   mode: str,
                   upgrade_dir=None) -> task.DagDetailDTO:
        """Upgrades observer

        Upgrades the observer to the target version and release.
        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the upgrade task to succeed or
        use upgrade_ob_sync to upgrade synchronously instead.

        Args:
            version (str): The version of the observer to be upgraded to.
            release (str): The release of the observer to be upgraded to.
            mode (str): Upgrade mode.

                - 'ROLLING'. Rolling upgrade.
                - 'STOPSERVICE'. Stop service upgrade.

            upgrade_dir (str, optional): the temp dir to used by the upgrade task.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request("/api/v1/ob/upgrade", "POST",
                                  data={
                                      "version": version,
                                      "release": release,
                                      "mode": mode,
                                      "upgradeDir": upgrade_dir
                                  })
        return self.__handle_task_ret_request(req)

    def upgrade_ob_sync(self,
                        version: str,
                        release: str,
                        mode: str,
                        upgrade_dir=None) -> task.DagDetailDTO:
        """Upgrades observer synchronously.

        Seealso upgrade_ob.
        Waits for the upgrade task to succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.upgrade_ob(version, release, mode, upgrade_dir)
        return self.wait_dag_succeed(dag.generic_id)

    def get_dag(self, generic_id: str, show_detail=True) -> task.DagDetailDTO:
        """Gets the detail of a task(DAG).

        Gets the detail of a task(DAG) by generic_id.

        Args:
            generic_id (str): The generic_id of the task.
            show_detail (bool, optional): Whether to show the detail of the task
                such as sub nodes. Defaults to True.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request(f"/api/v1/task/dag/{generic_id}", "GET",
                                  query_param={"show_details": show_detail})
        return self._handle_ret_request(req, task.DagDetailDTO)

    def operate_dag(self, generic_id: str, operator: str) -> task.DagDetailDTO:
        """Operates a task(DAG).

        Operates a task(DAG) by generic_id.
        Return as soon as request successfully.

        Args:
            generic_id (str): The generic_id of the task.
            operator (str): The operator to operate the task.

                - 'ROLLBACK'. Rollback a failed task.
                - 'CANCEL'. Cancel a runnig task.
                - 'RETRY'. Retry a failed task.
                - 'PASS'. Pass a failed task.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request(f"/api/v1/task/dag/{generic_id}", "POST",
                                  data={"operator": operator})
        return self._handle_ret_request(req)

    def operate_dag_sync(self, generic_id: str, operator: str):
        """Operates a task(DAG) synchronously.

        Seealso operate_dag.
        Waits for the operation succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the operation failed,
                include the failed task detail and logs.
        """
        self.operate_dag(generic_id, operator)
        dag = None
        try:
            dag = self.wait_dag_succeed(generic_id)
        except TaskExecuteFailedError as e:
            dag = e.dag
        if operator.upper() == task.Operator.ROLLBACK_STR.value:
            if dag.is_succeed() and dag.is_rollback():
                return True
        elif operator.upper() == task.Operator.CANCEL_STR.value:
            if dag.is_failed() and dag.is_cancel():
                return True
        elif operator.upper() == task.Operator.RETRY_STR.value:
            if dag.is_succeed() and dag.is_run():
                return True
        elif operator.upper() == task.Operator.PASS_STR.value:
            if dag.is_succeed() and dag.is_pass():
                return True
        raise TaskExecuteFailedError(
            f"Failed to {operator} task {generic_id}", dag)

    def get_node(self, generic_id: str, show_detail=True) -> task.NodeDetailDTO:
        """Gets the detail of a task node.

        Gets the detail of a task node by generic_id.
        Node is the item of a task(DAG).

        Args:
            generic_id (str): The generic_id of the node.
            show_detail (bool, optional): Whether to show the detail of the node
                such as sub tasks. Defaults to True.

        Returns:
            Node detail as NodeDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request(f"/api/v1/task/node/{generic_id}", "GET",
                                  query_param={"show_details": show_detail})
        return self._handle_ret_request(req, task.NodeDetailDTO)

    def get_sub_task(self, generic_id: str) -> task.TaskDetailDTO:
        """Gets the detail of a sub task.

        Gets the detail of a sub task by generic_id.
        Sub task is the item of a task node.

        Args:
            generic_id (str): The generic_id of the sub task.
        """
        req = self.create_request(f"/api/v1/task/sub_task/{generic_id}", "GET")
        return self._handle_ret_request(req, task.TaskDetailDTO)

    def get_agent_last_maintenance_dag(self, show_detail=True) -> task.DagDetailDTO:
        req = self.create_request("/api/v1/task/dag/maintain/agent", "GET",
                                  query_param={"show_details": show_detail})
        return self._handle_ret_request(req, task.DagDetailDTO)

    def get_agent_unfinished_dag(self, show_detail=True):
        req = self.create_request("/api/v1/task/dag/agent/unfinish", "GET",
                                  query_param={"show_details": show_detail})
        return self._handle_ret_from_content_request(req, task.DagDetailDTO)

    def get_all_agent_last_maintenance_dag(self, show_detail=True):
        req = self.create_request("/api/v1/task/dag/maintain/agents", "GET",
                                  query_param={"show_details": show_detail})
        return self._handle_ret_from_content_request(req, task.DagDetailDTO)

    def get_cluster_unfinished_dag(self, show_detail=True):
        req = self.create_request("/api/v1/task/dag/ob/unfinish", "GET",
                                  query_param={"show_details": show_detail})
        return self._handle_ret_from_content_request(req, task.DagDetailDTO)

    def get_ob_last_maintenance_dag(self, show_detail=True) -> task.DagDetailDTO:
        req = self.create_request("/api/v1/task/dag/maintain/ob", "GET",
                                  query_param={"show_details": show_detail})
        return self._handle_ret_from_content_request(req, task.DagDetailDTO)

    def get_unfinished_dags(self, show_detail=True):
        req = self.create_request("/api/v1/task/dag/unfinish", "GET",
                                  query_param={"show_details": show_detail})
        return self._handle_ret_from_content_request(req, task.DagDetailDTO)

    def get_ob_info(self) -> info.ObInfo:
        req = self.create_request("/api/v1/ob/info", "GET")
        return self._handle_ret_request(req, info.ObInfo)

    def get_status(self) -> info.AgentStatusWithOb:
        req = self.create_request("/api/v1/status", "GET", need_auth=False)
        return self._handle_ret_request(req, info.AgentStatusWithOb)

    def get_info(self) -> info.AgentStatusWithZone:
        req = self.create_request("/api/v1/info", "GET", need_auth=False)
        return self._handle_ret_request(req, info.AgentStatusWithZone)

    def wait_dag_succeed(self, generic_id: str, retry_time=60) -> task.DagDetailDTO:
        """Waits for a task(DAG) to succeed.

        Waits for a task(DAG) to succeed.

        Args:
            generic_id (str): The generic_id of the task.
            retry_time (int, optional): The retry times when connection error occurs.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            requests.exceptions.ConnectionError: Connection error.
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
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

    # Tenant API function
    def create_resource_unit_config(
            self, unit_config_name: str, memory_size: str, max_cpu: float,
            min_cpu: float = None, max_iops: int = None, min_iops: int = None,
            log_disk_size: str = None) -> bool:
        """Creates a resource unit config.

        Args:
            unit_config_name (str): The name of the resource unit config.
            memory_size (str): The memory size of the resource unit config.
            max_cpu (float): The max cpu of the resource unit config, should be greater than 1.
            min_cpu (float, optional): 
                The min cpu of the resource unit config, should be greater than 1.
                If not set, the min cpu will be set to the max cpu.
            max_iops (int, optional): The max iops of the resource unit config.
                If not set, the max iops will be set default value by observer.
            min_iops (int, optional): The min iops of the resource unit config.
                If not set, the min iops will be set default value by observer.
            log_disk_size (str, optional): The log disk size of the resource unit config.
                If not set, the log disk size will be set default value by observer.

        Returns:
            bool: True if success.

        Raises:
            OBShellHandleError: Error message return by OBShell server.
        """
        data = {}
        data["name"] = unit_config_name
        data["memory_size"] = memory_size
        data["max_cpu"] = max_cpu
        if min_cpu is not None:
            data["min_cpu"] = min_cpu
        if max_iops is not None:
            data["max_iops"] = max_iops
        if min_iops is not None:
            data["min_iops"] = min_iops
        if log_disk_size is not None:
            data["log_disk_size"] = log_disk_size
        req = self.create_request("/api/v1/unit/config", "POST", data=data)
        return self._handle_ret_request(req)

    def drop_resource_unit_config(self, unit_config_name: str) -> bool:
        """Drops a existing resource unit config.

        Args:
            unit_config_name (str): The name of the resource unit config.

        Returns:
            bool: True if success.

        Raises:
            OBShellHandleError: Error message return by OBShell server.
        """
        req = self.create_request(
            f"/api/v1/unit/config/{unit_config_name}", "DELETE")
        return self._handle_ret_request(req)

    def get_all_resource_unit_configs(self) -> List[unit.UnitConfig]:
        """Gets all exsiting resource unit configs."""
        req = self.create_request("/api/v1/units/config", "GET")
        return self._handle_ret_from_content_request(req, unit.UnitConfig)

    def get_resource_unit_config(self, unit_config_name: str) -> unit.UnitConfig:
        """Gets a specific resource uint config by name"""
        req = self.create_request(
            f"/api/v1/unit/config/{unit_config_name}", "GET")
        return self._handle_ret_request(req, unit.UnitConfig)

    def create_tenant(
            self, tenant_name: str, zone_list: List[tenant.ZoneParam], mode: str = 'MYSQL', primary_zone: str = None, whitelist: str = None,
            root_password: str = None, scenario: str = None, import_script: bool = False,
            charset: str = None, collation: str = None, read_only: bool = False,
            comment: str = None, variables: dict = None, parameters: dict = None) -> task.DagDetailDTO:
        """Creates a tenant.

        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the create tenant task to succeed or
        use create_tenant_sync to upgrade synchronously instead.

        Seealso create_tenant_sync.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """

        data = {
            "name": tenant_name,
            "zone_list": [zone.__dict__ for zone in zone_list],
        }
        options = ['mode', 'primary_zone', 'whitelist', 'root_password', 'charset',
                   "import_script", 'collation', 'read_only', 'comment', 'variables',
                   'parameters', 'scenario']
        mydict = locals()
        for k, v in mydict.items():
            if k in options and v is not None:
                data[k] = v
        req = self.create_request("/api/v1/tenant", "POST", data=data)
        return self.__handle_task_ret_request(req)

    def create_tenant_sync(
            self, tenant_name: str, zone_list: List[tenant.ZoneParam], mode: str = 'MYSQL',
            primary_zone: str = "RANDOM", whitelist: str = None,
            root_password: str = None, scenario: str = None, import_script: bool = False,
            charset: str = None, collation: str = None, read_only: bool = False,
            comment: str = None, variables: dict = None, parameters: dict = None) -> task.DagDetailDTO:
        """Create a tenant synchronously.

        Creates a tenant with the specified name and zone list.

        Args:
            name (str): The name of the tenant.
            zone_list (List[ZoneParam]): 
                The zone list of the tenant, include replica configs and unit configs.
            mode (str, optional): 
                The mode of the tenant, "MYSQL" or "ORACLE". Defaults to 'MYSQL'.
            primary_zone (str, optional): 
                The primary zone of the tenant. Defaults to "RANDOM".
            whitelist (str, optional): 
                The whitelist of the tenant. Defaults to None.
            scenario:
                The scenario of the tenant.
                Can be one of 'express_oltp', 'complex_oltp', 'olap', 'htap', 'kv'.
                Defaults to 'oltp'.
            root_password (str, optional): 
                The root password of the tenant. Defaults to Empty.
            import_script (bool, optional):
                Whether need to import the observer's script. Defaults to False.
                Support from OBShell V4.2.4.2.
            charset (str, optional): The charset of the tenant.
                If not set, the charset will be set to default value by observer.
            collation (str, optional): The collation of the tenant.
                If not set, the collation will be set to default value by observer.
            read_only (bool, optional): 
                Whether the tenant is read only. Defaults to False.
            comment (str, optional): The comment of the tenant.
            variables (dict, optional): The variables of the tenant.
            parameters (dict, optional): The parameters of the tenant.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.create_tenant(
            tenant_name, zone_list, mode, primary_zone, whitelist, root_password,
            scenario, import_script, charset, collation, read_only, comment, variables, parameters)
        return self.wait_dag_succeed(dag.generic_id)

    def drop_tenant(self, tenant_name: str, need_recycle: bool = False) -> task.DagDetailDTO:
        """Drops a tenant.

        Drops a tenant by name.
        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the drop tenant task to succeed or
        use drop_tenant_sync to upgrade synchronously instead.

        Seealso drop_tenant_sync.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}", "DELETE", data={"need_recycle": need_recycle})
        return self.__handle_task_ret_request(req)

    def drop_tenant_sync(self, tenant_name: str, need_recycle: bool = False) -> task.DagDetailDTO:
        """Drops a tenant synchronously.

        Drops a tenant by name.

        Args:
            tenant_name (str): The name of the tenant. Return None if tenant not exist.
            need_recycle (str, optional): Whether to recycle the tenant's resource. Defaults to False.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.drop_tenant(tenant_name, need_recycle)
        if dag is None:
            return None
        return self.wait_dag_succeed(dag.generic_id)

    def lock_tenant(self, tenant_name: str) -> bool:
        """Locks the tenant.

        Locking the tenant to make it inaccessible.
        """
        req = self.create_request(f"/api/v1/tenant/{tenant_name}/lock", "POST")
        return self._handle_ret_request(req)

    def unlock_tenant(self, tenant_name: str) -> bool:
        """Unlocks the tenant."""
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}/lock", "DELETE")
        return self._handle_ret_request(req)

    def rename_tenant(self, tenant_name: str, new_name: str) -> task.DagDetailDTO:
        """Renames the tenant."""
        req = self.create_request(f"/api/v1/tenant/{tenant_name}/name", "PUT", data={
            "new_name": new_name
        })
        return self._handle_ret_request(req)

    def add_tenant_replica(self, tenant_name: str, zone_list: List[tenant.ZoneParam]) -> task.DagDetailDTO:
        """Adds tenant replicas.

        Add replicas on specified zones to the tenant.
        You can use wait_dag_succeed to wait for the add tenant replica task to succeed or
        use add_tenant_replica_sync to add synchronously instead.

        Seealso add_tenant_replica_sync.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request(f"/api/v1/tenant/{tenant_name}/replicas", "POST", data={
            "zone_list": [zone.__dict__ for zone in zone_list]
        })
        return self.__handle_task_ret_request(req)

    def add_tenant_replica_sync(self, tenant_name: str, zone_list: List[tenant.ZoneParam]) -> task.DagDetailDTO:
        """Adds tenant replicas synchronously.

        Adds replicas on specified zones to the tenant.

        Args:
            tenant_name (str): The name of the tenant.
            zone_list(ZoneParam): 
                The zone list of the tenant, include replica configs and unit configs.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.add_tenant_replica(tenant_name, zone_list)
        return self.wait_dag_succeed(dag.generic_id)

    def delete_tenant_replica(self, tenant_name: str, zones: List[str]) -> task.DagDetailDTO:
        """Deletes tenant replicas.

        Delete replicas on specified zones from the tenant.
        You can use wait_dag_succeed to wait for the delete tenant replica task to succeed or
        use delete_tenant_replica_sync to delete synchronously instead.

        Seealso delete_tenant_replica_sync.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request(f"/api/v1/tenant/{tenant_name}/replicas", "DELETE", data={
            "zones": zones
        })
        return self.__handle_task_ret_request(req)

    def delete_tenant_replica_sync(self, tenant_name: str, zones: List[str]) -> task.DagDetailDTO:
        """Deletes tenant replicas synchronously.

        Deletes replicas on specified zones from the tenant.

        Args:
            tenant_name (str): The name of the tenant.
            zones (List[str]): 
                The zone list of the tenant where the replicas locate on.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.delete_tenant_replica(tenant_name, zones)
        return self.wait_dag_succeed(dag.generic_id)

    def modify_tenant_replica(self, tenant_name: str, zone_list: List[tenant.ModifyReplicaParam]) -> task.DagDetailDTO:
        """Modifies tenant replicas.

        Modify replicas' properties on specified zones of the tenant,
        include unit config, unit num and replica type.
        You can use wait_dag_succeed to wait for the modify tenant replica task to succeed or
        use modify_tenant_replica_sync to modify synchronously instead.

        Seealso modify_tenant_replica_sync.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request(f"/api/v1/tenant/{tenant_name}/replicas", "PATCH", data={
            "zone_list": [zone.__dict__ for zone in zone_list]
        })
        return self.__handle_task_ret_request(req)

    def modify_tenant_replica_sync(self, tenant_name: str, zone_list: List[tenant.ModifyReplicaParam]) -> task.DagDetailDTO:
        """Modifies tenant replicas synchronously.

        Modifies replicas' properties on specified zones of the tenant,
        include unit config, unit num and replica type.

        Args:
            tenant_name (str): The name of the tenant.
            zone_list (List[ModifyReplicaParam]): 
                The zone list of the tenant where the replicas locate on.

        Returns:
            Task detail as task.DagDetailDTO. Return None if nothing has be changed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        resp = self.modify_tenant_replica(tenant_name, zone_list)
        if resp is not None:  # no content resp
            return self.wait_dag_succeed(resp.generic_id)
        return None

    def set_tenant_primary_zone_sync(self, tenant_name: str, primary_zone: str) -> task.DagDetailDTO:
        """Sets the primary zone of the tenant synchronously.

        Args:
            tenant_name (str): The name of the tenant.
            primary_zone (str): The primary zone of the tenant. For example:
                "zone1;zone2,zone3".
        """
        resp = self.set_tenant_primary_zone(tenant_name, primary_zone)
        if resp is not None:  # no content resp
            return self.wait_dag_succeed(resp.generic_id)
        return None

    def set_tenant_primary_zone(self, tenant_name: str, primary_zone: str) -> task.DagDetailDTO:
        """Sets the primary zone of the tenant.

        Args:
            tenant_name (str): The name of the tenant.
            primary_zone (str): The primary zone of the tenant. For example:
                "zone1;zone2,zone3".
        """
        req = self.create_request(f"/api/v1/tenant/{tenant_name}/primary-zone", "PUT", data={
            "primary_zone": primary_zone
        })
        return self.__handle_task_ret_request(req)

    def set_tenant_whitelist(self, tenant_name: str, whitelist: str) -> bool:
        """Sets the access whitelist of the tenant.

        Args:
            tenant_name (str): The name of the tenant.
            whitelist (str): The access whitelist of the tenant. For example:
                "%".
        """
        req = self.create_request(f"/api/v1/tenant/{tenant_name}/whitelist", "PUT", data={
            "whitelist": whitelist
        })
        return self._handle_ret_request(req)

    def set_tenant_root_password(self, tenant_name: str, new_password: str, old_password: str = "") -> bool:
        """Sets the root password of the tenant."""
        req = self.create_request(f"/api/v1/tenant/{tenant_name}/password", "PUT", data={
            "old_password": old_password,
            "new_password": new_password
        })
        return self._handle_ret_request(req)

    def set_tenant_variables(self, tenant_name: str, variables: dict) -> bool:
        """Sets the global variables of the tenant."""
        req = self.create_request(f"/api/v1/tenant/{tenant_name}/variables", "PUT", data={
            "variables": variables
        })
        return self._handle_ret_request(req)

    def set_tenant_parameters(self, tenant_name: str, parameters: dict) -> bool:
        """Sets the global parameters of the tenant."""
        req = self.create_request(f"/api/v1/tenant/{tenant_name}/parameters", "PUT", data={
            "parameters": parameters
        })
        return self._handle_ret_request(req)

    def get_tenant_variable(self, tenant_name: str, variable: str) -> tenant.VariableInfo:
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}/variable/{variable}", "GET")
        return self._handle_ret_request(req, tenant.VariableInfo)

    def get_tenant_parameter(self, tenant_name: str, parameter: str) -> tenant.ParameterInfo:
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}/parameter/{parameter}", "GET")
        return self._handle_ret_request(req, tenant.ParameterInfo)

    def get_tenant_variables(self, tenant_name: str, filter: str = "%") -> List[tenant.VariableInfo]:
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}/variables", "GET", query_param={"filter": filter})
        return self._handle_ret_from_content_request(req, tenant.VariableInfo)

    def get_tenant_parameters(self, tenant_name: str, filter: str = "%") -> List[tenant.ParameterInfo]:
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}/parameters", "GET", query_param={"filter": filter})
        return self._handle_ret_from_content_request(req, tenant.ParameterInfo)

    def get_tenant_info(self, tenant_name: str) -> tenant.TenantInfo:
        req = self.create_request(f"/api/v1/tenant/{tenant_name}", "GET")
        return self._handle_ret_request(req, tenant.TenantInfo)

    def get_all_tenants(self) -> List[tenant.TenantOverView]:
        req = self.create_request("/api/v1/tenants/overview", "GET")
        return self._handle_ret_from_content_request(req, tenant.TenantOverView)

    # Pool API function
    def get_all_resource_pools(self) -> List[pool.ResourcePoolInfo]:
        req = self.create_request("/api/v1/resource-pools", "GET")
        return self._handle_ret_from_content_request(req, pool.ResourcePoolInfo)

    def drop_resource_pool(self, pool_name: str):
        req = self.create_request(
            f"/api/v1/resource-pool/{pool_name}", "DELETE")
        return self._handle_ret_request(req)

    # Recyclebin API function
    def flashback_recyclebin_tenant(self, object_or_original_name: str, new_name: str = None) -> bool:
        """Restores the tenant from recyclebin.

        Args:
            object_or_original_name (str): The object name or original name
                of the tenant in recyclebin.
            new_name (str, optional): The new name of the tenant. Defaults to None.
                when new_name is None, the tenant will be restored with its original name.

        Returns:
            bool: True if success.

        Raises:
            OBShellHandleError: Error message return by OBShell server.
        """
        req = self.create_request(f"/api/v1/recyclebin/tenant/{object_or_original_name}", "POST", data={
            "new_name": new_name
        })
        return self._handle_ret_request(req)

    def purge_recyclebin_tenant(self, object_or_original_name: str) -> task.DagDetailDTO:
        """Purges the tenant in recyclebin.

        Seealse purge_recyclebin_tenant_sync

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: Error message return by OBShell server.
        """
        req = self.create_request(
            f"/api/v1/recyclebin/tenant/{object_or_original_name}", "DELETE")
        return self.__handle_task_ret_request(req)

    def purge_recyclebin_tenant_sync(self, object_or_original_name: str) -> bool:
        """Purges the tenant in recyclebin synchronously.

        Args:
            object_or_tenant_name (str): The object name or tenant name in recyclebin.
                When using original name, if there are multiple tenants with the same
                original name, the latest one will be purged.
                The resource of the tenant won't be recycled.

        Returns:
            bool: True if success.

        Raises:
            OBShellHandleError: Error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.purge_recyclebin_tenant(object_or_original_name)
        if dag is None:
            return None
        return self.wait_dag_succeed(dag.generic_id)

    def get_all_recyclebin_tenants(self) -> List[recyclebin.RecyclebinTenantInfo]:
        req = self.create_request("/api/v1/recyclebin/tenants", "GET")
        return self._handle_ret_from_content_request(req, recyclebin.RecyclebinTenantInfo)

    # Aggregation function

    def agg_clear_uninitialized_agent(self):
        """Clears the agent in a uninitialized cluster.

        Clears a "MASTER" or "FOLLOWER" agent to a "SINGLE".
        if there is a failed "Initialize Cluster" task, rollback it.
        if the agent is "MASTER", all of the agents will be removed.

        """
        agent = get_info(self.server)
        dag = self.get_agent_last_maintenance_dag()
        need_remove = False
        if (agent.identity == info.Agentidentity.FOLLOWER or
                agent.identity == info.Agentidentity.MASTER):
            need_remove = True
        if dag.name == "Initialize cluster":
            if not dag.is_finished():
                raise IllegalOperatorError(
                    "Cluster initialization is not finished.")
            if dag.is_succeed() and dag.is_run():
                raise IllegalOperatorError(
                    "The 'Initialize Cluster' task is already succeeded")
            if dag.is_failed():
                self.operate_dag_sync(
                    dag.generic_id, task.Operator.ROLLBACK_STR.value)
            need_remove = True
        if need_remove:
            self.remove_sync(self.host, self.port)
        return True

    def agg_create_cluster(
        self,
        servers_with_configs: dict,
        cluster_name: str,
        cluster_id: int,
        root_pwd: str,
        clear_if_failed=False
    ):
        """Creates a new obcluster.

        Creates a new obcluster with the specified servers and configurations.

        Args:
            servers_with_configs (list): The dict of the server and its configurations.
                The configuration should include the zone of the server.
                Example: {'11.11.11.1:2886': {"zone": "zone1", "memory_limit": "18G",
                "system_memory": "4G", "log_disk_size": "24G"}, ...}
            cluster_name (str): The name of the obcluster.
            cluster_id (int): The id of the obcluster.
            root_pwd (str): The password of root@sys user.
            clear_if_failed (bool, optional): Whether to clear the uninitialized agent
                if the task failed. Defaults to False.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
            IllegalOperatorError: raise when the operator is illegal.
        """

        copied_configs = copy.deepcopy(servers_with_configs)
        if self.server not in copied_configs:
            raise IllegalOperatorError(
                "configs should include the server of the client.")
        try:
            if 'zone' not in copied_configs[self.server]:
                raise IllegalOperatorError(
                    "configs should include the zone of the server.")
            self.join_sync(self.host, self.port,
                           copied_configs[self.server]['zone'])
            del copied_configs[self.server]['zone']
            self.config_observer_sync(
                copied_configs[self.server], "SERVER", [self.server])
            del copied_configs[self.server]
            for server, configs in copied_configs.items():
                if 'zone' not in configs:
                    raise IllegalOperatorError(
                        "configs should include the zone of the server.")
                ip, port = server.split(':')
                self.join_sync(ip, port, configs['zone'])
                del configs['zone']
                self.config_observer_sync(configs, "SERVER", [server])
            self.config_obcluster_sync(cluster_name, cluster_id, root_pwd)
            self.init_sync()
        except (OBShellHandleError, TaskExecuteFailedError, IllegalOperatorError) as e:
            if clear_if_failed:
                self.agg_clear_uninitialized_agent()
            raise e

    def _gen_cluster_backup_config(
        self,
        backup_base_uri: str = None,
        log_archive_concurrency: int = -1,
        binding: str = None,
        ha_low_thread_score: int = -1,
        piece_switch_interval: str = None,  # Mandatory or Optional, default Optional
        archive_lag_target: str = None,
        delete_policy: str = None,
        delete_recovery_window: str = None,
    ):
        data = {}
        if backup_base_uri is not None:
            data['backup_base_uri'] = backup_base_uri
        if log_archive_concurrency != -1:
            data['log_archive_concurrency'] = log_archive_concurrency
        if binding is not None:
            data['binding'] = binding
        if ha_low_thread_score != -1:
            data['ha_low_thread_score'] = ha_low_thread_score
        if piece_switch_interval is not None:
            data['piece_switch_interval'] = piece_switch_interval
        if archive_lag_target is not None:
            data['archive_lag_target'] = archive_lag_target
        if delete_policy is not None or delete_recovery_window is not None:
            data['delete_policy'] = {
                'policy': delete_policy,
                'recovery_window': delete_recovery_window
            }
        return data

    def post_cluster_backup_config(
        self,
        backup_base_uri: str,
        log_archive_concurrency: int = -1,
        binding: str = None,
        ha_low_thread_score: int = -1,
        piece_switch_interval: str = None,
        archive_lag_target: str = None,
        delete_policy: str = None,
        delete_recovery_window: str = None,
    ):
        """Configures the backup of the obcluster.

        Configures the backup of the obcluster with the specified configurations.

        Args:
            backup_base_uri (str): The base URI where backups are stored.
            log_archive_concurrency (int, optional): Specifies the concurrency level for log archiving.
            binding (str, optional): Determines the binding mode between archiving and business operations ('Optional' or 'Mandatory').
            ha_low_thread_score (int, optional): Adjusts the thread priority score for high availability tasks.
            piece_switch_interval (str, optional): Defines the interval for switching backup pieces.
            archive_lag_target (str, optional): Sets the target lag time for log archiving processes.
            delete_policy (str, optional): Policy for deletion, limited to 'default'.
            delete_recovery_window (str, optional): Defines the recovery window for which data deletion policies apply.
        """
        data = self._gen_cluster_backup_config(
            backup_base_uri, log_archive_concurrency, binding, ha_low_thread_score,
            piece_switch_interval, archive_lag_target, delete_policy, delete_recovery_window
        )
        req = self.create_request(
            "/api/v1/obcluster/backup/config", "POST", data)
        return self.__handle_task_ret_request(req)

    def post_cluster_backup_config_sync(
        self,
        backup_base_uri: str,
        log_archive_concurrency: int = -1,
        binding: str = None,
        ha_low_thread_score: int = -1,
        piece_switch_interval: str = None,
        archive_lag_target: str = None,
        delete_policy: str = None,
        delete_recovery_window: str = None,
    ):
        """Configures the backup of the obcluster.

        Configures the backup of the obcluster with the specified configurations.
        Wait for the task to succeed.

        Args:
            backup_base_uri (str): The base URI where backups are stored.
            log_archive_concurrency (int, optional): Specifies the concurrency level for log archiving.
            binding (str, optional): Determines the binding mode between archiving and business operations ('Optional' or 'Mandatory').
            ha_low_thread_score (int, optional): Adjusts the thread priority score for high availability tasks.
            piece_switch_interval (str, optional): Defines the interval for switching backup pieces.
            archive_lag_target (str, optional): Sets the target lag time for log archiving processes.
            delete_policy (str, optional): Policy for deletion, limited to 'default'.
            delete_recovery_window (str, optional): Defines the recovery window for which data deletion policies apply.

        """
        dag = self.post_cluster_backup_config(
            backup_base_uri, log_archive_concurrency, binding, ha_low_thread_score,
            piece_switch_interval, archive_lag_target, delete_policy, delete_recovery_window
        )
        return self.wait_dag_succeed(dag.generic_id)

    def patch_cluster_backup_config(
        self,
        backup_base_uri: str = None,
        log_archive_concurrency: int = -1,
        binding: str = None,
        ha_low_thread_score: int = -1,
        piece_switch_interval: str = None,
        archive_lag_target: str = None,
        delete_policy: str = None,
        delete_recovery_window: str = None,
    ):
        """Updates the backup configuration of the obcluster.

        Updates the backup configuration of the obcluster with the specified configurations.

        Args:
            backup_base_uri (str, optional): The base URI where backups are stored.
            log_archive_concurrency (int, optional): Specifies the concurrency level for log archiving.
            binding (str, optional): Determines the binding mode between archiving and business operations ('Optional' or 'Mandatory').
            ha_low_thread_score (int, optional): Adjusts the thread priority score for high availability tasks.
            piece_switch_interval (str, optional): Defines the interval for switching backup pieces.
            archive_lag_target (str, optional): Sets the target lag time for log archiving processes.
            delete_policy (str, optional): Policy for deletion, limited to 'default'.
            delete_recovery_window (str, optional): Defines the recovery window for which data deletion policies apply.
        """
        data = self._gen_cluster_backup_config(
            backup_base_uri, log_archive_concurrency, binding, ha_low_thread_score,
            piece_switch_interval, archive_lag_target, delete_policy, delete_recovery_window
        )
        req = self.create_request(
            "/api/v1/obcluster/backup/config", "PATCH", data)
        return self.__handle_task_ret_request(req)

    def patch_cluster_backup_config_sync(
        self,
        backup_base_uri: str = None,
        log_archive_concurrency: int = -1,
        binding: str = None,
        ha_low_thread_score: int = -1,
        piece_switch_interval: str = None,
        archive_lag_target: str = None,
        delete_policy: str = None,
        delete_recovery_window: str = None,
    ):
        """Updates the backup configuration of the obcluster.

        Updates the backup configuration of the obcluster with the specified configurations.

        Args:
            backup_base_uri (str, optional): The base URI where backups are stored.
            log_archive_concurrency (int, optional): Specifies the concurrency level for log archiving.
            binding (str, optional): Determines the binding mode between archiving and business operations ('Optional' or 'Mandatory').
            ha_low_thread_score (int, optional): Adjusts the thread priority score for high availability tasks.
            piece_switch_interval (str, optional): Defines the interval for switching backup pieces.
            archive_lag_target (str, optional): Sets the target lag time for log archiving processes.
            delete_policy (str, optional): Policy for deletion, limited to 'default'.
            delete_recovery_window (str, optional): Defines the recovery window for which data deletion policies apply.
        """

        dag = self.patch_cluster_backup_config(
            backup_base_uri, log_archive_concurrency, binding, ha_low_thread_score,
            piece_switch_interval, archive_lag_target, delete_policy, delete_recovery_window
        )
        return self.wait_dag_succeed(dag.generic_id)

    def _gen_tenant_backup_config(
        self,
        data_base_uri: str = None,
        archive_base_uri: str = None,
        log_archive_concurrency: int = -1,
        binding: str = None,
        ha_low_thread_score: int = -1,
        piece_switch_interval: str = None,  # Mandatory or Optional, default Optional
        archive_lag_target: str = None,
        delete_policy: str = None,
        delete_recovery_window: str = None,
    ):
        data = {}
        if data_base_uri is not None:
            data['data_base_uri'] = data_base_uri
        if archive_base_uri is not None:
            data['archive_base_uri'] = archive_base_uri
        if log_archive_concurrency != -1:
            data['log_archive_concurrency'] = log_archive_concurrency
        if binding is not None:
            data['binding'] = binding
        if ha_low_thread_score != -1:
            data['ha_low_thread_score'] = ha_low_thread_score
        if piece_switch_interval is not None:
            data['piece_switch_interval'] = piece_switch_interval
        if archive_lag_target is not None:
            data['archive_lag_target'] = archive_lag_target
        if delete_policy is not None or delete_recovery_window is not None:
            data['delete_policy'] = {
                'policy': delete_policy,
                'recovery_window': delete_recovery_window
            }
        return data

    def post_tenant_backup_config(
        self,
        tenant_name: str,
        data_base_uri: str,
        archive_base_uri: str = None,
        log_archive_concurrency: int = -1,
        binding: str = None,
        ha_low_thread_score: int = -1,
        piece_switch_interval: str = None,
        archive_lag_target: str = None,
        delete_policy: str = None,
        delete_recovery_window: str = None,
    ):
        """Configures the backup of the tenant.

        Configures the backup of the tenant with the specified configurations.

        Args:
            tenant_name (str): The identifier for the tenant.
            data_base_uri (str): The URI pointing to the location of data backups.
            archive_base_uri (str, optional): The URI for archive logs storage, if different from the main backup path.
            log_archive_concurrency (int, optional): Specifies the concurrency level for log archiving.
            binding (str, optional): Determines the binding mode between archiving and business operations ('Optional' or 'Mandatory').
            ha_low_thread_score (int, optional): Adjusts the thread priority score for high availability tasks.
            piece_switch_interval (str, optional): Defines the interval for switching backup pieces.
            archive_lag_target (str, optional): Sets the target lag time for log archiving processes.
            delete_policy (str, optional): Policy for deletion, limited to 'default'.
            delete_recovery_window (str, optional): Defines the recovery window for which data deletion policies apply.
        """
        data = self._gen_tenant_backup_config(
            data_base_uri, archive_base_uri, log_archive_concurrency, binding, ha_low_thread_score,
            piece_switch_interval, archive_lag_target, delete_policy, delete_recovery_window
        )
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}/backup/config", "POST", data)
        return self.__handle_task_ret_request(req)

    def post_tenant_backup_config_sync(
        self,
        tenant_name: str,
        data_base_uri: str,
        archive_base_uri: str = None,
        log_archive_concurrency: int = -1,
        binding: str = None,
        ha_low_thread_score: int = -1,
        piece_switch_interval: str = None,
        archive_lag_target: str = None,
        delete_policy: str = None,
        delete_recovery_window: str = None,
    ):
        """Configures the backup of the tenant.

        Configures the backup of the tenant with the specified configurations.

        Args:
            tenant_name (str): The name of the tenant.
            data_base_uri (str): The URI pointing to the location of data backups.
            archive_base_uri (str, optional): The URI for archive logs storage, if different from the main backup path.
            log_archive_concurrency (int, optional): Specifies the concurrency level for log archiving.
            binding (str, optional): Determines the binding mode between archiving and business operations ('Optional' or 'Mandatory').
            ha_low_thread_score (int, optional): Adjusts the thread priority score for high availability tasks.
            piece_switch_interval (str, optional): Defines the interval for switching backup pieces.
            archive_lag_target (str, optional): Sets the target lag time for log archiving processes.
            delete_policy (str, optional): Policy for deletion, limited to 'default'.
            delete_recovery_window (str, optional): Defines the recovery window for which data deletion policies apply.
        """
        dag = self.post_tenant_backup_config(
            tenant_name, data_base_uri, archive_base_uri, log_archive_concurrency, binding, ha_low_thread_score,
            piece_switch_interval, archive_lag_target, delete_policy, delete_recovery_window
        )
        return self.wait_dag_succeed(dag.generic_id)

    def patch_tenant_backup_config(
        self,
        tenant_name: str,
        data_base_uri: str = None,
        archive_base_uri: str = None,
        log_archive_concurrency: int = -1,
        binding: str = None,
        ha_low_thread_score: int = -1,
        piece_switch_interval: str = None,
        archive_lag_target: str = None,
        delete_policy: str = None,
        delete_recovery_window: str = None,
    ):
        """Updates the backup configuration of the tenant.

        Updates the backup configuration of the tenant with the specified configurations.

        Args:
            tenant_name (str): The name of the tenant.
            data_base_uri (str): The URI pointing to the location of data backups.
            archive_base_uri (str, optional): The URI for archive logs storage, if different from the main backup path.
            log_archive_concurrency (int, optional): Specifies the concurrency level for log archiving.
            binding (str, optional): Determines the binding mode between archiving and business operations ('Optional' or 'Mandatory').
            ha_low_thread_score (int, optional): Adjusts the thread priority score for high availability tasks.
            piece_switch_interval (str, optional): Defines the interval for switching backup pieces.
            archive_lag_target (str, optional): Sets the target lag time for log archiving processes.
            delete_policy (str, optional): Policy for deletion, limited to 'default'.
            delete_recovery_window (str, optional): Defines the recovery window for which data deletion policies apply.
        """
        data = self._gen_tenant_backup_config(
            data_base_uri, archive_base_uri, log_archive_concurrency, binding, ha_low_thread_score,
            piece_switch_interval, archive_lag_target, delete_policy, delete_recovery_window
        )
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}/backup/config", "PATCH", data)
        return self.__handle_task_ret_request(req)

    def patch_tenant_backup_config_sync(
        self,
        tenant_name: str,
        data_base_uri: str = None,
        archive_base_uri: str = None,
        log_archive_concurrency: int = -1,
        binding: str = None,
        ha_low_thread_score: int = -1,
        piece_switch_interval: str = None,
        archive_lag_target: str = None,
        delete_policy: str = None,
        delete_recovery_window: str = None,
    ):
        """Updates the backup configuration of the tenant.

        Updates the backup configuration of the tenant with the specified configurations.

        Args:
            tenant_name (str): The name of the tenant.
            data_base_uri (str): The URI pointing to the location of data backups.
            archive_base_uri (str, optional): The URI for archive logs storage, if different from the main backup path.
            log_archive_concurrency (int, optional): Specifies the concurrency level for log archiving.
            binding (str, optional): Determines the binding mode between archiving and business operations ('Optional' or 'Mandatory').
            ha_low_thread_score (int, optional): Adjusts the thread priority score for high availability tasks.
            piece_switch_interval (str, optional): Defines the interval for switching backup pieces.
            archive_lag_target (str, optional): Sets the target lag time for log archiving processes.
            delete_policy (str, optional): Policy for deletion, limited to 'default'.
            delete_recovery_window (str, optional): Defines the recovery window for which data deletion policies apply.
        """
        dag = self.patch_tenant_backup_config(
            tenant_name, data_base_uri, archive_base_uri, log_archive_concurrency, binding, ha_low_thread_score,
            piece_switch_interval, archive_lag_target, delete_policy, delete_recovery_window
        )
        return self.wait_dag_succeed(dag.generic_id)

    def start_cluster_backup(
        self,
        mode: str = None,
        plus_archive: bool = None,
        encryption: str = None,
    ):
        """Starts the backup of the obcluster.

        Starts the backup of the obcluster with the specified configurations.

        Args:
            mode (str, optional): Specifies the type of backup operation to perform. Supported values are 'full' and 'incremental'.
            plus_archive (bool, optional): Flag indicating whether to include archive logs within the backup process for a combined data and log backup.
            encryption (str, optional): The encryption passphrase used to secure the backup once completed.
        """
        data = {}
        if mode is not None:
            data['mode'] = mode
        else:
            data['mode'] = ""
        if plus_archive is not None:
            data['plus_archive'] = plus_archive
        if encryption is not None:
            data['encryption'] = encryption
        req = self.create_request("/api/v1/obcluster/backup", "POST", data)
        return self.__handle_task_ret_request(req)

    def start_cluster_backup_sync(
        self,
        mode: str = None,
        plus_archive: bool = None,
        encryption: str = None,
    ):
        """Starts the backup of the obcluster.

        Starts the backup of the obcluster with the specified configurations.

        Args:
            mode (str, optional): Specifies the type of backup operation to perform. Supported values are 'full' and 'incremental'.
            plus_archive (bool, optional): Flag indicating whether to include archive logs within the backup process for a combined data and log backup.
            encryption (str, optional): The encryption passphrase used to secure the backup once completed.
        """
        dag = self.start_cluster_backup(mode, plus_archive, encryption)
        return self.wait_dag_succeed(dag.generic_id)

    def start_tenant_backup(
        self,
        tenant_name: str,
        mode: str = None,
        plus_archive: bool = None,
        encryption: str = None,
    ):
        """Starts the backup of the tenant.

        Starts the backup of the tenant with the specified configurations.

        Args:
            tenant_name (str): The name of the tenant.
            mode (str, optional): The backup mode.  Supported values are 'full' and 'incremental'.
            plus_archive (bool, optional): Whether to add log archive together with data backup.
            encryption (str, optional): The encryption of the backup.
        """
        data = {}
        if mode is not None:
            data['mode'] = mode
        else:
            data['mode'] = ""
        if plus_archive is not None:
            data['plus_archive'] = plus_archive
        if encryption is not None:
            data['encryption'] = encryption
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}/backup", "POST", data)
        return self.__handle_task_ret_request(req)

    def start_tenant_backup_sync(
        self,
        tenant_name: str,
        mode: str = None,
        plus_archive: bool = None,
        encryption: str = None,
    ):
        """Starts the backup of the tenant.

        Starts the backup of the tenant with the specified configurations.

        Args:
            tenant_name (str): The name of the tenant.
            mode (str, optional): The backup mode.  Supported values are 'full' and 'incremental'.
            plus_archive (bool, optional): Whether to add log archive together with data backup.
            encryption (str, optional): The encryption of the backup.
        """
        dag = self.start_tenant_backup(
            tenant_name, mode, plus_archive, encryption)
        return self.wait_dag_succeed(dag.generic_id)

    def patch_cluster_backup_status(
        self,
        status: str = None,
    ):
        """Updates the backup status of the obcluster.

        Updates the backup status of the obcluster with the specified status.

        Args:
            status (str, optional): The backup status. Supported value is 'canceled'. Default is 'canceled'.
        """
        data = {}
        if status is not None:
            data['status'] = status
        else:
            data['status'] = ""
        req = self.create_request("/api/v1/obcluster/backup", "PATCH", data)
        return self._handle_ret_request(req)

    def patch_tenant_backup_status(
        self,
        tenant_name: str,
        status: str = None,
    ):
        """Updates the backup status of the tenant.

        Updates the backup status of the tenant with the specified status.

        Args:
            tenant_name (str): The name of the tenant.
            status (str, optional): The backup status. Supported value is 'canceled'. Default is 'canceled'.
        """
        data = {}
        if status is not None:
            data['status'] = status
        else:
            data['status'] = ""
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}/backup", "PATCH", data)
        return self._handle_ret_request(req)

    def patch_cluster_backup_log_status(
        self,
        status: str = None,
    ):
        """Updates the archive log statu of the obcluster.

        Updates the archive log of the obcluster with the specified status.

        Args:
            status (str, optional): The expected status of the archive log. Supported values are 'doing' and 'stop'. Default is 'stop'.
        """
        data = {}
        if status is not None:
            data['status'] = status
        else:
            data['status'] = ""
        req = self.create_request(
            "/api/v1/obcluster/backup/log", "PATCH", data)
        return self._handle_ret_request(req)

    def patch_tenant_backup_log_status(
        self,
        tenant_name: str,
        status: str = None,
    ):
        """Updates the archive log status of the tenant.

        Updates the archive log of the tenant with the specified status.

        Args:
            tenant_name (str): The name of the tenant.
            status (str, optional): The expected status of the archive log. Supported values are 'doing' and 'stop'. Default is 'stop'.
        """
        data = {}
        if status is not None:
            data['status'] = status
        else:
            data['status'] = ""
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}/backup/log", "PATCH", data)
        return self._handle_ret_request(req)

    def get_cluster_backup_overview(self) -> ob.CdbObBackupResponse:
        """Gets the overview of the obcluster backup jobs.

        Gets the overview of the obcluster backup jobs.

        Returns:
            BackupStatus: The backup status of all the tenants.
        """
        req = self.create_request("/api/v1/obcluster/backup/overview", "GET")
        return self._handle_ret_request(req, ob.CdbObBackupResponse)

    def get_tenant_backup_overview(self, tenant_name: str) -> ob.CdbObBackupResponse:
        """Gets the overview of the tenant backup jobs.

        Gets the overview of the tenant backup jobs.

        Args:
            tenant_name (str): The name of the tenant.

        Returns:
            BackupStatus: The backup status of the tenant.
        """
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}/backup/overview", "GET")
        return self._handle_ret_request(req, ob.CdbObBackupResponse)

    def post_tenant_restore(
        self,
        data_backup_uri: str,
        tenant_name: str,
        zone_list: List[tenant.ZoneParam],
        archive_log_uri: str = None,
        timestamp: str = None,
        scn: int = None,
        ha_high_thread_score: int = None,
        primary_zone: str = None,
        concurrency: int = None,
        decryption: list = None,
        kms_encrypt_info: str = None,
    ):
        """Restores the tenant.

        Restores the tenant with the specified configurations.

        Args:
            data_backup_uri (str): Complete destination path for data backups.
            tenant_name (str): Name of the tenant targeted for restoration.
            zone_list (List[ZoneParam]): The zone list of the tenant, include replica configs and unit configs.
            archive_log_uri (str, optional): Destination path for log archives.
            timestamp (str, optional): Specific timestamp for restoration.
            scn (str, optional): System Change Number (SCN) for restoration.
            ha_high_thread_score (int, optional): Adjusts high-priority HA threads count.
            primary_zone (str, optional): Designated primary zone for the tenant.
            concurrency (int, optional): Parallel processing level for data recovery.
            decryption (list, optional): Decryption key for all backups.
            kms_encrypt_info (str, optional): Key Management Service encryption details, if applicable.
        """
        data = {
            'data_backup_uri': data_backup_uri,
            'restore_tenant_name': tenant_name,
            "zone_list": [zone.__dict__ for zone in zone_list],
        }
        if archive_log_uri is not None:
            data['archive_log_uri'] = archive_log_uri
        if timestamp is not None:
            data['timestamp'] = timestamp
        if scn is not None:
            data['scn'] = scn
        if ha_high_thread_score is not None:
            data['ha_high_thread_score'] = ha_high_thread_score
        if primary_zone is not None:
            data['primary_zone'] = primary_zone
        if concurrency is not None:
            data['concurrency'] = concurrency
        if decryption is not None:
            data['decryption'] = decryption
        if kms_encrypt_info is not None:
            data['kms_encrypt_info'] = kms_encrypt_info
        req = self.create_request("/api/v1/tenant/restore", "POST", data)
        return self.__handle_task_ret_request(req)

    def post_tenant_restore_sync(
        self,
        data_backup_uri: str,
        tenant_name: str,
        zone_list: List[tenant.ZoneParam],
        archive_log_uri: str = None,
        timestamp: str = None,
        scn: int = None,
        ha_high_thread_score: int = None,
        primary_zone: str = None,
        concurrency: int = None,
        decryption: list = None,
        kms_encrypt_info: str = None,
    ):
        """Restores the tenant.

        Restores the tenant with the specified configurations.

        Args:
            data_backup_uri (str): Complete destination path for data backups.
            tenant_name (str): Name of the tenant targeted for restoration.
            zone_list (List[ZoneParam]): The zone list of the tenant, include replica configs and unit configs.
            archive_log_uri (str, optional): Destination path for log archives.
            timestamp (str, optional): Specific timestamp for restoration.
            scn (str, optional): System Change Number (SCN) for restoration.
            ha_high_thread_score (int, optional): Adjusts high-priority HA threads count.
            primary_zone (str, optional): Designated primary zone for the tenant.
            concurrency (int, optional): Parallel processing level for data recovery.
            decryption (list, optional): Decryption key for all backups.
            kms_encrypt_info (str, optional): Key Management Service encryption details, if applicable.
        """
        dag = self.post_tenant_restore(
            data_backup_uri, tenant_name, zone_list, archive_log_uri,
            timestamp, scn, ha_high_thread_score, primary_zone, concurrency,
            decryption, kms_encrypt_info
        )
        return self.wait_dag_succeed(dag.generic_id)

    def delete_tenant_restore(self, tenant_name: str) -> int:
        """Get the last restore dag ID of the tenant.

        Args:
            tenant_name (str): The name of the tenant.
        """
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}/restore", "DELETE")
        return self.__handle_task_ret_request(req)

    def delete_tenant_restore_sync(self, tenant_name: str) -> task.DagDetailDTO:
        """Get the last restore dag ID of the tenant.

        Args:
            tenant_name (str): The name of the tenant.
        """
        dag = self.delete_tenant_restore(tenant_name)
        if dag is None:
            return None
        return self.wait_dag_succeed(dag.generic_id)

    def get_tenant_restore_overview(self, tenant_name: str) -> ob.RestoreOverview:
        """Gets the overview of the tenant restore jobs.

        Args:
            tenant_name (str): The name of the tenant.

        Returns:
            RestoreOverview: The restore status of the tenant.
        """
        req = self.create_request(
            f"/api/v1/tenant/{tenant_name}/restore/overview", "GET")
        return self._handle_ret_request(req, ob.RestoreOverview)
