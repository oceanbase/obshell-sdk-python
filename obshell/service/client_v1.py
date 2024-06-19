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

from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.PublicKey import RSA

from obshell.info import get_info, get_public_key
from obshell.client import Client
from obshell.auth.base import OBShellVersion, AuthType
from obshell.auth.password import PasswordAuth
from obshell.request import BaseRequest
from obshell.model.ob import UpgradePkgInfo
import obshell.model.task as task
import obshell.model.info as info


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
        if (OBShellVersion.V422 in agent.version or
                OBShellVersion.V423 in agent.version):
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
        else:
            raise OBShellHandleError(resp.json()['error'])

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

    def create_request(self, uri: str, method: str, data=None, need_auth=True):
        return BaseRequest(uri, method,
                           self.host, self.port,
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

    def init(self) -> task.DagDetailDTO:
        """Initializes the cluster.

        Return as soon as request successfully.
        You can use wait_dag_succeed to wait for the init task to succeed or
        use init_sync to initialize synchronously instead.

        Returns:
            Task detail as task.DagDetailDTO.

        Raises:
            OBShellHandleError: error message return by OBShell server.
        """
        req = self.create_request("/api/v1/ob/init", "POST")
        return self.__handle_task_ret_request(req)

    def init_sync(self) -> task.DagDetailDTO:
        """Initializes the cluster synchronously.

        Seealso init.
        Waits for the init task to succeed.

        Raises:
            OBShellHandleError: error message return by OBShell server.
            TaskExecuteFailedError: raise when the task failed,
                include the failed task detail and logs.
        """
        dag = self.init()
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
                       port: str,
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
                                  data={"showDetail": show_detail})
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
        if operator == task.Operator.ROLLBACK_STR.value:
            if dag.is_succeed() and dag.is_rollback():
                return True
        elif operator == task.Operator.CANCEL_STR.value:
            if dag.is_failed() and dag.is_cancel():
                return True
        elif operator == task.Operator.RETRY_STR.value:
            if dag.is_succeed() and dag.is_run():
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
                                  data={"showDetail": show_detail})
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
                                  data={"showDetail": show_detail})
        return self._handle_ret_request(req, task.DagDetailDTO)

    def get_agent_unfinished_dag(self, show_detail=True):
        req = self.create_request("/api/v1/task/dag/agent/unfinish", "GET",
                                  data={"showDetail": show_detail})
        return self._handle_ret_from_content_request(req, task.DagDetailDTO)

    def get_all_agent_last_maintenance_dag(self, show_detail=True):
        req = self.create_request("/api/v1/task/dag/maintain/agents", "GET",
                                  data={"showDetail": show_detail})
        return self._handle_ret_from_content_request(req, task.DagDetailDTO)

    def get_cluster_unfinished_dag(self, show_detail=True):
        req = self.create_request("/api/v1/task/dag/ob/unfinish", "GET",
                                  data={"showDetail": show_detail})
        return self._handle_ret_from_content_request(req, task.DagDetailDTO)

    def get_ob_last_maintenance_dag(self, show_detail=True) -> task.DagDetailDTO:
        req = self.create_request("/api/v1/task/dag/maintain/ob", "GET",
                                  data={"showDetail": show_detail})
        return self._handle_ret_from_content_request(req, task.DagDetailDTO)

    def get_unfinished_dags(self, show_detail=True):
        req = self.create_request("/api/v1/task/dag/unfinish", "GET",
                                  data={"showDetail": show_detail})
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
                "copied_configs should include the server of the client.")
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
