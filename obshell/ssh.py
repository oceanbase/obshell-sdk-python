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

import os
import socket
import getpass
import time
import tempfile
import warnings
import ipaddress
from threading import Thread
from typing import List, Dict
from multiprocessing import cpu_count, Process

warnings.filterwarnings("ignore")

from paramiko import SFTPClient
from paramiko.client import SSHClient, AutoAddPolicy
from subprocess import Popen, PIPE

from obshell import ClientSet, TaskExecuteFailedError
from obshell.log import logger
from obshell.pkg import load_rpm_pcakge, ExtractFile
from obshell.auth.password import PasswordAuth
from obshell.model.info import Agentidentity


class TempFileMananger:

    def __init__(self) -> None:
        self.files = {}

    def create(self, file_path, content):
        if file_path not in self.files:
            mode = 'wb' if isinstance(content, bytes) else 'w'
            logger.debug('input content type: %s, use mode: %s' % (type(content), mode))
            self.files[file_path] = tempfile.NamedTemporaryFile(mode=mode, prefix='obshell-sdk-temp-')
            self.files[file_path].write(content)
            self.files[file_path].flush()
            logger.debug('create temp file %s' % self.files[file_path].name)
        return self.files[file_path].name

    def close(self):
        for file in self.files.values():
            logger.debug('close temp file %s' % file.name)
            file.close()
        self.files = {}


class SshReturn(object):

    def __init__(self, code, stdout, stderr):
        self.code = code
        self.stdout = stdout
        self.stderr = stderr

    def __bool__(self):
        return self.code == 0
    
    def __nonzero__(self):
        return self.__bool__()


def local_execute(command: str, timeout=6000):
    logger.debug('execute local command: %s' % command)
    try:
        p = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
        output, error = p.communicate(timeout=timeout)
        code = p.returncode
        output = output.decode(errors='replace')
        error = error.decode(errors='replace')
    except Exception as e:
        output = ''
        error = str(e)
        code = 255
    return SshReturn(code, output, error)


def write_file(file_path, content, mode=0o644):
    logger.debug('write local file %s' % file_path)
    with open(file_path, 'wb' if isinstance(content, bytes) else 'w') as f:
        f.write(content)
    os.chmod(file_path, mode)
    return True


def is_local_ip(ip):
    if ip == "127.0.0.1" or ip == "::1":
        return True
    local_ips = [ipaddress.ip_address(addr) for addr in socket.gethostbyname_ex(socket.gethostname())[2]]
    return ipaddress.ip_address(ip) in local_ips


_FLAG_ROOT_PWD = "password"
USER = getpass.getuser()
MAX_PARALLER = cpu_count() * 4 if cpu_count() else 8
MAX_SIZE = 100
MIN_SIZE = 20
USE_RSYNC = bool(local_execute('rsync -h'))

# The size of each sftp chunked transfer, default is 64M.
# Since the maximum size of a single file in the current OB, observer, is around 450M, with 64M, it can be divided into 7-8 chunks.
# This would require 7-8 concurrent connections, and since the default MaxSessions in the sshd configuration is 10, this value is appropriate.
# If you want to improve the performance of sftp chunked transfer, you can reduce this value to increase the number of concurrent connections.
# However, you will need to correspondingly increase the MaxSessions configuration on the target machine.
CHUNK_SIZE = 1024*1024*64
# The maximum number of parallel SFTP transfers to avoid exceeding the MaxSessions limit
PARALLEL_SFTP_MAX = 8


class NodeConfig:
    
    def __init__(self, ip, work_dir, username=USER, obshell_port=2886, ssh_port=22, password=None, key_filename=None, timeout=None, **kwargs):
        if not work_dir or work_dir == '/':
            raise Exception('work_dir is invalid')
        if not work_dir.startswith('/'):
            raise Exception('work_dir must be absolute path')
        self.ip = ip
        self.obshell_port = obshell_port
        self.username = username
        self.work_dir = work_dir
        self.ssh_port = ssh_port
        self.password = password
        self.key_filename = key_filename
        self.timeout = timeout
        self.kwargs = kwargs


class SshClient:

    _rsync_cache = {}

    def __init__(self, config: NodeConfig, temp_file_manager: TempFileMananger = None):
        self.config = config
        self.ssh_client = SSHClient()
        self.sftp_client = None
        self.is_connected = False
        self.temp_file_manager = temp_file_manager
        self._remote_transporter = None
        self.is_local = is_local_ip(config.ip) and (config.username == USER or config.username == 'root')

    @property
    def remote_transporter(self):
        if self._remote_transporter is not None:
            return self._remote_transporter
        if USE_RSYNC is False or self.config.password:
            self._remote_transporter = self._sftp_write_file
        else:
            if self.config.ip not in self._rsync_cache:
                self._rsync_cache[self.config.ip] = bool(self.execute('rsync -h'))
            if self._rsync_cache[self.config.ip]:
                self._remote_transporter = self._rsync_write_file
            else:
                self._remote_transporter = self._sftp_write_file

        return self._remote_transporter

    def connect(self):
        if self.is_connected:
            return
        self.ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        self.ssh_client.set_log_channel(None)
        self.ssh_client.connect(
            self.config.ip,
            port=self.config.ssh_port,
            username=self.config.username,
            password=self.config.password,
            key_filename=self.config.key_filename,
            timeout=self.config.timeout,
            **self.config.kwargs
        )
        SFTPClient.from_transport(self.ssh_client.get_transport())
        self.sftp_client = self.ssh_client.open_sftp()
        self.is_connected = True

    def close(self):
        if self.is_connected:
            self.sftp_client.close()
            self.ssh_client.close()
            self.is_connected = False

    def execute(self, command: str):
        if self.is_local:
            return local_execute(command)
        logger.debug('execute command: %s' % command)
        command = '(%s);echo -e "\n$?\c"' % (command.strip(';').lstrip('\n'))
        try:
            _, stdout, stderr = self.ssh_client.exec_command(command)
            output = stdout.read().decode(errors='replace')
            error = stderr.read().decode(errors='replace')
            if output:
                idx = output.rindex('\n')
                code = int(output[idx:])
                stdout = output[:idx]
            else:
                code, stdout = 1, ''
        except Exception as e:
            code = 255
            stdout = ''
            error = str(e)
        return SshReturn(code, stdout, error)

    def write_file(self, context, remote_file_path, mode=0o644):
        dir_path = os.path.dirname(remote_file_path)
        logger.debug('create dir %s' % dir_path)
        ret = self.execute('mkdir -p %s' % dir_path)
        if self.is_local:
            return write_file(remote_file_path, context, mode)
        if not ret:
            raise Exception('Failed to create directory %s: %s' % (dir_path, ret.stderr))
        return self.remote_transporter(context, remote_file_path, mode)
    
    def _rsync_write_file(self, context, remote_file_path, mode=0o644):
        temp_file_manager = TempFileMananger()
        try:
            if self.temp_file_manager:
                local_file = self.temp_file_manager.create(remote_file_path, context)
            else:
                local_file = temp_file_manager.create(remote_file_path, context)
            if self._sync(local_file, remote_file_path):
                ret = self.execute('chmod %o %s' % (mode, remote_file_path))
                if not ret:
                    raise Exception('Failed to chmod %o %s: %s' % (mode, remote_file_path, ret.stderr))
                return True
        finally:
            temp_file_manager.close()
    
    def _sync(self, source, target):
        identity_option = "-o StrictHostKeyChecking=no "
        if self.config.key_filename:
            identity_option += '-i {key_filename} '.format(key_filename=self.config.key_filename)
        if self.config.ssh_port:
            identity_option += '-p {}'.format(self.config.ssh_port)

        target = "{user}@{host}:{remote_path}".format(user=self.config.username, host=self.config.ip, remote_path=target)
        cmd = 'yes | rsync -a -W -L -e "ssh {identity_option}" {source} {target}'.format(
            identity_option=identity_option,
            source=source,
            target=target
        )
        return local_execute(cmd)
    
    def _sftp_write_file(self, context, remote_file_path, mode=0o644):
        context_size = len(context)
        if context_size < CHUNK_SIZE:
            with self.sftp_client.open(remote_file_path, 'w') as remote_file:
                remote_file.write(context)
                remote_file.flush()
        else:
            chunks = []
            try:
                threads : List[Thread] = []
                for idx in range(0, len(context), CHUNK_SIZE):
                    if idx/CHUNK_SIZE/PARALLEL_SFTP_MAX > 0 and idx/CHUNK_SIZE%PARALLEL_SFTP_MAX == 0:
                        # Wait for the completion of the previous batch of sftp operations
                        for thread in threads:
                            thread.join()
                    chunk = (self.config, remote_file_path, idx, context[idx:idx+CHUNK_SIZE])
                    thread = Thread(target=write_chunk, args=chunk)
                    thread.start()
                    threads.append(thread)
                    chunks.append(chunk)
                for thread in threads:
                    thread.join()
            except Exception as e:
                self.execute('rm -f %s.*' % remote_file_path)
                raise e
            
            for chunk in chunks:
                ret = self.execute('cat %s.%s >> %s; rm -f %s.%s' % (remote_file_path, chunk[2], remote_file_path, remote_file_path, chunk[2]))
                if not ret:
                    raise Exception('Failed to merge chunks to %s: %s' % (remote_file_path, ret.stderr))
        
        ret = self.execute('chmod %o %s' % (mode, remote_file_path))
        if not ret:
            raise Exception('Failed to chmod %o %s: %s' % (mode, remote_file_path, ret.stderr))
        return True


def write_chunk(config, remote_file_path, idx, chunk):
    client = SshClient(config)
    client.connect()
    remote_file_path = f"{remote_file_path}.{idx}"
    logger.debug(f"write chunk {idx} to {remote_file_path}")
    with client.sftp_client.open(remote_file_path, 'w') as remote_file:
        remote_file.write(chunk)
        remote_file.flush()
    return True


def check_remote_dir_empty(client: SshClient, work_dir: str):
    logger.debug(f"Check remote directory: {work_dir}")
    return client.execute(f'![ -e {work_dir} ] || [ "$(ls -A {work_dir} 2>/dev/null | wc -l)" -eq 0 ]')


def check_observer_version(client: SshClient, work_dir: str):
    logger.debug(f"Check observer version in remote directory: {work_dir}")
    return client.execute(f"export LD_LIBRARY_PATH='{work_dir}/lib'; {work_dir}/bin/observer -V")


def initialize_nodes(rpm_packages: List[str], force_clean: bool, configs: List[NodeConfig]):
    """ Initialize nodes by uploading RPM packages and optionally cleaning directories.
    
        Parameters:
            - rpm_packages (List[str]): Paths of RPM packages to send to nodes.
            - force_clean (bool): If True, clean target directories on nodes before proceeding.
            - configs (List[NodeConfig]): Configuration details for each node.
            
        Process:
            1.  Connect to each node via SSH.
            2.  Clean directories if 'force_clean' is True.
            3.  If 'force_clean' is False, ensure directories are empty; raise error if not.
            4.  Upload and unpack RPM packages to nodes,  setting up required files and links.
            5.  Close all SSH connections after operations.
            
        Raises:
            - Exception: If directory checks fail or other operations encounter an error.
    """
    ssh_clients = {config.ip: SshClient(config) for config in configs}
    try:
        for ssh_client in ssh_clients.values():
            ssh_client.connect()

        if force_clean:
            for ssh_client in ssh_clients.values():
                _clean_node(ssh_client, ssh_client.config.work_dir)
        else :
            for ssh_client in ssh_clients.values():
                if not check_remote_dir_empty(ssh_client, ssh_client.config.work_dir):
                    raise Exception(f"{ssh_client.config.ip}:{ssh_client.config.work_dir} is not empty, please clean it first")

        for rpm_package in rpm_packages:
            install_package(rpm_package, ssh_clients, configs)
                    
        for ssh_client in ssh_clients.values():
            ret = check_observer_version(ssh_client, ssh_client.config.work_dir)
            if not ret:
                raise Exception(f'Check {ssh_client.config.ip}:{ssh_client.config.work_dir} observer version failed, maybe be oceanbase-ce-libs not installed. Reason: {ret.stderr}')
    except Exception as e:
        raise e
    finally:
        for ssh_client in ssh_clients.values():
            ssh_client.close()
    return True


def install_obshell(rpm_package: str, configs: List[NodeConfig]):
    """
        Installs and configures the OBShell RPM package on the specified list of node configurations.   
        
        Parameters:
            rpm_package (str): The name of the RPM package to be installed.
            configs (List[NodeConfig]): A list of node configurations, each containing the node's IP and other relevant information.
            
        Returns:
            bool: Returns True if the installation is successful, otherwise returns False.
            
        Process:
            1. Creates a dictionary of SSH clients based on the provided list of node configurations.
            2. Attempts to install the RPM package on each node.
            3. Ensures all SSH clients are closed if an exception occurs during the installation process.
    """
    ssh_clients = {config.ip: SshClient(config) for config in configs}
    try:
        return install_package(rpm_package, ssh_clients, configs)
    finally:
        for ssh_client in ssh_clients.values():
            ssh_client.close()


def install_package(rpm_package: str, ssh_clients: Dict[str, SshClient], configs: List[NodeConfig]):
    logger.debug('load rpm package %s' % rpm_package)
    files, links = load_rpm_pcakge(rpm_package)
    
    write_files_to_servers(ssh_clients, configs, files)

    for link_path, target in links.items():
        for config in configs:
            ssh_client = ssh_clients[config.ip]
            dest_path = get_dest_path(config.work_dir, link_path)
            
            if target.startswith('./'):     
                target_path = get_dest_path(config.work_dir, target)
            else:
                target_path = target
                
            dir_path = os.path.dirname(dest_path)
            cmd = 'mkdir -p %s; cd %s; ln -sf %s %s' % (dir_path, dir_path, target_path, dest_path)
            logger.debug('create link %s -> %s' % (dest_path, target_path))      
            ret = ssh_client.execute(cmd)
            if not ret:
                raise Exception('Failed to create link %s -> %s: %s' % (dest_path, target_path, ret.stderr))
    return True


class WriteFilesWorker(object):

    def __init__(self, id, config: NodeConfig, temp_file_manager: TempFileMananger = None):
        self.id = id
        self.config = config
        self.temp_file_manager = temp_file_manager
        self.files: List[ExtractFile] = []
        self.size = 0

    def add_file(self, file: ExtractFile):
        self.files.append(file)
        self.size += file.size

    def __call__(self):
        client = SshClient(self.config, self.temp_file_manager)
        client.connect()
        import time
        start = time.time()
        for file in self.files:
            remote_file_path = get_dest_path(client.config.work_dir, file.path)
            logger.debug('worker %s: write file %s' % (self.id, remote_file_path))
            if not client.write_file(file.context, remote_file_path, file.mode):
                return False
        logger.debug('worker %s cost %s' % (self.id, time.time()-start))
        return True


def write_files_to_servers(ssh_clients: Dict[str, SshClient] , configs: List[NodeConfig], files: List[ExtractFile]):
    """ Write files to the target servers.
        
        This function transfers files to each primary node using SSH. 
        If there are multiple nodes on the same machine, it only writes the files once via SSH.
        Then, it copies the files to other nodes on the same machine using the `cp` command.
        
        Parameters:
            - ssh_clients (Dict[str, SshClient]): A dictionary mapping IP addresses to their corresponding SshClient instances.  
            - configs (List[NodeConfig]): A list of NodeConfig objects containing configuration details for each node. 
            - files (List[ExtractFile]): A list of ExtractFile objects representing the files to be written to the servers.     
                
        Returns:
            - True if all files are successfully written and copied.
            
        Raises:
            - Exception: If file copying between nodes fails.    
    """
    # wirtes files to primary node
    processes : List[Process] = []
    for clients in ssh_clients.values():
        proc = Process(target=paraller_write_files, args=(clients.config, files))
        proc.start()
        processes.append(proc)
    for proc in processes:
        proc.join()

    # Copy installed files from one node to other nodes on the same machine to improve installation efficiency.
    for config in configs:
        client = ssh_clients[config.ip]
        primary_config = client.config
        if primary_config.work_dir == config.work_dir:
            continue
            
        for file in files:
            remote_file_path = get_dest_path(primary_config.work_dir, file.path)
            dest_path = get_dest_path(config.work_dir, file.path)
            ret = client.execute('mkdir -p %s; cp %s %s' % (os.path.dirname(dest_path), remote_file_path, dest_path))
            if not ret:
                raise Exception('Failed to copy files from %s to %s: %s' % (primary_config.ip, config.ip, ret.stderr))
    return True


def paraller_write_files(config: NodeConfig, files: List[ExtractFile]):
    """ Write files in parallel to a server.
        This function distributes files to be written in parallel using multiple workers. 
        The degree of parallelism is determined by MAX_PARALLER, and each worker handles 
        at least MIN_SIZE files. The function tries to ensure that each worker handles a 
        similar total file size to balance the load.
        
        Parameters:
            - config (NodeConfig): Configuration details for connecting to the server.
            - files (List[ExtractFile]): List of files to be written to the server.
        
        Process:
            1. Calculate the number of workers based on the number of files and the constraints.
            2. Distribute files among the workers to balance the workload by size.
            3. Use a pool of processes to execute the file writing operations in parallel.
            4. Log each worker's ID and the total size of files it handles.
            5. Raise an exception if any worker fails to write its files. 
        
        Returns:
            - True if all files are successfully written in parallel.
        
        Raises:
            - Exception: If writing files fails for any worker.
  """
    file_num = len(files)
    paraller = int(min(MAX_PARALLER, file_num))
    size = min(MAX_SIZE, int(file_num / paraller))
    size = int(max(MIN_SIZE, size))

    workers = []
    for i in range(file_num//size+1):
        workers.append(WriteFilesWorker(i, config))
    for file in files:
        worker: WriteFilesWorker = workers[0]
        worker.add_file(file)
        workers = sorted(workers, key=lambda w: w.size)

    threads : List[Thread] = []
    for worker in workers:
        logger.debug('worker %s size %s' % (worker.id, worker.size))
        thread = Thread(target=worker)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

    return True


def _clean_node(client: SshClient, work_dir: str):
    for file in ["daemon", "obshell", "observer"]:
        _stop_process(client, work_dir, file)

    ret = client.execute('rm -fr %s' % work_dir)
    if not ret:
        raise Exception('Failed to clean %s work dir %s: %s' % (client.config.ip, work_dir, ret.stderr))
    return True


def _stop_obshell(client: SshClient, work_dir: str):
    for proc in ["daemon", "obshell"]:
        _stop_process(client, work_dir, proc)


def _stop_process(client: SshClient, work_dir: str, process_name: str):
    pid_file = os.path.join(work_dir, 'run', f'{process_name}.pid')
    if not client.execute('[ -f %s ]' % pid_file):
        return
    ret = client.execute('kill -9 `cat %s`' % pid_file)
    if not ret:
        logger.debug('Failed to kill %s(%s): %s' % (client.config.ip, pid_file, ret.stderr))


def get_dest_path(work_dir: str, file_path: str) -> str:
    if file_path.startswith('./home/admin/oceanbase'):
        file_path = file_path[23:]
    elif file_path.startswith('./usr'):
        file_path = file_path[6:]
    return os.path.join(work_dir, file_path)


def start_obshell(configs: List[NodeConfig]):
    """ Start the obshell servers on the specified nodes.
    
        Parameters:
            - configs (List[NodeConfig]): A list of NodeConfig objects, each containing configuration for connecting to a node.
        
        Process:
            1.  Establishes SSH connections to each node using the provided configurations.
            2.  Starts the obshell server on each node by executing the appropriate command.
            3.  Ensures proper resource cleanup by closing all SSH connections after processing.
            
        Raises:  
            - Exception: If any operation fails, such as failing to start the obshell server on a node.
    """
    logger.debug('start obshell servers...')
    ssh_clients = {config.ip: SshClient(config) for config in configs}
    try:
        for ssh_client in ssh_clients.values():
            ssh_client.connect()

        for config in configs:
            ssh_client = ssh_clients[config.ip]
            ret = ssh_client.execute('%s/bin/obshell admin start --ip %s --port %s' % (config.work_dir, config.ip, config.obshell_port))
            if not ret:
                raise Exception('Failed to start %s obshell: %s' % (config.ip, ret.stderr))
    finally:
        for ssh_client in ssh_clients.values():
            ssh_client.close()
    logger.debug('start obshell servers success')
    return True


def _start_obshell(client: SshClient, work_dir: str, ip: str, obshell_port: int, password: str = None):
    logger.debug('start obshell %s:%s' % (ip, obshell_port))
    cmd = '%s/bin/obshell admin start --ip %s --port %s' % (work_dir, ip, obshell_port)
    if password is not None:
        password = "'{}'".format(password.replace("'", "'\"'\"'"))
        if client.execute("%s/bin/obshell admin start -h | grep %s" % (work_dir, _FLAG_ROOT_PWD)):
            cmd = "%s --%s=%s" % (cmd, _FLAG_ROOT_PWD, password)
        else:
            cmd = "export OB_ROOT_PASSWORD=%s; %s" % (password, cmd)
    return client.execute(cmd)


def takeover(password, configs: List[NodeConfig]):
    """  
        Takes over the observer nodes using the provided password and node configurations.
        
        Parameters:
            password (str): The password to authenticate with the observer nodes.
            configs (List[NodeConfig]): A list of node configurations, each containing the node's IP, work directory, OBShell port, and other relevant information.
            
        Returns:
            bool: Returns True if the takeover is successful, otherwise raises an exception.
        
        Process:
            1. Attempts to connect to each SSH client.
            2. Iterates over the node configurations and starts the OBShell on each node using the provided password and configuration details.
            3. If starting the OBShell fails on any node, raises an exception with the node's IP and the error message.
            4. Ensures all SSH clients are closed after the takeover process, regardless of whether it was successful or not.
    """
    logger.debug('takeover observer...')
    ssh_clients = {config.ip: SshClient(config) for config in configs}
    try:
        for ssh_client in ssh_clients.values():
            ssh_client.connect()

        # stop obshell
        for config in configs:
            _stop_obshell(ssh_clients[config.ip], config.work_dir)

        for config in configs:
            ret = _start_obshell(ssh_clients[config.ip], config.work_dir, config.ip, config.obshell_port, password)
            if not ret:
                raise Exception('Failed to takeover %s observer: %s' % (config.ip, ret.stderr))
        
        times = 60
        while times:
            try:
                time.sleep(10)
                times -= 1
                count = 0
                for config in configs:
                    client = ClientSet(config.ip, config.obshell_port, auth=PasswordAuth(password))
                    info = client.v1.get_status() 
                    if info.agent.identity == Agentidentity.TAKE_OVER_MASTER.value:
                        dag = client.v1.get_agent_last_maintenance_dag()
                        logger.debug('find takeover observer dag %s, wait...' % dag.generic_id)
                        client.v1.wait_dag_succeed(dag.generic_id)
                        count = len(configs)
                        break
                    elif info.agent.identity == Agentidentity.CLUSTER_AGENT.value:
                        count += 1
                if count == len(configs):
                    logger.debug('takeover observer success')
                    return True
            except TaskExecuteFailedError as e:
                logger.debug('takeover observer failed: %s, retry...' % e)
                raise e
            except Exception as e:
                if times:
                    logger.debug('takeover observer failed: %s, retry...' % e)
                    continue
                else:
                    raise e
    finally:
        for ssh_client in ssh_clients.values():
            ssh_client.close()
