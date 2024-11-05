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
import tempfile
import warnings
import ipaddress
from typing import List, Dict
from multiprocessing import cpu_count
from multiprocessing.pool import Pool

warnings.filterwarnings("ignore")

from paramiko import SFTPClient
from paramiko.client import SSHClient, AutoAddPolicy
from subprocess import Popen, PIPE

from obshell.log import logger
from obshell.pkg import load_rpm_pcakge, ExtractFile


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


USER = getpass.getuser()
MAX_PARALLER = cpu_count() * 4 if cpu_count() else 8
MAX_SIZE = 100
MIN_SIZE = 20
USE_RSYNC = bool(local_execute('rsync -h'))


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
        with self.sftp_client.open(remote_file_path, 'w') as remote_file:
            remote_file.write(context)
        
        ret = self.execute('chmod %o %s' % (mode, remote_file_path))
        if not ret:
            raise Exception('Failed to chmod %o %s: %s' % (mode, remote_file_path, ret.stderr))
        return True


def check_remote_dir_empty(client: SshClient, work_dir: str):
    logger.debug(f"Check remote directory: {work_dir}")
    ret = client.execute(f'if [ -d {work_dir} ]; then ls -A {work_dir}; fi')
    return ret and len(ret.stdout) == 0


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
                clean_server(ssh_client, ssh_client.config.work_dir)
        else :
            for ssh_client in ssh_clients.values():
                if not check_remote_dir_empty(ssh_client, ssh_client.config.work_dir):
                    raise Exception(f"{ssh_client.config.ip}:{ssh_client.config.work_dir} is not empty, please clean it first")

        for rpm_package in rpm_packages:
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
                    cmd = 'cd %s; ln -sf %s %s' % (dir_path, target_path, dest_path)
                    logger.debug('create link %s -> %s' % (dest_path, target_path))      
                    ret = ssh_client.execute(cmd)

                    if not ret:
                        raise Exception('Failed to create link %s -> %s: %s' % (dest_path, target_path, ret.stderr))
    except Exception as e:
        raise e
    finally:
        for ssh_client in ssh_clients.values():
            ssh_client.close()
    return True


class WriteFilesWorker(object):

    def __init__(self, id, config: NodeConfig, temp_file_manager: TempFileMananger = None):
        self.id = id
        self.config = config
        self.temp_file_manager = temp_file_manager
        self.files = []
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
    

def write_files(worker: WriteFilesWorker):
    return worker()


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
    for clients in ssh_clients.values():
        paraller_write_files(clients.config, files)

    # for followers, copy files from primary node
    for config in configs:
        client = ssh_clients[config.ip]
        primary_config = client.config
        if primary_config.work_dir == config.work_dir:
            continue
        ret = client.execute("cp -r %s/* %s" % (primary_config.work_dir, config.work_dir))
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

    for worker in workers:
        logger.debug('worker %s size %s' % (worker.id, worker.size))

    pool = Pool(processes=paraller)
    results = pool.map(write_files, workers)
    for r in results:
        if not r:
            raise Exception('Failed to write files to %s' % config.ip)
    return True


def clean_server(client: SshClient, work_dir: str):
    for file in ["daemon.pid", "obshell.pid", "observer.pid"]:
        pid_file = os.path.join(work_dir, 'run', file)
        if not client.execute('[ -f %s ]' % pid_file):
            continue
        ret = client.execute('kill -9 `cat %s`' % pid_file)
        if not ret:
            logger.debug('Failed to kill %s(%s): %s' % (client.config.ip, pid_file, ret.stderr))

    ret = client.execute('rm -fr %s' % work_dir)
    if not ret:
        raise Exception('Failed to clean %s work dir %s: %s' % (client.config.ip, work_dir, ret.stderr))
    return True


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
