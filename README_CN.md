<p align="center">
    <a href="https://github.com/oceanbase/oceanbase/blob/master/LICENSE">
        <img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-blue" />
    </a>
    <a href="https://en.oceanbase.com/docs/oceanbase-database">
        <img alt="English doc" src="https://img.shields.io/badge/docs-English-blue" />
    </a>
    <a href="https://www.oceanbase.com/docs/oceanbase-database-cn">
        <img alt="Chinese doc" src="https://img.shields.io/badge/文档-简体中文-blue" />
    </a>
</p>

[英文版](README.md) | 中文版

**OBShell-SDK-Python** 是 [OceanBase 社区](https://open.oceanbase.com/) 为了方便开发者快速使用 OBShell 服务而提供的 SDK，开发者可以使用该 SDK 便捷地调用 OBShell 的接口。

## 安装
```
pip install git://github.com/oceanbase/obshell-sdk-python.git
```

## 快速使用
使用时请确保 OBShell 处于运行状态
### 创建客户端
创建指定版本的 client
```python
import obshell.service.v1.client as ClientV1
from obshell.sdk.auth.password import PasswordAuth

def main():
    client = ClientV1("11.11.11.1", 2886, PasswordAuth("****"))
```
创建 client_set
```python
from obshell.service.client_set import ClientSet
from obshell.sdk.auth.password import PasswordAuth

def main():
    client = ClientSet("11.11.11.1", 2886, PasswordAuth("****"))
```
### 部署 OBShell 集群
OBShell-SDK-Python 提供了两类方法来创建一个 OBShell 集群，一是向 OBShell 请求对应的 API 成功后，立刻返回，二是在向 OBShell 请求 API 成功后，等待 OBShell 任务执行完成后再返回。前者任务异步执行，后者任务同步执行。

**部署一个 1-1-1 集群：**
* 任务异步执行
```python
from obshell.service.client_set import ClientSet
from obshell.sdk.auth.password import PasswordAuth
def main():
    client = ClientSet("11.11.11.1", 2886, PasswordAuth("****"))

    # join master
    dag = client.v1.join("11.11.11.1", 2886, "zone1")
    client.v1.wait_dag_succeed(dag.generic_id)
    # join follower
    dag = client.v1.join("11.11.11.2", 2886, "zone2")
    client.v1.wait_dag_succeed(dag.generic_id)
    dag = client.v1.join("11.11.11.3", 2886, "zone3")
    client.v1.wait_dag_succeed(dag.generic_id)

    # configure observer
    configs = {
        "datafile_size": "24G", "log_disk_size": "24G", 
        "cpu_count": "16", "memory_limit": "16G", "system_memory": "8G", 
        "enable_syslog_recycle": "true", "enable_syslog_wf": "true"}
    dag = client.v1.config_observer(configs, "GLOBAL", [])
    client.v1.wait_dag_succeed(dag.generic_id)

    # configure obcluster
    dag = client.v1.config_obcluster_sync("test-sdk", 11, "****")
    client.v1.wait_dag_succeed(dag.generic_id)

    # initialize obcluster
    dag = client.v1.init_sync()
    client.v1.wait_dag_succeed(dag.generic_id)
    
    # get the status of the cluster
    status = client.v1.get_status()
    print(status)
```
* 任务同步执行
```python
from obshell.service.client_set import ClientSet
from obshell.sdk.auth.password import PasswordAuth

def main():
    client = ClientSet("11.11.11.1", 2886, PasswordAuth("****"))

    # join master
    client.v1.join_sync("11.11.11.1", 2886, "zone1")
    # join follower
    client.v1.join_sync("11.11.11.2", 2886, "zone2")
    client.v1.join_sync("11.11.11.3", 2886, "zone3")

    # configure observer
    configs = {
        "datafile_size": "24G", "log_disk_size": "24G", 
        "cpu_count": "16", "memory_limit": "16G", "system_memory": "8G", 
        "enable_syslog_recycle": "true", "enable_syslog_wf": "true"}
    client.v1.config_observer_sync(configs, "GLOBAL", [])

    # configure obcluster
    client.v1.config_obcluster_sync("test-sdk", 11, "****")

    # initialize obcluster
    client.v1.init_sync()
    
    # get the status of the cluster
    status = client.v1.get_status()
    print(status)
```
### 发起扩容
将节点 '11.11.11.4' 扩容到节点 '11.11.11.1' 所在的集群中
```python
from obshell.service.client_set import ClientSet
from obshell.sdk.auth.password import PasswordAuth

def main():
    client = ClientSet("111.11.11.1", 2886, PasswordAuth("****"))

    # scale out
    configs = {
        "datafile_size": "24G", "log_disk_size": "24G", 
        "cpu_count": "16", "memory_limit": "16G", "system_memory": "8G", 
        "enable_syslog_recycle": "true", "enable_syslog_wf": "true"}
    client.v1.scale_out_sync("11.11.11.4", 2886, "zone3", configs)
```
