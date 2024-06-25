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

English | [Chinese](README_CN.md)

**OBShell-SDK-Python**  is an SDK provided by the[OceanBase Community](https://open.oceanbase.com/) to facilitate developers with quick access to OBShell services, allowing them to conveniently call OBShell interfaces using this SDK.

## Install
```
pip install obshell
```

## Quick Start
Please ensure that OBShell is running when using it.
### Create a Client
Create a specified version client.
```python
from obshell import ClientV1
from obshell.auth import PasswordAuth

def main():
    client = ClientV1("11.11.11.1", 2886, PasswordAuth("****"))
```
Create client_set.
```python
from obshell import ClientSet
from obshell.auth import PasswordAuth

def main():
    client = ClientSet("11.11.11.1", 2886, PasswordAuth("****"))
```
### Deploy Cluster
OBShell-SDK-Python provides two types of methods to deploy an OBShell cluster: the first immediately returns after successfully making a request to the OBShell API, and the second waits for the OBShell task to complete after the API request is successful before returning. The former executes the task asynchronously, while the latter executes the task synchronously.

**Deploy a 1-1-1 cluster:**
* Asynchronous Task Execution
```python
from obshell import ClientSet
from obshell.auth import PasswordAuth
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
* Synchronous Task Execution
```python
from obshell import ClientSet
from obshell.auth import PasswordAuth

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
### Scale out
Scale out the agent '11.11.11.4' into the cluster where the agent '11.11.11.1' is located.
```python
from obshell import ClientSet
from obshell.auth import PasswordAuth

def main():
    client = ClientSet("111.11.11.1", 2886, PasswordAuth("****"))

    # scale out
    configs = {
        "datafile_size": "24G", "log_disk_size": "24G", 
        "cpu_count": "16", "memory_limit": "16G", "system_memory": "8G", 
        "enable_syslog_recycle": "true", "enable_syslog_wf": "true"}
    client.v1.scale_out_sync("11.11.11.4", 2886, "zone3", configs)
```
