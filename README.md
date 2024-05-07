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
pip install git://github.com/oceanbase/obshell-sdk-python.git
```

## Quick Start
Please ensure that OBShell is running when using it.
### Create a Client
Create a specified version client.
```python
import obshell_sdk_python.service.v1.client as cli
from obshell_sdk_python.sdk.auth.password import PasswordAuth

def main():
    client = cli.ClientV1("11.11.11.1", 2886, PasswordAuth("****"))
```
### Deploy Cluster
OBShell-SDK-Python provides two types of methods to deploy an OBShell cluster: the first immediately returns after successfully making a request to the OBShell API, and the second waits for the OBShell task to complete after the API request is successful before returning. The former executes the task asynchronously, while the latter executes the task synchronously.

**Deploy a 1-1-1 cluster:**
* Asynchronous Task Execution
```python
import obshell_sdk_python.service.v1.client as cli
from obshell_sdk_python.sdk.auth.password import PasswordAuth
def main():
    client = cli.ClientV1("11.11.11.1", 2886, PasswordAuth("****"))

    # join master
    dag = client.join("11.11.11.1", 2886, "zone1")
    client.wait_dag_succeed(dag.generic_id)
    # join follower
    dag = client.join("11.11.11.2", 2886, "zone2")
    client.wait_dag_succeed(dag.generic_id)
    dag = client.join("11.11.11.3", 2886, "zone3")
    client.wait_dag_succeed(dag.generic_id)

    # configure observer
    configs = {
        "datafile_size": "24G", "log_disk_size": "24G", 
        "cpu_count": "16", "memory_limit": "16G", "system_memory": "8G", 
        "enable_syslog_recycle": "true", "enable_syslog_wf": "true"}
    dag = client.config_observer(configs, "GLOBAL", [])
    client.wait_dag_succeed(dag.generic_id)

    # configure obcluster
    dag = client.config_obcluster_sync("test-sdk", 11, "****")
    client.wait_dag_succeed(dag.generic_id)

    # initialize obcluster
    dag = client.init_sync()
    client.wait_dag_succeed(dag.generic_id)
    
    # get the status of the cluster
    status = client.get_status()
    print(status)
```
* Synchronous Task Execution
```python
import obshell_sdk_python.service.v1.client as cli
from obshell_sdk_python.sdk.auth.password import PasswordAuth

def main():
    client = cli.ClientV1("11.11.11.1", 2886, PasswordAuth("1111"))

    # join master
    client.join_sync("11.11.11.1", 2886, "zone1")
    # join follower
    client.join_sync("11.11.11.2", 2886, "zone2")
    client.join_sync("11.11.11.3", 2886, "zone3")

    # configure observer
    configs = {
        "datafile_size": "24G", "log_disk_size": "24G", 
        "cpu_count": "16", "memory_limit": "16G", "system_memory": "8G", 
        "enable_syslog_recycle": "true", "enable_syslog_wf": "true"}
    client.config_observer_sync(configs, "GLOBAL", [])

    # configure obcluster
    client.config_obcluster_sync("test-sdk", 11, "****")

    # initialize obcluster
    client.init_sync()
    
    # get the status of the cluster
    status = client.get_status()
    print(status)
```
### Scale out
Scale out the agent '11.11.11.4' into the cluster where the agent '11.11.11.1' is located.
```python
import obshell_sdk_python.service.v1.client as cli
from obshell_sdk_python.sdk.auth.password import PasswordAuth

def main():
    client = cli.ClientV1("11.11.11.1", 2886, PasswordAuth("****"))

    # scale out
    configs = {
        "datafile_size": "24G", "log_disk_size": "24G", 
        "cpu_count": "16", "memory_limit": "16G", "system_memory": "8G", 
        "enable_syslog_recycle": "true", "enable_syslog_wf": "true"}
    client.scale_out_sync("11.11.11.4", 2886, "zone3", configs)
```
