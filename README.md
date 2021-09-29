# client-Python

We expect to provide a python client:
- **Flexibility**. It can support all Kubernetes-based systems with minimized extra development, such as [Openshift](https://www.redhat.com/en/technologies/cloud-computing/openshift), [istio](https://istio.io/), etc.
- **Usability**. Developers just need to learn to write json/yaml(kubernetes native style) from [Kubernetes documentation](https://kubernetes.io/docs/home/).
- **Integration**. It can work with the other Kubernetes clients, such as [fabric8](https://github.com/fabric8io/kubernetes-client), [official](https://github.com/kubernetes-client/java/).


## Comparison

|                           | [official](https://github.com/kubernetes-client/go) | [cdk8s](https://cdk8s.io/) | [client-Python](https://github.com/kubesys/kubernetes-client-python) |
|---------------------------|------------------|------------------|-------------------|
|        Compatibility                      | for kubernetes-native kinds    | for crd kinds                 |  for both |
|  Support customized Kubernetes resources  |  a lot of development          | a lot of development          |  zero-deployment     |
|    Works with the other SDKs              |  complex                       | complex                       |  simple              |

## Architecture

![avatar](/docs/arch.png)

## Installation

```shell
python3 -m pip install kubesys
```

just import the module by:

```python
from kubesys.client import KubernetesClient
```

## Usage

- [Usage](#usage)
    - [中文文档](https://www.yuque.com/kubesys/kubernetes-client/overview)
    - [Creating a client](#creating-a-client)
    - [Simple example](#simple-example)
    - [full-example](#full-example)

#### create token with the following commands:

1. create token

```Bash
kubectl create -f https://raw.githubusercontent.com/kubesys/client-go/master/account.yaml
```

2. get token

```Bash
kubectl -n kube-system describe secret $(kubectl -n kube-system get secret | grep kubernetes-client | awk '{print $1}') | grep "token:" | awk -F":" '{print$2}' | sed 's/ //g'
```

### Creating a client

we assume the following information: 

```yaml
host name: aliyun
URL: "https://192.168.1.1:6443"
Token: "THISISTHETOKEN"					# Just as an assumption, in reality this is a long-string
```

* you can simply define the dictionary as follows and then initialize the client  

```python
account={
    "URL": "https://192.168.1.1:6443",
    "Token":"THISISTHETOKEN"
}
client = KubernetesClient(account_info=account)
```

* Also, you can make use of  the host informations in your json-configure file. We edit `account.json` with the following ahead of time:

```json
{
    "aliyun":{
        "URL": "https://192.168.1.1:6443",
        "Token":"THISISTHETOKEN"
    }
}
```

then, we can  initialize the client:

```python
 # "json_path" have the default value: "account.json", you can specify parameters to modify.
client = KubernetesClient(host_label="aliyun") 
```

**If you have set the value of `account_info`, `host_label` will not take effect! **



### simple-example

Assume you have a json:

```json
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "busybox",
    "namespace": "default",
    "labels": {
      "test": "test"
    }
  }
}
```

List resources:

```python
response_dict,OK,http_status_code = client.ListResources("Pod")
print("response dict: ", response_dict)
print("is OK: ", OK)
print("HTTP status code: ", http_status_code)
```

Create a resource:

```go
pod_json= '''{
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "busybox",
            "namespace": "default"
        },
        "spec": {
            "containers": [
                {
                    "image": "busybox",
                    "env": [{
                        "name": "abc",
                        "value": "abc"
                    }],
                    "command": [
                        "sleep",
                        "3600"
                    ],
                    "imagePullPolicy": "IfNotPresent",
                    "name": "busybox"
                }],
            "restartPolicy": "Always"
        }
	}'''

client.createResource(pod_json);
print("response_dict: ", response_dict)
print("is OK: ", OK)
print("HTTP status code: ", http_status_code)
```

Get a resource:

```python
response_dict,OK,http_status_code = client.getResource(kind="Pod",namespace="default", name="busybox")
print("response_dict: ", response_dict)
print("is OK: ", OK)
print("HTTP status code: ", http_status_code)
```

Delete a resource:

```python
response_dict,OK,http_status_code = client.deleteResource(kind="Pod", namespace="default",name="busybox")
print("response_dict: ", response_dict)
print("is OK: ", OK)
print("HTTP status code: ", http_status_code)
```

Watch a resource:

```python
from kubesys.watcher import KubernetesWatcher
from kubesys.watch_handler import WatchHandler

def DoAdder(json_dict)->None:
    print("add pod")

def DoModified(json_dict)->None:
    print("modifiy pod")

def DoDeleted(json_dict)->None:
    print("delete pod")

client = KubernetesClient(host_label="default")   
                                                              # init a client normally
# you can give the watchHandler by python-function
watcher = KubernetesWatcher(client,WatchHandler(add_func=DoAdder,modify_func=DoModified,delete_func= DoDeleted))
# or you can easily give the func-param by python-Lambda
# watcher = KubernetesWatcher(client,WatchHandler(add_func=lambda json_dict: print("add pod"),modify_func=lambda json_dict: print("modifiy pod"),delete_func=lambda json_dict: print("delete pod")))

client.watchResource(kind="Pod", namespace="default", name="busybox",watcher=watcher)
```

Show better print for python-dict as json:

```python
from kubesys.common import goodPrintDict

print(goodPrintDict(response_dict))
```



## full-example

see the result in [run-outputs](/out.txt)

```python
from kubesys.client import KubernetesClient
from kubesys.common import goodPrintDict
from kubesys.watcher import KubernetesWatcher
from kubesys.watch_handler import WatchHandler

def test_CRUD():
    pod_json= '''{
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {
                            "name": "busybox",
                            "namespace": "default"
                        },
                        "spec": {
                            "containers": [
                            {
                                "image": "busybox",
                                "env": [{
                                    "name": "abc",
                                    "value": "abc"
                                    }],
                                "command": [
                                    "sleep",
                                    "3600"
                                    ],
                                "imagePullPolicy": "IfNotPresent",
                                "name": "busybox"
                            }],
                            "restartPolicy": "Always"
                        }
                    }'''

    client = KubernetesClient(host_label="default")

    # test list resources
    print("--test list resources:")
    response_dict,OK,http_status_code = client.listResources("Pod")
    print("response_dict: %s"%(goodPrintDict(response_dict,show_print=False)))
    print("is OK: ", OK)
    print("HTTP status code: ", http_status_code,"\n")

    # test create resources
    print("--test create resources:")
    response_dict,OK,http_status_code = client.createResource(pod_json)
    print("response_dict: %s"%(goodPrintDict(response_dict,show_print=False)))
    print("is OK: ", OK)
    print("HTTP status code: ", http_status_code,"\n")

    # test get one single Resources
    print("--test get one single Resources")
    response_dict,OK,http_status_code = client.getResource(kind="Pod", namespace="default", name="busybox")
    print("response_dict: %s"%(goodPrintDict(response_dict,show_print=False)))
    print("is OK: ", OK)
    print("HTTP status code: ", http_status_code,"\n")

    # test delete pod
    print("--test delete pod:")
    response_dict,OK,http_status_code = client.deleteResource(kind="Pod", namespace="default", name="busybox")
    print("response_dict: %s"%(goodPrintDict(response_dict,show_print=False)))
    print("is OK: ", OK)
    print("HTTP status code: ", http_status_code,"\n")

def test_watcher():
    print("--start to watch...")
    client = KubernetesClient(host_label="default")
    watcher = KubernetesWatcher(client,WatchHandler())
    client.watchResource(kind="Pod", namespace="default", name="busybox",watcher=watcher)
    
def main():
    test_CRUD()
    test_watcher()

if __name__ == '__main__':
    main()
```