'''
 * Copyright (2024, ) Institute of Software, Chinese Academy of Sciences
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 '''
import sys
from typing import Union, Dict, List, Optional
from kubesys.common import getLastIndex, dictToJsonString, jsonStringToBytes, getParams, formatURL
from kubesys.http_request import createRequest,doCreateRequest
from kubesys.analyzer import KubernetesAnalyzer
from kubesys.exceptions import WatchException,HTTPError
import requests
import json
from kubesys.common import jsonBytesToDict
import threading
from kubesys.logger import logger, info, error, debug, warning
from kubesys import http_request
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urljoin
from functools import lru_cache
import time

from kubesys.tls import readConfig, recreate_tls_files
from kubesys.watcher import KubernetesWatcher

__author__ = ('Tian Yu <yutian20@otcaix.iscas.ac.cn>',
              'Jiexin Liu <liujiexin@otcaix.iscas.ac.cn>',
              'Heng Wu <wuheng@iscas.ac.cn>')


class KubernetesClient():
    watcher_threads = {}  # static field, record the thread that used to watch

    # def __init__(self, url=None, token=None, analyzer=None, verify_SSL=False,
    #              account_json={"json_path": "account.json", "host_label": "default"}, relearning=True) -> None:
    #     if not url and not token:
    #         with open(account_json["json_path"], 'r', encoding='UTF-8') as f:
    #             account_info_dict = json.load(f)
    #             if account_json["host_label"] not in account_info_dict.keys():
    #                 print("host label<%s> is not found in %s" % (account_json["host_label"], account_json["json_path"]))
    #                 exit(-2)
    #             url = account_info_dict[account_json["host_label"]]["URL"]
    #             token = account_info_dict[account_json["host_label"]]["Token"]

    def __init__(self, url=None, token=None, config=None, relearning=True) -> None:
        # 初始化缓存相关属性
        self._version_cache = {}
        self._last_cache_update = 0
        self._cache_ttl = 300  # 缓存有效期5分钟
        
        try:
            if config is not None:
                recreate_tls_files(config)
            else:
                recreate_tls_files('/etc/kubernetes/admin.conf')
        except Exception as e:
            print(f"recreate_tls_files error: {e}")

        try:
            self.config = config

            if self.config is None:
                if url is None or token is None:
                    raise HTTPError('missing url or token')
                self.url = url.rstrip("/")
                self.token = token
            else:
                self.config = readConfig(config)
                self.url = self.config.server
                self.token = None

            self.analyzer = KubernetesAnalyzer()
            info("Initializing Kubernetes client...")
            self.analyzer.learning(url=self.url, token=self.token, config=self.config)

            if relearning and self.analyzer:
                self.Init()

            # 初始化logger
            self.logger = logging.getLogger(__name__)
            
            # 初始化session
            self.session = requests.Session()
            
            # 配置重试策略
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[500, 502, 503, 504]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
            
            # 初始化headers
            self.headers = {
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate, br",
            }
            if self.token:
                self.headers["Authorization"] = "Bearer " + self.token
                
        except Exception as e:
            error(f"Failed to initialize Kubernetes client: {str(e)}")
            raise

    def Init(self) -> None:
        self.analyzer.learning(url=self.url, token=self.token, config=self.config)

    def getNamespace(self, supportNS, value) -> str:
        if supportNS and len(value) > 0:
            return "namespaces/" + value + "/"

        return ""

    def getRealKind(self, kind, apiVersion) -> str:
        index = apiVersion.find("/")
        if index < 0:
            return kind
        else:
            return apiVersion[:index] + "." + kind

    def _get_api_resources(self) -> Dict[str, List[Dict]]:
        """
        Get available API resources and their preferred versions
        Returns: Dict[resource_kind, List[{group, version, namespaced}]]
        """
        try:
            current_time = time.time()
            
            # 检查缓存是否有效
            if (hasattr(self, '_last_cache_update') and 
                hasattr(self, '_version_cache') and 
                current_time - self._last_cache_update < self._cache_ttl and 
                self._version_cache):
                return self._version_cache

            resources = {}
            
            # Get core API resources
            core_api = createRequest(
                url=urljoin(self.url, '/api/v1'),
                token=self.token,
                method='GET',
                config=self.config
            )
            
            if core_api and 'resources' in core_api:
                for resource in core_api['resources']:
                    if '/' not in resource.get('name', ''):  # Skip subresources
                        kind = resource.get('kind')
                        if kind:
                            if kind not in resources:
                                resources[kind] = []
                            resources[kind].append({
                                'group': '',
                                'version': 'v1',
                                'namespaced': resource.get('namespaced', True)
                            })

            # Get API groups
            groups_response = createRequest(
                url=urljoin(self.url, '/apis'),
                token=self.token,
                method='GET',
                config=self.config
            )

            if groups_response and 'groups' in groups_response:
                for group in groups_response['groups']:
                    group_name = group.get('name', '')
                    preferred_version = group.get('preferredVersion', {}).get('version')
                    
                    if not preferred_version:
                        continue

                    # Get resources for this API group
                    group_resources = createRequest(
                        url=urljoin(self.url, f'/apis/{group_name}/{preferred_version}'),
                        token=self.token,
                        method='GET',
                        config=self.config
                    )

                    if group_resources and 'resources' in group_resources:
                        for resource in group_resources['resources']:
                            if '/' not in resource.get('name', ''):  # Skip subresources
                                kind = resource.get('kind')
                                if kind:
                                    if kind not in resources:
                                        resources[kind] = []
                                    resources[kind].append({
                                        'group': group_name,
                                        'version': preferred_version,
                                        'namespaced': resource.get('namespaced', True)
                                    })

            # Cache the results
            self._version_cache = resources
            self._last_cache_update = current_time
            return resources
            
        except Exception as e:
            error(f"Failed to get API resources: {str(e)}")
            # 如果出错，确保返回空字典而不是None
            return {}

    def _get_resource_info(self, kind: str) -> Dict:
        """
        Get the preferred API version and other info for a given resource kind
        """
        resources = self._get_api_resources()
        if kind not in resources:
            raise ValueError(f"Resource kind '{kind}' not found in the cluster")

        # Use the first available version (which is typically the preferred version)
        return resources[kind][0]

    def _ensure_api_version(self, resource: Union[dict, str]) -> dict:
        """
        Ensure the resource has the correct API version
        """
        if isinstance(resource, str):
            resource = json.loads(resource)
        
        if not isinstance(resource, dict):
            raise ValueError("Resource must be a dictionary")
        
        if 'kind' not in resource:
            raise ValueError("Resource must have a 'kind' field")
        
        kind = resource['kind']
        if 'apiVersion' not in resource:
            resource_info = self._get_resource_info(kind)
            group = resource_info['group']
            version = resource_info['version']
            resource['apiVersion'] = f"{group}/{version}" if group else version
        
        return resource

    def _get_resource_url(self, resource: dict, name: str = None) -> str:
        """
        Get the appropriate URL for the resource
        """
        kind = resource['kind']
        api_version = resource['apiVersion']
        namespace = resource.get('metadata', {}).get('namespace', 'default')
        
        resource_info = self._get_resource_info(kind)
        is_namespaced = resource_info['namespaced']
        
        if '/' in api_version:
            group, version = api_version.split('/')
            base_url = f"/apis/{group}/{version}"
        else:
            base_url = f"/api/{api_version}"

        resource_type = kind.lower() + 's'
        
        if is_namespaced:
            url = f"{self.url}{base_url}/namespaces/{namespace}/{resource_type}"
        else:
            url = f"{self.url}{base_url}/{resource_type}"
            
        if name:
            url = f"{url}/{name}"
            
        return url

    def createResource(self, resource: Union[dict, str], **kwargs):
        """Create a Kubernetes resource with automatic API version detection"""
        try:
            resource = self._ensure_api_version(resource)
            url = self._get_resource_url(resource)
            
            return createRequest(
                url=url,
                token=self.token,
                method="POST",
                body=json.dumps(resource),
                config=self.config,
                **kwargs
            )
        except Exception as e:
            raise Exception(f"Failed to create resource: {str(e)}")

    def updateResource(self, resource: Union[dict, str], **kwargs):
        """Update a Kubernetes resource with automatic API version detection"""
        try:
            resource = self._ensure_api_version(resource)
            name = resource.get('metadata', {}).get('name')
            
            if not name:
                raise ValueError("Resource must have a name")
                
            url = self._get_resource_url(resource, name)
            
            return createRequest(
                url=url,
                token=self.token,
                method="PUT",
                body=json.dumps(resource),
                config=self.config,
                **kwargs
            )
        except Exception as e:
            raise Exception(f"Failed to update resource: {str(e)}")

    def deleteResource(self, kind: str, name: str, namespace: str = None, **kwargs):
        """Delete a Kubernetes resource with automatic API version detection"""
        try:
            resource_info = self._get_resource_info(kind)
            group = resource_info['group']
            version = resource_info['version']
            api_version = f"{group}/{version}" if group else version
            
            resource = {
                'kind': kind,
                'apiVersion': api_version,
                'metadata': {
                    'name': name,
                    'namespace': namespace
                }
            }
            
            url = self._get_resource_url(resource, name)
            
            return createRequest(
                url=url,
                token=self.token,
                method="DELETE",
                config=self.config,
                **kwargs
            )
        except Exception as e:
            raise Exception(f"Failed to delete resource: {str(e)}")

    def getResource(self, kind, namespace='default', name='', pretty=False):
        try:
            fullKind = self.analyzer.checkAndReturnRealKind(kind)
            url = self.url + self.analyzer.fullkind_to_api[fullKind] + "/"
            is_namespaced = self.analyzer.resources[fullKind].get('namespaced', False)
            url += self.getNamespace(is_namespaced, namespace)
            resource_name = self.analyzer.resources[fullKind]['name']
            if "/" in resource_name:
                resource_name = resource_name.split("/")[0]
            url += resource_name
            if name:
                url = f"{url}/{name}"
            params = {}
            if pretty:
                params['pretty'] = 'true'
            debug(f"Requesting URL: {url}")  # 调试日志
            return http_request.createRequest(
                url=url,
                token=self.token,
                method="GET",
                config=self.config,
                **params
            )
        except Exception as e:
            error(f"Failed to get resource {kind}/{name}: {str(e)}")
            raise

    def listResources(self, kind, namespace=None, **kwargs) -> dict:
        fullKind = self.analyzer.checkAndReturnRealKind(kind)
        url = self.url + self.analyzer.fullkind_to_api[fullKind] + "/"
        is_namespaced = self.analyzer.resources[fullKind].get('namespaced', False)
        url += self.getNamespace(is_namespaced, namespace)
        resource_name = self.analyzer.resources[fullKind]['name']
        if "/" in resource_name:
            resource_name = resource_name.split("/")[0]
        url += resource_name
        return createRequest(url=url, token=self.token, method="GET", keep_json=False, config=self.config, **kwargs)

    def bindResource(self, pod, host, **kwargs) -> dict:
        jsonObj = {}
        jsonObj["apiVersion"] = "v1"
        jsonObj["kind"] = "Binding"

        meta = {}
        meta["name"] = pod["metadata"]["name"]
        meta["namespace"] = pod["metadata"]["namespace"]
        jsonObj["metadata"] = meta

        target = {}
        target["apiVersion"] = "v1"
        target["kind"] = "Node"
        target["name"] = host
        jsonObj["target"] = target

        kind = self.getRealKind(pod["kind"], pod["apiVersion"])
        namespace = pod["metadata"]["namespace"]

        url = self.url + self.analyzer.fullkind_to_api[kind] + "/"
        is_namespaced = self.analyzer.resources[kind].get('namespaced', False)
        url += self.getNamespace(is_namespaced, namespace)
        url += self.analyzer.resources[kind]['name'] + "/"
        url += pod["metadata"]["name"] + "/binding"

        return createRequest(url=url, token=self.token, method="POST", data=jsonObj, keep_json=False, config=self.config,**kwargs)

    def watchResource(self, kind, namespace, watcherhandler, name=None, thread_name=None, is_daemon=True,
                      **kwargs) -> KubernetesWatcher:
        '''
        if is_daemon is True, when the main thread leave, this thead will leave automatically.
        '''
        fullKind = self.analyzer.checkAndReturnRealKind(kind)

        api_prefix = self.analyzer.fullkind_to_api[fullKind]
        plural = self.analyzer.fullkind_to_plural[fullKind]
        is_namespaced = self.analyzer.resources[fullKind].get('namespaced', False)
        url = self.url + api_prefix + "/"
        if is_namespaced and namespace:
            url += f"namespaces/{namespace}/"
        url += plural
        if name:
            url += "/" + name

        thread_t = threading.Thread(target=KubernetesClient.watching,
                                    args=(url, self.token, self.config, watcherhandler, kwargs,),
                                    name=thread_name, daemon=is_daemon)

        watcher = KubernetesWatcher(thread_t=thread_t, kind=kind, namespace=namespace, watcher_handler=watcherhandler,
                                    name=name, url=url, **kwargs)
        KubernetesClient.watcher_threads[thread_t.getName()] = watcher
        watcher.run()
        return watcher

    def watchResources(self, kind, namespace, watcherhandler, thread_name=None, is_daemon=True,
                       **kwargs) -> KubernetesWatcher:
        '''
        if is_daemon is True, when the main thread leave, this thead will leave automatically.
        '''
        return self.watchResource(kind, namespace, watcherhandler, name=None, thread_name=thread_name,
                                  is_daemon=is_daemon, **kwargs)
            

    def watchResourceBase(self, kind, namespace, handlerFunction, name=None, thread_name=None, is_daemon=True,
                          **kwargs) -> KubernetesWatcher:
        '''
        if is_daemon is True, when the main thread leave, this thead will leave automatically.
        '''
        fullKind = self.analyzer.checkAndReturnRealKind(kind)

        url = self.analyzer.fullkind_to_api[fullKind] + "/watch/"
        url += self.getNamespace(self.analyzer.resources[fullKind].get('namespaced', False), namespace)
        if name:
            url += self.analyzer.fullkind_to_plural[fullKind] + "/" + name
        else:
            url += self.analyzer.fullkind_to_plural[fullKind]

        thread_t = threading.Thread(target=KubernetesClient.watchingBase,
                                    args=(url, self.token, handlerFunction, kwargs,), name=thread_name,
                                    daemon=is_daemon)
        watcher = KubernetesWatcher(thread_t=thread_t, kind=kind, namespace=namespace, watcher_handler=handlerFunction,
                                    name=name, url=url, **kwargs)
        KubernetesClient.watcher_threads[thread_t.getName()] = watcher
        watcher.run()
        return watcher

    def watchResourcesBase(self, kind, namespace, handlerFunction, thread_name=None, is_daemon=True,
                           **kwargs) -> KubernetesWatcher:
        '''
        if is_daemon is True, when the main thread leave, this thead will leave automatically.
        '''
        return self.watchResourceBase(kind, namespace, handlerFunction, name=None, thread_name=thread_name,
                                      is_daemon=is_daemon, **kwargs)

    @staticmethod
    def watching(url, token, config, watchHandler, kwargs):
        # TODO
        response=doCreateRequest(url=formatURL(url, getParams(kwargs)) + "&watch=true&timeoutSeconds=315360000", token=token, method="GET", config=config,stream=True)
        for json_bytes in response.iter_lines():
            if len(json_bytes) < 1:
                continue

            jsonObj = jsonBytesToDict(json_bytes)
            if "type" not in jsonObj.keys():
                raise WatchException(f"type is not found in keys while watching, dict is: {jsonObj}" )

            if jsonObj["type"] == "ADDED":
                watchHandler.DoAdded(jsonObj["object"])
            elif jsonObj["type"] == "MODIFIED":
                watchHandler.DoModified(jsonObj["object"])
            elif jsonObj["type"] == "DELETED":
                watchHandler.DoDeleted(jsonObj["object"])
            else:
                raise WatchException(f"unknow type while watching: {jsonObj['type']}")
        KubernetesClient.removeWatcher(thread_name=threading.currentThread().getName())

    @staticmethod
    def watchingBase(url, token, handlerFunction, kwargs):
        if token is None:
            header = {
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate, br",
            }
        else:
            header = {
                "Accept": "*/*",
                "Authorization": "Bearer " + token,
                "Accept-Encoding": "gzip, deflate, br",
            }

        # TODO
        with requests.get(url=formatURL(url, getParams(kwargs)) + "&watch=true&timeoutSeconds=315360000", headers=header, verify=False, stream=True) as response:
            for json_bytes in response.iter_lines():
                if len(json_bytes) < 1:
                    continue

                jsonObj = jsonBytesToDict(json_bytes)
                handlerFunction(jsonObj=jsonObj)

        del KubernetesClient.watcher_threads[threading.currentThread().getName()]

    def updateResourceStatus(self, jsonStr, **kwargs) -> dict:
        jsonObj = jsonStr
        if type(jsonObj) is str:
            jsonObj = json.loads(jsonObj)
        elif type(jsonObj) is dict:
            jsonStr=dictToJsonString(jsonStr)

        kind = self.getRealKind(jsonObj["kind"], jsonObj["apiVersion"])
        namespace = ""
        if "namespace" in jsonObj["metadata"]:
            namespace = jsonObj["metadata"]["namespace"]

        url = self.url + self.analyzer.fullkind_to_api[kind] + "/"
        is_namespaced = self.analyzer.resources[kind].get('namespaced', False)
        url += self.getNamespace(is_namespaced, namespace)
        url += self.analyzer.resources[kind]['name'] + "/" + jsonObj["metadata"]["name"]
        url += "/status"

        return createRequest(url=url, token=self.token, method="PATCH", body=jsonStr, keep_json=False,config=self.config, **kwargs)

    def getResourceStatus(self,kind, name, namespace="", **kwargs)->dict:
        fullKind = self.analyzer.checkAndReturnRealKind(kind)

        url = self.url + self.analyzer.fullkind_to_api[fullKind] + "/"
        is_namespaced = self.analyzer.resources[fullKind].get('namespaced', False)
        url += self.getNamespace(is_namespaced, namespace)
        resource_name = self.analyzer.resources[fullKind]['name']
        if "/" in resource_name:
            resource_name = resource_name.split("/")[0]
        url += resource_name + "/" + name
        url += "/status"

        return createRequest(url=url, token=self.token, method="GET", keep_json=False, config=self.config, **kwargs)

    def listResourcesWithSelector(self, kind, namespace, tp,selects) -> dict:
        fullKind = self.analyzer.checkAndReturnRealKind(kind)

        url = self.url + self.analyzer.fullkind_to_api[fullKind] + "/"
        is_namespaced = self.analyzer.resources[fullKind].get('namespaced', False)
        url += self.getNamespace(is_namespaced, namespace)
        url += self.analyzer.resources[fullKind]['name']
        if tp=='label':
            url += "?labelSelector="
        elif tp=='field':
            url += "?fieldSelector="
        else:
            raise HTTPError(404,f"selector type {tp} should either be label or field")
        for key, value in selects.items():
            url += key + "%3D=" + value + ","
        url = url[:len(url) - 1]
        return createRequest(url=url, token=self.token, method="GET", keep_json=False,config=self.config)


    def getKinds(self) -> list:
        return list(self.analyzer.KindToFullKindDict.keys())

    def getFullKinds(self) -> list:
        return list(self.analyzer.resources.keys())

    def kind(self, fullkind) -> str:
        index = getLastIndex(fullkind, ".")
        if index < 1:
            return fullkind
        return fullkind[index + 1:]

    def getKindDesc(self) -> dict:
        desc = {}
        for fullKind in self.analyzer.resources.keys():
            value = {}
            value["apiVersion"] = self.analyzer.fullkind_to_api[fullKind]
            value["kind"] = self.kind(fullKind)
            value["plural"] = self.analyzer.resources[fullKind]['name']
            value["verbs"] = self.analyzer.fullkind_to_verbs[fullKind]
            desc[fullKind] = value

        return desc

    def getKindDescBytes(self) -> bytes:
        desc = self.getKindDesc()

        return jsonStringToBytes(dictToJsonString(desc))

    '''
    static methods for watch thread
    '''

    @staticmethod
    def getWatchThreadCount() -> int:
        return len(KubernetesClient.watcher_threads.keys())

    @staticmethod
    def getWatcher(thread_name) -> KubernetesWatcher:
        if thread_name in KubernetesClient.watcher_threads.keys():
            return KubernetesClient.watcher_threads[thread_name]
        return None

    @staticmethod
    def removeWatcher(thread_name) -> None:
        if thread_name in KubernetesClient.watcher_threads.keys():
            if KubernetesClient.isWatcherAlive(thread_name):
                KubernetesClient.watcher_threads[thread_name].stop()

            del KubernetesClient.watcher_threads[thread_name]

    @staticmethod
    def isWatcherAlive(thread_name) -> bool:
        if thread_name in KubernetesClient.watcher_threads.keys():
            return KubernetesClient.watcher_threads[thread_name].is_alive()
        return False

    @staticmethod
    def removeWatchers() -> None:
        for thread_name in KubernetesClient.watcher_threads.keys():
            KubernetesClient.watcher_threads[thread_name].stop()
        KubernetesClient.watcher_threads = {}

    @staticmethod
    def removeClosedWatchers() -> None:
        for thread_name in KubernetesClient.watcher_threads.keys():
            if not KubernetesClient.isWatcherAlive(thread_name):
                KubernetesClient.removeWatcher(thread_name)

    @staticmethod
    def joinWatchers() -> None:
        for thread_name in KubernetesClient.watcher_threads.keys():
            KubernetesClient.watcher_threads[thread_name].join()

    @staticmethod
    def getWatcherThreadNames() -> list:
        return KubernetesClient.watcher_threads.keys()

    def _watch(self):
        """实现watch逻辑，包含重试机制和错误处理"""
        retry_interval = 1  # 初始重试间隔1秒
        
        while self.running:
            try:
                info(f"[Watcher] {self.kind} watcher attempting to establish watch connection")
                
                # 调用client的watchResources方法并获取响应
                response = self.client.watchResources(
                    kind=self.kind,
                    watcherhandler=self.handler,
                    **self.kwargs
                )
                
                # 重置重试间隔
                retry_interval = 1
                info(f"[Watcher] {self.kind} watcher connection established")
                
                # 处理响应流
                for line in response.iter_lines():
                    if not self.running:
                        break
                        
                    if not line:
                        continue
                        
                    try:
                        # 解析事件数据
                        event = json.loads(line.decode('utf-8'))
                        
                        # 更新指标
                        self.metrics['last_event_time'] = time.time()
                        self.metrics['event_count'] += 1
                        
                        # 记录事件信息
                        event_type = event.get('type')
                        obj = event.get('object', {})
                        name = obj.get('metadata', {}).get('name')
                        debug(f"[Watcher] {self.kind} received {event_type} event for {name}")
                        debug(f"[Watcher] Event content: {json.dumps(event, indent=2)}")
                        
                        # 处理事件
                        if self.handler:
                            self.handler.handle(event)
                        
                    except json.JSONDecodeError as je:
                        error(f"[Watcher] Failed to decode event: {str(je)}, raw data: {line}")
                        continue
                    except Exception as e:
                        self.metrics['error_count'] += 1
                        error(f"[Watcher] {self.kind} error processing event: {str(e)}")
                        continue
                
            except Exception as e:
                self.metrics['error_count'] += 1
                self.metrics['reconnect_count'] += 1
                error(f"[Watcher] {self.kind} watch connection failed: {str(e)}")
                
                # 指数退避重试
                retry_interval = min(retry_interval * 2, self.max_retry_interval)
                warning(f"[Watcher] {self.kind} retrying in {retry_interval} seconds")
                
                if self.running:
                    time.sleep(retry_interval)
                    continue
                else:
                    break
        
        info(f"[Watcher] {self.kind} watcher thread exiting")

    def _verify_connection(self):
        """验证与API server的连接"""
        try:
            # 尝试获取资源列表
            self.client.getResources(kind=self.kind)
            info(f"[Watcher] Successfully verified connection for {self.kind}")
            return True
        except Exception as e:
            error(f"[Watcher] Connection verification failed for {self.kind}: {str(e)}")
            return False

    def start(self):
        if self.running:
            warning(f"[Watcher] {self.kind} watcher is already running")
            return
        
        # 先验证连接
        if not self._verify_connection():
            error(f"[Watcher] Cannot start watcher for {self.kind}: connection verification failed")
            return
            
        info(f"[Watcher] Starting watcher for resource kind: {self.kind}")
        self.running = True
        self.metrics['start_time'] = time.time()
        self.thread = threading.Thread(target=self._watch)
        self.thread.daemon = True
        self.thread.start()
        info(f"[Watcher] {self.kind} watcher thread started")

    def partiallyUpdateResource(self, resource: Union[dict, str], **kwargs):
        """
        Partially update (PATCH) a Kubernetes resource with automatic API version detection
        Supports both strategic merge patch and JSON merge patch
        """
        try:
            resource = self._ensure_api_version(resource)
            name = resource.get('metadata', {}).get('name')
            
            if not name:
                raise ValueError("Resource must have a name")
                
            url = self._get_resource_url(resource, name)
            
            headers = {
                'Content-Type': 'application/strategic-merge-patch+json',
                'Accept': 'application/json'
            }
            
            return createRequest(
                url=url,
                token=self.token,
                method="PATCH",
                body=json.dumps(resource),
                headers=headers,
                config=self.config,
                **kwargs
            )
        except Exception as e:
            raise Exception(f"Failed to patch resource: {str(e)}")

    def patchResource(self, kind: str, name: str, patch_data: dict, 
                     namespace: str = None, patch_type: str = "strategic", **kwargs):
        """
        Apply a patch to a Kubernetes resource
        
        Args:
            kind: Resource kind (e.g. 'Node', 'Pod')
            name: Resource name
            patch_data: The patch to apply
            namespace: Resource namespace (if applicable)
            patch_type: One of "strategic" (default), "merge", or "json"
        """
        try:
            resource_info = self._get_resource_info(kind)
            group = resource_info['group']
            version = resource_info['version']
            api_version = f"{group}/{version}" if group else version
            
            resource = {
                'kind': kind,
                'apiVersion': api_version,
                'metadata': {
                    'name': name,
                    'namespace': namespace
                }
            }
            
            url = self._get_resource_url(resource, name)
            
            content_type = {
                "strategic": "application/strategic-merge-patch+json",
                "merge": "application/merge-patch+json",
                "json": "application/json-patch+json"
            }.get(patch_type, "application/strategic-merge-patch+json")
            
            headers = {
                'Content-Type': content_type,
                'Accept': 'application/json'
            }
            
            return createRequest(
                url=url,
                token=self.token,
                method="PATCH",
                body=json.dumps(patch_data),
                headers=headers,
                config=self.config,
                **kwargs
            )
        except Exception as e:
            raise Exception(f"Failed to patch resource: {str(e)}")













