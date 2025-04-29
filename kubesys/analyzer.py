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
from kubesys.logger import logger
from kubesys import http_request
from kubesys.common import getLastIndex
from kubesys.exceptions import KindException

__author__ = ('Tian Yu <yutian20@otcaix.iscas.ac.cn>',
              'Heng Wu <wuheng@iscas.ac.cn>',
              'Jiexin Liu <liujiexin@otcaix.iscas.ac.cn>')


class KubernetesAnalyzer:
    def __init__(self) -> None:
        # key: 多种写法，value: fullKind（如"batch.v1.Job"）
        self.kind_map = {}  # 支持Node、batch.Job、v1.Node、batch.v1.Job等多种写法
        self.fullkind_to_api = {}  # fullKind -> api前缀
        self.resources = {}  # fullKind -> 资源详情
        self.fullkind_to_plural = {}  # fullKind -> 复数名（plural）

    def checkAndReturnRealKind(self, kind: str) -> str:
        """
        支持如下写法自动适配：
        - Node
        - batch.Job
        - v1.Node
        - batch.v1.Job
        - mygroup.io.v1alpha1.MyKind
        """
        # 1. 直接是fullKind
        if kind in self.fullkind_to_api:
            return kind
        # 2. group.kind 或 version.kind
        if kind in self.kind_map:
            return self.kind_map[kind]
        # 3. 仅kind名
        if kind in self.kind_map:
            return self.kind_map[kind]
        # 4. 智能模糊查找
        candidates = [fk for k, fk in self.kind_map.items() if k.lower() == kind.lower()]
        if len(candidates) == 1:
            return candidates[0]
        elif len(candidates) > 1:
            raise KindException(f"Ambiguous kind '{kind}', candidates: {candidates}")
        raise KindException(f"Invalid kind '{kind}'")

    def learning(self, url, token, config=None):
        """
        动态学习所有资源，自动建立kind多写法映射
        """
        try:
            logger.info("Start learning Kubernetes API resources...")
            self.kind_map.clear()
            self.fullkind_to_api.clear()
            self.resources.clear()
            self.fullkind_to_plural.clear()

            # 1. 处理核心资源（/api/v1）
            core_resources = http_request.createRequest(
                url=url + '/api/v1',
                token=token,
                method="GET",
                keep_json=False,
                config=config
            )
            if core_resources and 'resources' in core_resources:
                for res in core_resources['resources']:
                    kind = res.get('kind')
                    version = 'v1'
                    group = ''
                    fullkind = f"{version}.{kind}"
                    self.fullkind_to_api[fullkind] = '/api/v1'
                    self.resources[fullkind] = res
                    # 新增：同步填充plural
                    if 'name' in res and '/' not in res['name']:
                        self.fullkind_to_plural[fullkind] = res['name']
                        logger.debug(f"res_name: {res['name']}")
                    # 支持多种写法
                    self.kind_map[kind] = fullkind
                    self.kind_map[f"{version}.{kind}"] = fullkind

            # 2. 处理分组资源（/apis）
            api_groups = http_request.createRequest(
                url=url + '/apis',
                token=token,
                method="GET",
                keep_json=False,
                config=config
            )
            if api_groups and 'groups' in api_groups:
                for group in api_groups['groups']:
                    group_name = group.get('name')
                    versions = group.get('versions', [])
                    for ver in versions:
                        version = ver.get('version')
                        group_version = ver.get('groupVersion')
                        api_prefix = f"/apis/{group_version}"
                        # 获取该groupVersion下的资源
                        group_resources = http_request.createRequest(
                            url=url + api_prefix,
                            token=token,
                            method="GET",
                            keep_json=False,
                            config=config
                        )
                        
                        if group_resources and 'resources' in group_resources:
                            for res in group_resources['resources']:
                                kind = res.get('kind')
                                fullkind = f"{group_name}.{version}.{kind}"
                                self.fullkind_to_api[fullkind] = api_prefix
                                self.resources[fullkind] = res
                                # 新增：同步填充plural
                                if 'name' in res and '/' not in res['name']:
                                    self.fullkind_to_plural[fullkind] = res['name']
                                # 支持多种写法
                                self.kind_map[kind] = fullkind
                                self.kind_map[f"{group_name}.{kind}"] = fullkind
                                self.kind_map[f"{version}.{kind}"] = fullkind
                                self.kind_map[f"{group_name}.{version}.{kind}"] = fullkind
                                # CRD支持
                                if '.' in group_name:
                                    self.kind_map[f"{group_name}.{version}.{kind}"] = fullkind
                                    self.kind_map[f"{group_name}.{kind}"] = fullkind

            logger.info(f"Successfully learned {len(self.kind_map)} kind mappings")
        except Exception as e:
            logger.error(f"Failed to learn Kubernetes API resources: {str(e)}")
            raise

    def getApiPrefix(self, kind: str) -> str:
        real_kind = self.checkAndReturnRealKind(kind)
        return self.fullkind_to_api.get(real_kind)

    def getGroup(self, apiVersion) -> str:
        index = getLastIndex(apiVersion, "/")
        if index > 0:
            return apiVersion[:index]
        else:
            return ""

    def getFullKind(self, shortKind, apiVersion) -> str:
        index = apiVersion.find("/")
        apiGroup = ""

        if index > -1:
            apiGroup = apiVersion[:index]

        fullKind = ""
        if len(apiGroup) == 0:
            fullKind = shortKind
        else:
            fullKind = apiGroup + "." + shortKind

        return fullKind
