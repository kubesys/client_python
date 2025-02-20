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
import kubesys.http_request as http_request
from kubesys.common import getLastIndex
from kubesys.exceptions import KindException

__author__ = ('Tian Yu <yutian20@otcaix.iscas.ac.cn>',
              'Heng Wu <wuheng@iscas.ac.cn>',
              'Jiexin Liu <liujiexin@otcaix.iscas.ac.cn>')


class KubernetesAnalyzer:
    def __init__(self) -> None:
        self.KindToFullKindDict = {}
        self.FullKindToApiPrefixDict = {}

        self.FullKindToNameDict = {}
        self.FullKindToNamespaceDict = {}

        self.FullKindToVersionDict = {}
        self.FullKindToGroupDict = {}
        self.FullKindToVerbsDict = {}

    def checkAndReturnRealKind(self, kind):
        mapper=self.KindToFullKindDict
        index = kind.find(".")
        if index < 0:
            if not mapper.get(kind) or len(mapper.get(kind)) == 0:
                raise KindException(f"Invalid kind {kind}")
            if len(mapper[kind]) == 1:
                return mapper[kind][0]

            else:
                value = ""
                for s in mapper[kind]:
                    value += "," + s

                raise KindException("please use fullKind: " + value[1:])
        return kind

    def learning(self, url, token, config) -> None:
        registryValues = http_request.createRequest(url=url, token=token, method="GET", keep_json=False, config=config)

        # print(registryValues)
        for path in registryValues["paths"]:
            if path.startswith("/api") and (len(path.split("/")) == 4 or path.lower().strip() == "/api/v1"):
                resourceValues = http_request.createRequest(url=url + path, token=token, method="GET", keep_json=False, config=config)
                apiVersion = str(resourceValues["groupVersion"])

                for resourceValue in resourceValues["resources"]:
                    shortKind = resourceValue["kind"]
                    fullKind = self.getFullKind(shortKind, apiVersion)

                    if fullKind not in self.FullKindToApiPrefixDict.keys():
                        if shortKind not in self.KindToFullKindDict.keys():
                            self.KindToFullKindDict[shortKind] = []

                        self.KindToFullKindDict[shortKind].append(fullKind)
                        self.FullKindToApiPrefixDict[fullKind] = url + path

                        self.FullKindToNameDict[fullKind] = str(resourceValue["name"])
                        self.FullKindToNamespaceDict[fullKind] = bool(resourceValue["namespaced"])

                        self.FullKindToVersionDict[fullKind] = apiVersion
                        self.FullKindToGroupDict[fullKind] = self.getGroup(apiVersion)
                        self.FullKindToVerbsDict[fullKind] = resourceValue["verbs"]

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
