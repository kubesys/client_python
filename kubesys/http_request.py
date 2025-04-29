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
from kubesys.common import formatURL, getParams, dictToJsonString
import requests
from requests.models import HTTPError
from requests.exceptions import JSONDecodeError
import json
from kubesys.tls import tlsPaths

__author__ = ('Tian Yu <yutian20@otcaix.iscas.ac.cn>',
              'Jiexin Liu <liujiexin@otcaix.scas.ac.cn>',
              'Heng Wu <wuheng@iscas.ac.cn>')

def createRequest(url, token, method="GET", body=None, verify=False,
                  keep_json=False, config=None, **kwargs):
    try:
        logger.debug(f"Making request: {method} {url}")
        response = doCreateRequest(
            formatURL(url, getParams(kwargs)), token, method, body, config)
        
        try:
            result = response.json()
            if result.get('kind') == 'Status':
                error_msg = f"{result.get('reason')} {result.get('message')}"
                logger.error(f"Request failed: {error_msg}")
                raise HTTPError(result.get('code'), error_msg)
                
            if keep_json:
                result = dictToJsonString(result)
            return result
            
        except JSONDecodeError:
            error_msg = f"{response.url} {response.reason}"
            logger.error(f"Failed to decode JSON response: {error_msg}")
            raise HTTPError(response.status_code, error_msg)
            
    except Exception as e:
        logger.error(f"Request failed: {str(e)}")
        raise

def doCreateRequest(url, token, method="GET", body=None, config=None,stream=False):
    print(url)
    if config is None:
        response = doCreateRequestWithToken(url, token, method,stream, body)
    else:
        response = doCreateRequestWithConfig(url, config, method,stream, body)
    return response


def doCreateRequestWithToken(url, token, method,stream, body=None):
    header, data = getHeaderAndBody(token, body,method)
    return requests.request(method, url=url,
                            headers=header, data=data, verify=False,stream=stream)


def doCreateRequestWithConfig(url, config, method, stream,body=None):

    header, data = getHeaderAndBody(None, body,method)
    pem, ca, key = tlsPaths(config)
    return requests.request(method, url=url, headers=header, data=data,
                            verify=pem, cert=(ca, key),stream=stream)


def getHeaderAndBody(token, body,method):
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

    if body:
        if method=="PATCH":
            header["Content-Type"] = "application/merge-patch+json"
        else:
            header["Content-Type"] = "application/json"

        if type(body) is dict:
            data = json.dumps(body, indent=4, separators=(',', ': '))
        else:
            data = str(body)
    else:
        body = None
    return header, body
