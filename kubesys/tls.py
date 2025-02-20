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
import os

import yaml
from base64 import b64decode

__author__ = ('Tian Yu <yutian20@otcaix.iscas.ac.cn>',
              'Heng Wu <wuheng@iscas.ac.cn>',
              'Jiexin Liu <liujiexin@otcaix.iscas.ac.cn>')

from cryptography import x509
from cryptography.hazmat.backends import default_backend


class Config():
    def __init__(self, server, certificateAuthorityData, clientCertificateData, clientKeyData):
        self.server = server
        self.certificateAuthorityData = certificateAuthorityData
        self.clientCertificateData = clientCertificateData
        self.clientKeyData = clientKeyData


def readConfig(config='/etc/kubernetes/admin.conf'):
    file = open(config, 'r', encoding='utf-8')
    yf = yaml.load(file.read(), Loader=yaml.SafeLoader)
    return Config(server=yf['clusters'][0]['cluster']['server'],
                  certificateAuthorityData=b64decode(yf['clusters'][0]['cluster']['certificate-authority-data']),
                  clientCertificateData=b64decode(yf['users'][0]['user']['client-certificate-data']),
                  clientKeyData=b64decode(yf['users'][0]['user']['client-key-data']))


def rootCAs(certificateAuthorityData):
    return x509.load_pem_x509_csr(certificateAuthorityData, default_backend())


def tlsPaths(config):
    return tlsFile('pem', config.certificateAuthorityData), tlsFile('ca', config.clientCertificateData), tlsFile('key', config.clientKeyData)


def tlsFile(name, content):
    path = os.getcwd() + "/" + name
    if os.path.exists(path):
        os.remove(path)
    f = open(path, "w")
    f.write(str(content, 'UTF-8'))
    f.close()
    return path
