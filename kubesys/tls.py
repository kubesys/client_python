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
import tempfile
from kubesys.logger import error, debug
 
import yaml
from base64 import b64decode
import fcntl
import shutil

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
    try:
        with open(config, 'r', encoding='utf-8') as file:
            yf = yaml.load(file.read(), Loader=yaml.SafeLoader)
            
        # 检查配置文件格式
        if not yf or 'clusters' not in yf or not yf['clusters'] or 'users' not in yf or not yf['users']:
            raise ValueError("Invalid kubernetes config file format")
            
        return Config(
            server=yf['clusters'][0]['cluster']['server'],
            certificateAuthorityData=b64decode(yf['clusters'][0]['cluster']['certificate-authority-data']),
            clientCertificateData=b64decode(yf['users'][0]['user']['client-certificate-data']),
            clientKeyData=b64decode(yf['users'][0]['user']['client-key-data'])
        )
    except Exception as e:
        error(f"Failed to read kubernetes config: {str(e)}")
        raise


def rootCAs(certificateAuthorityData):
    return x509.load_pem_x509_csr(certificateAuthorityData, default_backend())


def tlsPaths(config):
    """
    生成证书文件路径
    :param config: 配置对象
    :return: (pem_path, ca_path, key_path)
    """
    try:
        return (
            tlsFile('pem', config.certificateAuthorityData),
            tlsFile('ca', config.clientCertificateData),
            tlsFile('key', config.clientKeyData)
        )
    except Exception as e:
        error(f"Failed to create TLS paths: {str(e)}")
        raise


def tlsFile(name, content):
    """
    在临时目录创建证书文件
    :param name: 证书文件名
    :param content: 证书内容
    :return: 证书文件路径
    """
    path = os.path.join(os.getcwd(), name)
    
    try:
        # 以追加模式打开文件（如果不存在则创建）
        with open(path, 'a+') as f:
            # 获取文件锁
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                # 检查现有内容
                f.seek(0)
                current_content = f.read()
                new_content = str(content, 'UTF-8')
                
                if current_content != new_content:
                    # 截断文件并写入新内容
                    f.seek(0)
                    f.truncate()
                    f.write(new_content)
            finally:
                # 释放文件锁
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        
        # 设置权限
        os.chmod(path, 0o600)
        return path
        
    except Exception as e:
        error(f"Failed to handle certificate file {name}: {str(e)}")
        raise


def recreate_tls_files(config_path='/etc/kubernetes/admin.conf'):
    """
    删除旧的ca、pem、key等文件，并根据config重新生成
    """
    # 1. 读取配置
    config = readConfig(config_path)
    # 2. 生成目标文件名
    files = [
        os.path.join(os.getcwd(), 'pem'),
        os.path.join(os.getcwd(), 'ca'),
        os.path.join(os.getcwd(), 'key')
    ]
    # 3. 删除旧文件
    for f in files:
        if os.path.exists(f):
            try:
                os.remove(f)
                debug(f"Deleted old TLS file: {f}")
            except Exception as e:
                error(f"Failed to delete {f}: {str(e)}")
    # 4. 重新生成
    pem_path, ca_path, key_path = tlsPaths(config)
    print(f"[DEBUG] TLS files: pem={pem_path}, ca={ca_path}, key={key_path}")
    return pem_path, ca_path, key_path
