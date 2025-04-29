'''
Copyright (2024, ) Institute of Software, Chinese Academy of Sciences

@author: liujiexin@otcaix.iscas.ac.cn

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

import logging
import sys
import os

class KubesysLogger:
    """Kubesys日志管理类"""
    
    def __init__(self, name="kubesys"):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.DEBUG)
        
        # 创建格式化器
        self._formatter = logging.Formatter(
            "%(asctime)s %(name)s %(lineno)s %(levelname)s %(message)s",
            "%Y-%m-%d %H:%M:%S"
        )
        
        # 默认添加控制台处理器
        self._setup_default_handler()
        
        # 避免日志重复
        self._logger.propagate = False
    
    def _setup_default_handler(self):
        """设置默认的控制台处理器"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(self._formatter)
        self._logger.addHandler(console_handler)
    
    def set_output(self, log_file=None, log_level=logging.DEBUG):
        """
        设置日志输出
        
        Args:
            log_file: 日志文件路径，如果为None则输出到控制台
            log_level: 日志级别，默认为DEBUG
        """
        # 清除现有的处理器
        for handler in self._logger.handlers[:]:
            self._logger.removeHandler(handler)
        
        # 设置日志级别
        self._logger.setLevel(log_level)
        
        if log_file:
            # 确保日志目录存在
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            # 创建文件处理器
            handler = logging.FileHandler(log_file)
        else:
            # 创建控制台处理器
            handler = logging.StreamHandler(sys.stdout)
        
        # 设置格式化器
        handler.setFormatter(self._formatter)
        self._logger.addHandler(handler)
    
    def debug(self, msg, *args, **kwargs):
        self._logger.debug(msg, *args, **kwargs)
    
    def info(self, msg, *args, **kwargs):
        self._logger.info(msg, *args, **kwargs)
    
    def warning(self, msg, *args, **kwargs):
        self._logger.warning(msg, *args, **kwargs)
    
    def error(self, msg, *args, **kwargs):
        self._logger.error(msg, *args, **kwargs)
    
    def critical(self, msg, *args, **kwargs):
        self._logger.critical(msg, *args, **kwargs)
    
    def get_logger(self):
        """兼容原有代码的获取logger方法"""
        return self

# 创建全局logger实例
logger = KubesysLogger()

# 为了兼容原有代码，导出常用的日志函数
debug = logger.debug
info = logger.info
warning = logger.warning
error = logger.error
critical = logger.critical

# 导出配置函数和logger实例
__all__ = ['logger', 'debug', 'info', 'warning', 'error', 'critical'] 