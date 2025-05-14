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
        self._formatter = logging.Formatter(
            "%(asctime)s %(filename)s:%(lineno)d %(levelname)s %(message)s",
            "%Y-%m-%d %H:%M:%S"
        )
        # 默认添加控制台处理器
        self._setup_default_handler()
        # 避免日志重复
        self._logger.propagate = False
        # 外部设置的logger
        self._external_logger = None

    def _setup_default_handler(self):
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(self._formatter)
        self._logger.addHandler(console_handler)

    def set_logger(self, external_logger):
        """设置外部logger，用于与uni-virt日志系统集成"""
        self._external_logger = external_logger
        return self

    def set_output(self, log_file=None, log_level=logging.DEBUG):
        """设置日志输出: 同时输出到控制台和文件（如指定）"""
        # 清除现有的处理器
        for handler in self._logger.handlers[:]:
            self._logger.removeHandler(handler)

        self._logger.setLevel(log_level)
        # 始终添加控制台处理器
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(self._formatter)
        self._logger.addHandler(console_handler)

        # 如果指定文件，也添加文件处理器
        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(self._formatter)
            self._logger.addHandler(file_handler)
        return self

    def _log(self, level, msg, *args, **kwargs):
        """内部日志记录方法，使用stacklevel保证正确调用源信息"""
        # 主logger记录
        self._logger.log(level, msg, *args, stacklevel=3, **kwargs)
        # 外部logger记录（如有）
        if self._external_logger:
            self._external_logger.log(level, msg, *args, stacklevel=3, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self._log(logging.DEBUG, msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self._log(logging.INFO, msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self._log(logging.WARNING, msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self._log(logging.ERROR, msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self._log(logging.CRITICAL, msg, *args, **kwargs)

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
