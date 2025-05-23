"""
Kyber-1024 插件包
"""

from .plugin import Kyber1024Plugin

__version__ = "1.0.0"
__author__ = "QACMF Team"
__description__ = "Kyber-1024 密钥封装机制 (KEM) 插件"

# 插件入口点
PLUGIN_CLASS = Kyber1024Plugin 