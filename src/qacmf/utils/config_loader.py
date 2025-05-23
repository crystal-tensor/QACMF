#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
配置加载和解析工具

该模块提供了加载、验证和解析QACMF框架配置文件的功能。
支持YAML和JSON格式的配置文件，并提供配置合并和环境变量覆盖功能。
"""

import os
import json
import yaml
from typing import Dict, Any, Optional, Union
import logging

logger = logging.getLogger(__name__)

class ConfigLoader:
    """配置加载器类，用于加载和解析QACMF框架的配置文件"""
    
    DEFAULT_CONFIG_PATHS = [
        "./config/default.yaml",
        "/etc/qacmf/config.yaml",
        os.path.expanduser("~/.qacmf/config.yaml")
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        """初始化配置加载器
        
        Args:
            config_path: 配置文件路径，如果为None，则按默认路径顺序查找
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        
    def load(self) -> Dict[str, Any]:
        """加载配置文件
        
        Returns:
            加载的配置字典
        
        Raises:
            FileNotFoundError: 当配置文件不存在时
            ValueError: 当配置文件格式错误时
        """
        if self.config_path:
            return self._load_from_path(self.config_path)
        
        # 按默认路径顺序查找配置文件
        for path in self.DEFAULT_CONFIG_PATHS:
            if os.path.exists(path):
                return self._load_from_path(path)
        
        raise FileNotFoundError(f"无法找到配置文件，已尝试路径: {self.DEFAULT_CONFIG_PATHS}")
    
    def _load_from_path(self, path: str) -> Dict[str, Any]:
        """从指定路径加载配置文件
        
        Args:
            path: 配置文件路径
            
        Returns:
            加载的配置字典
        """
        logger.info(f"从 {path} 加载配置")
        
        if not os.path.exists(path):
            raise FileNotFoundError(f"配置文件不存在: {path}")
        
        file_ext = os.path.splitext(path)[1].lower()
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                if file_ext in ('.yaml', '.yml'):
                    self.config = yaml.safe_load(f)
                elif file_ext == '.json':
                    self.config = json.load(f)
                else:
                    raise ValueError(f"不支持的配置文件格式: {file_ext}")
                    
            # 处理环境变量覆盖
            self._process_env_overrides()
            
            return self.config
        except Exception as e:
            logger.error(f"加载配置文件失败: {str(e)}")
            raise
    
    def _process_env_overrides(self):
        """处理环境变量覆盖配置
        
        环境变量格式: QACMF_SECTION_KEY=value
        例如: QACMF_MASTER_KEY_ROTATION_INTERVAL=30d
        """
        prefix = "QACMF_"
        for env_key, env_value in os.environ.items():
            if env_key.startswith(prefix):
                # 移除前缀并转换为小写
                key_path = env_key[len(prefix):].lower().split('_')
                
                # 递归设置配置值
                self._set_nested_config(self.config, key_path, env_value)
    
    def _set_nested_config(self, config: Dict[str, Any], key_path: list, value: str):
        """递归设置嵌套配置值
        
        Args:
            config: 配置字典
            key_path: 键路径列表
            value: 要设置的值
        """
        if len(key_path) == 1:
            # 尝试转换值类型
            config[key_path[0]] = self._convert_value_type(value)
        else:
            key = key_path[0]
            if key not in config:
                config[key] = {}
            self._set_nested_config(config[key], key_path[1:], value)
    
    @staticmethod
    def _convert_value_type(value: str) -> Union[str, int, float, bool]:
        """尝试将字符串值转换为适当的类型
        
        Args:
            value: 要转换的字符串值
            
        Returns:
            转换后的值
        """
        # 尝试转换为布尔值
        if value.lower() in ('true', 'yes', '1'):
            return True
        if value.lower() in ('false', 'no', '0'):
            return False
        
        # 尝试转换为整数
        try:
            return int(value)
        except ValueError:
            pass
        
        # 尝试转换为浮点数
        try:
            return float(value)
        except ValueError:
            pass
        
        # 保持为字符串
        return value
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值
        
        Args:
            key: 配置键，支持点号分隔的路径
            default: 默认值，当键不存在时返回
            
        Returns:
            配置值或默认值
        """
        if not self.config:
            self.load()
        
        # 处理点号分隔的路径
        parts = key.split('.')
        value = self.config
        
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        
        return value


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """加载配置的便捷函数
    
    Args:
        config_path: 配置文件路径，如果为None，则按默认路径顺序查找
        
    Returns:
        加载的配置字典
    """
    loader = ConfigLoader(config_path)
    return loader.load()