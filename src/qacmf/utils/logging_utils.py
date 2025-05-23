#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
日志记录工具

该模块提供了QACMF框架的日志记录功能，支持多种日志输出方式和日志级别控制。
包含日志格式化、日志轮转和敏感信息过滤等功能。
"""

import os
import sys
import logging
import logging.handlers
from typing import Optional, Dict, Any, List
import json
from datetime import datetime

# 默认日志格式
DEFAULT_LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] - %(message)s"

# 敏感字段列表，这些字段的值在日志中会被掩码处理
SENSITIVE_FIELDS = [
    "password", "secret", "token", "key", "private", "credential",
    "auth", "signature", "cert", "certificate"
]

class SensitiveFilter(logging.Filter):
    """敏感信息过滤器，用于在日志中掩码敏感信息"""
    
    def __init__(self, sensitive_fields: Optional[List[str]] = None):
        """初始化敏感信息过滤器
        
        Args:
            sensitive_fields: 敏感字段列表，如果为None则使用默认列表
        """
        super().__init__()
        self.sensitive_fields = sensitive_fields or SENSITIVE_FIELDS
    
    def filter(self, record):
        """过滤日志记录
        
        Args:
            record: 日志记录对象
            
        Returns:
            True表示保留该记录，False表示丢弃
        """
        if isinstance(record.msg, str):
            for field in self.sensitive_fields:
                # 查找类似 field=value 或 "field": "value" 的模式
                patterns = [
                    f"{field}=\"([^\"]+)\"",  # field="value"
                    f"{field}='([^']+)'",      # field='value'
                    f"\"{field}\":\s*\"([^\"]+)\"",  # "field": "value"
                    f"'{field}':\s*'([^']+)'",      # 'field': 'value'
                    f"{field}=([^\s,;]+)"     # field=value
                ]
                
                for pattern in patterns:
                    import re
                    record.msg = re.sub(pattern, f"{field}=****", record.msg)
        
        return True

class QACMFLogger:
    """QACMF框架日志记录器"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化日志记录器
        
        Args:
            config: 日志配置字典，如果为None则使用默认配置
        """
        self.config = config or {}
        self.loggers = {}
    
    def get_logger(self, name: str) -> logging.Logger:
        """获取指定名称的日志记录器
        
        Args:
            name: 日志记录器名称
            
        Returns:
            日志记录器对象
        """
        if name in self.loggers:
            return self.loggers[name]
        
        logger = logging.getLogger(name)
        
        # 如果已经配置过处理器，则直接返回
        if logger.handlers:
            self.loggers[name] = logger
            return logger
        
        # 配置日志级别
        log_level = self._get_config_value('level', 'INFO')
        logger.setLevel(getattr(logging, log_level.upper()))
        
        # 添加控制台处理器
        if self._get_config_value('console_output', True):
            self._add_console_handler(logger)
        
        # 添加文件处理器
        if self._get_config_value('file_output', False):
            self._add_file_handler(logger)
        
        # 添加敏感信息过滤器
        sensitive_fields = self._get_config_value('sensitive_fields', SENSITIVE_FIELDS)
        logger.addFilter(SensitiveFilter(sensitive_fields))
        
        # 禁止传播到根日志记录器
        logger.propagate = False
        
        self.loggers[name] = logger
        return logger
    
    def _get_config_value(self, key: str, default: Any) -> Any:
        """从配置中获取值
        
        Args:
            key: 配置键
            default: 默认值
            
        Returns:
            配置值或默认值
        """
        return self.config.get(key, default)
    
    def _add_console_handler(self, logger: logging.Logger):
        """添加控制台处理器
        
        Args:
            logger: 日志记录器对象
        """
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, self._get_config_value('console_level', 'INFO').upper()))
        
        # 设置格式化器
        formatter = logging.Formatter(self._get_config_value('format', DEFAULT_LOG_FORMAT))
        console_handler.setFormatter(formatter)
        
        logger.addHandler(console_handler)
    
    def _add_file_handler(self, logger: logging.Logger):
        """添加文件处理器
        
        Args:
            logger: 日志记录器对象
        """
        log_dir = self._get_config_value('log_dir', './logs')
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, f"qacmf_{datetime.now().strftime('%Y%m%d')}.log")
        max_bytes = self._get_config_value('max_bytes', 10 * 1024 * 1024)  # 默认10MB
        backup_count = self._get_config_value('backup_count', 5)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8'
        )
        file_handler.setLevel(getattr(logging, self._get_config_value('file_level', 'DEBUG').upper()))
        
        # 设置格式化器
        formatter = logging.Formatter(self._get_config_value('format', DEFAULT_LOG_FORMAT))
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)

# 全局日志记录器实例
_logger_instance = None

def setup_logging(config: Optional[Dict[str, Any]] = None):
    """设置全局日志配置
    
    Args:
        config: 日志配置字典
    """
    global _logger_instance
    _logger_instance = QACMFLogger(config)
    
    # 配置根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.WARNING)  # 默认只显示警告及以上级别
    
    # 清除现有处理器
    for handler in root_logger.handlers[:]:  
        root_logger.removeHandler(handler)
    
    # 添加控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    formatter = logging.Formatter(DEFAULT_LOG_FORMAT)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

def get_logger(name: str) -> logging.Logger:
    """获取指定名称的日志记录器
    
    Args:
        name: 日志记录器名称
        
    Returns:
        日志记录器对象
    """
    global _logger_instance
    if _logger_instance is None:
        setup_logging()
    
    return _logger_instance.get_logger(name)