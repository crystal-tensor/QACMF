#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
安全相关工具

该模块提供了QACMF框架的安全相关功能，包括沙箱隔离、权限检查、
安全审计和资源限制等功能。
"""

import os
import sys
import time
import json
import logging
import resource
import subprocess
from typing import Dict, Any, List, Optional, Callable, Union, Tuple
import threading
import tempfile
import importlib.util
import inspect
from functools import wraps

logger = logging.getLogger(__name__)

class SecurityViolationError(Exception):
    """安全违规异常"""
    pass

class ResourceLimitExceededError(Exception):
    """资源限制超出异常"""
    pass

class PermissionDeniedError(Exception):
    """权限拒绝异常"""
    pass

# 安全审计事件类型
AUDIT_EVENT_TYPES = {
    'PLUGIN_LOAD': '插件加载',
    'KEY_GENERATION': '密钥生成',
    'KEY_ROTATION': '密钥轮换',
    'KEY_DESTRUCTION': '密钥销毁',
    'CONFIG_CHANGE': '配置变更',
    'AUTH_SUCCESS': '认证成功',
    'AUTH_FAILURE': '认证失败',
    'PERMISSION_DENIED': '权限拒绝',
    'SECURITY_VIOLATION': '安全违规',
}

def audit_log(event_type: str, details: Dict[str, Any], user: Optional[str] = None):
    """记录安全审计日志
    
    Args:
        event_type: 事件类型，应为AUDIT_EVENT_TYPES中的一个
        details: 事件详情
        user: 操作用户，如果为None则尝试获取当前用户
    
    Raises:
        ValueError: 当事件类型不在预定义列表中时
    """
    if event_type not in AUDIT_EVENT_TYPES:
        raise ValueError(f"未知的审计事件类型: {event_type}")
    
    if user is None:
        try:
            import getpass
            user = getpass.getuser()
        except:
            user = 'unknown'
    
    timestamp = time.time()
    formatted_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
    
    audit_entry = {
        'timestamp': timestamp,
        'formatted_time': formatted_time,
        'event_type': event_type,
        'event_name': AUDIT_EVENT_TYPES[event_type],
        'user': user,
        'details': details
    }
    
    # 记录到专用的审计日志
    logger.info(f"AUDIT: {json.dumps(audit_entry)}")
    
    # 对于严重的安全事件，同时记录警告日志
    if event_type in ['SECURITY_VIOLATION', 'AUTH_FAILURE', 'PERMISSION_DENIED']:
        logger.warning(f"安全事件: {event_type} - 用户: {user} - 详情: {details}")

def require_permission(permission: str):
    """权限检查装饰器
    
    Args:
        permission: 所需的权限名称
    
    Returns:
        装饰器函数
    
    Example:
        @require_permission('admin')
        def sensitive_operation():
            pass
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 获取当前用户和权限上下文
            # 实际实现中，这里应该从会话或请求中获取用户信息
            # 并检查用户是否具有所需权限
            
            # 示例实现，实际应用中需要替换为真实的权限检查逻辑
            from ..core.policy_engine import PolicyEngine
            policy_engine = PolicyEngine()
            
            if not policy_engine.check_permission(permission):
                details = {
                    'required_permission': permission,
                    'function': func.__name__,
                    'module': func.__module__
                }
                audit_log('PERMISSION_DENIED', details)
                raise PermissionDeniedError(f"缺少所需权限: {permission}")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

class Sandbox:
    """安全沙箱，用于隔离执行不受信任的代码"""
    
    def __init__(self, resource_limits: Optional[Dict[str, int]] = None):
        """初始化安全沙箱
        
        Args:
            resource_limits: 资源限制字典，键为资源名称，值为限制值
        """
        self.resource_limits = resource_limits or {
            'CPU_TIME': 5,  # 秒
            'MEMORY': 100 * 1024 * 1024,  # 字节 (100MB)
            'FILES': 10,  # 最大打开文件数
        }
    
    def _set_resource_limits(self):
        """设置进程资源限制"""
        # 设置CPU时间限制
        resource.setrlimit(resource.RLIMIT_CPU, 
                          (self.resource_limits.get('CPU_TIME', 5), 
                           self.resource_limits.get('CPU_TIME', 5)))
        
        # 设置内存限制
        resource.setrlimit(resource.RLIMIT_AS, 
                          (self.resource_limits.get('MEMORY', 100 * 1024 * 1024), 
                           self.resource_limits.get('MEMORY', 100 * 1024 * 1024)))
        
        # 设置打开文件数限制
        resource.setrlimit(resource.RLIMIT_NOFILE, 
                          (self.resource_limits.get('FILES', 10), 
                           self.resource_limits.get('FILES', 10)))
    
    def run_code(self, code: str, globals_dict: Optional[Dict[str, Any]] = None) -> Any:
        """在沙箱中执行Python代码
        
        Args:
            code: 要执行的Python代码字符串
            globals_dict: 全局变量字典
            
        Returns:
            代码执行的结果
            
        Raises:
            SecurityViolationError: 当代码尝试执行不允许的操作时
            ResourceLimitExceededError: 当代码超出资源限制时
        """
        if globals_dict is None:
            globals_dict = {}
        
        # 创建一个临时模块来执行代码
        temp_module_name = f"_qacmf_sandbox_{time.time()}_{id(self)}"
        temp_module = types.ModuleType(temp_module_name)
        
        # 设置安全的内置函数
        safe_builtins = self._get_safe_builtins()
        temp_module.__dict__.update(safe_builtins)
        temp_module.__dict__.update(globals_dict)
        
        # 在子进程中执行代码以隔离资源限制
        result_queue = multiprocessing.Queue()
        
        def target_func():
            try:
                # 设置资源限制
                self._set_resource_limits()
                
                # 编译并执行代码
                compiled_code = compile(code, '<string>', 'exec')
                exec(compiled_code, temp_module.__dict__)
                
                # 如果代码中定义了main函数，则调用它
                if 'main' in temp_module.__dict__ and callable(temp_module.__dict__['main']):
                    result = temp_module.__dict__['main']()
                    result_queue.put(('success', result))
                else:
                    result_queue.put(('success', None))
            except Exception as e:
                result_queue.put(('error', str(e)))
        
        process = multiprocessing.Process(target=target_func)
        process.start()
        
        # 等待进程完成或超时
        process.join(self.resource_limits.get('CPU_TIME', 5) + 1)
        
        # 如果进程仍在运行，则终止它
        if process.is_alive():
            process.terminate()
            process.join()
            raise ResourceLimitExceededError("代码执行超时")
        
        # 获取执行结果
        if not result_queue.empty():
            status, result = result_queue.get()
            if status == 'error':
                raise SecurityViolationError(f"代码执行错误: {result}")
            return result
        else:
            raise SecurityViolationError("代码执行失败，没有返回结果")
    
    def _get_safe_builtins(self) -> Dict[str, Any]:
        """获取安全的内置函数字典
        
        Returns:
            安全的内置函数字典
        """
        # 创建一个安全的内置函数子集
        safe_builtins = {}
        
        # 允许的内置函数列表
        allowed_builtins = [
            'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'bytearray', 'bytes',
            'callable', 'chr', 'complex', 'dict', 'divmod', 'enumerate', 'filter',
            'float', 'format', 'frozenset', 'hash', 'hex', 'int', 'isinstance',
            'issubclass', 'iter', 'len', 'list', 'map', 'max', 'min', 'next',
            'object', 'oct', 'ord', 'pow', 'print', 'range', 'repr', 'reversed',
            'round', 'set', 'slice', 'sorted', 'str', 'sum', 'tuple', 'type', 'zip'
        ]
        
        for name in allowed_builtins:
            if hasattr(builtins, name):
                safe_builtins[name] = getattr(builtins, name)
        
        return safe_builtins

def validate_file_path(path: str, allowed_dirs: List[str]) -> bool:
    """验证文件路径是否在允许的目录中
    
    Args:
        path: 要验证的文件路径
        allowed_dirs: 允许的目录列表
        
    Returns:
        如果路径在允许的目录中则为True，否则为False
    """
    abs_path = os.path.abspath(path)
    
    for allowed_dir in allowed_dirs:
        allowed_abs = os.path.abspath(allowed_dir)
        if abs_path.startswith(allowed_abs):
            return True
    
    return False

def secure_delete_file(path: str):
    """安全删除文件，覆盖文件内容后删除
    
    Args:
        path: 要删除的文件路径
        
    Raises:
        FileNotFoundError: 当文件不存在时
        PermissionError: 当没有权限删除文件时
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"文件不存在: {path}")
    
    if not os.path.isfile(path):
        raise ValueError(f"路径不是文件: {path}")
    
    # 获取文件大小
    file_size = os.path.getsize(path)
    
    # 使用随机数据覆盖文件内容
    with open(path, 'wb') as f:
        # 第一次用0覆盖
        f.seek(0)
        f.write(b'\x00' * file_size)
        f.flush()
        os.fsync(f.fileno())
        
        # 第二次用随机数据覆盖
        f.seek(0)
        f.write(os.urandom(file_size))
        f.flush()
        os.fsync(f.fileno())
        
        # 第三次用1覆盖
        f.seek(0)
        f.write(b'\xff' * file_size)
        f.flush()
        os.fsync(f.fileno())
    
    # 删除文件
    os.remove(path)

def check_file_integrity(path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
    """检查文件完整性
    
    Args:
        path: 文件路径
        expected_hash: 预期的哈希值
        algorithm: 哈希算法
        
    Returns:
        如果文件哈希值与预期相符则为True，否则为False
        
    Raises:
        FileNotFoundError: 当文件不存在时
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"文件不存在: {path}")
    
    # 计算文件哈希值
    hash_obj = getattr(hashlib, algorithm)()
    
    with open(path, 'rb') as f:
        # 分块读取文件以处理大文件
        chunk_size = 8192
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hash_obj.update(chunk)
    
    file_hash = hash_obj.hexdigest()
    
    # 比较哈希值
    return file_hash == expected_hash

def sanitize_input(input_str: str, allowed_pattern: str = r'[A-Za-z0-9_\-\.]') -> str:
    """清理输入字符串，只保留允许的字符
    
    Args:
        input_str: 输入字符串
        allowed_pattern: 允许的字符正则表达式模式
        
    Returns:
        清理后的字符串
    """
    import re
    return re.sub(f"[^{allowed_pattern}]", '', input_str)

def rate_limit(max_calls: int, time_period: int):
    """速率限制装饰器
    
    Args:
        max_calls: 时间段内允许的最大调用次数
        time_period: 时间段长度（秒）
        
    Returns:
        装饰器函数
    
    Example:
        @rate_limit(5, 60)  # 每60秒最多调用5次
        def api_function():
            pass
    """
    def decorator(func):
        # 使用线程锁保护计数器
        lock = threading.Lock()
        calls = []
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            with lock:
                # 清理过期的调用记录
                current_time = time.time()
                calls[:] = [call_time for call_time in calls if current_time - call_time <= time_period]
                
                # 检查是否超出速率限制
                if len(calls) >= max_calls:
                    raise ResourceLimitExceededError(
                        f"速率限制: 在{time_period}秒内最多允许{max_calls}次调用"
                    )
                
                # 记录当前调用
                calls.append(current_time)
            
            # 执行原函数
            return func(*args, **kwargs)
        
        return wrapper
    
    return decorator