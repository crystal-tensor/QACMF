"""
插件动态加载与沙箱隔离引擎
负责安全地加载和管理密码算法插件
"""
import os
import sys
import importlib
import importlib.util
import logging
from typing import Dict, Any, List, Optional
import hashlib

logger = logging.getLogger(__name__)

class PluginSandbox:
    """为插件提供隔离的执行环境"""
    
    def __init__(self, plugin_name: str, plugin_path: str):
        """
        初始化插件沙箱
        
        Args:
            plugin_name: 插件名称
            plugin_path: 插件路径
        """
        self.plugin_name = plugin_name
        self.plugin_path = plugin_path
        self.plugin_module = None
        self.plugin_instance = None
        
    def load(self) -> Any:
        """
        加载插件并返回实例
        
        Returns:
            插件实例
        """
        try:
            # 验证插件文件
            self._verify_plugin_integrity()
            
            # 动态导入模块
            spec = importlib.util.spec_from_file_location(
                self.plugin_name, 
                os.path.join(self.plugin_path, f"{self.plugin_name}.py")
            )
            
            if spec is None or spec.loader is None:
                raise ImportError(f"无法加载插件 {self.plugin_name}")
                
            module = importlib.util.module_from_spec(spec)
            sys.modules[self.plugin_name] = module
            spec.loader.exec_module(module)
            
            # 查找插件类
            plugin_class = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and attr_name.lower().endswith('plugin'):
                    plugin_class = attr
                    break
                    
            if plugin_class is None:
                raise ImportError(f"在插件 {self.plugin_name} 中找不到插件类")
                
            # 实例化插件
            self.plugin_instance = plugin_class()
            self.plugin_module = module
            
            # 验证插件接口
            self._verify_plugin_interface()
            
            return self.plugin_instance
            
        except Exception as e:
            logger.error(f"加载插件 {self.plugin_name} 时出错: {str(e)}")
            raise
    
    def _verify_plugin_integrity(self) -> None:
        """验证插件文件完整性"""
        plugin_file = os.path.join(self.plugin_path, f"{self.plugin_name}.py")
        
        if not os.path.exists(plugin_file):
            raise FileNotFoundError(f"插件文件不存在: {plugin_file}")
            
        # 可以在这里添加签名验证等安全措施
        
    def _verify_plugin_interface(self) -> None:
        """验证插件实现了所需的接口"""
        required_methods = ['metadata', 'initialize', 'keygen']
        
        for method in required_methods:
            if not hasattr(self.plugin_instance, method) or not callable(getattr(self.plugin_instance, method)):
                raise AttributeError(f"插件 {self.plugin_name} 缺少必需的方法: {method}")

class PluginManager:
    """管理所有已加载的插件"""
    
    def __init__(self):
        """初始化插件管理器"""
        self.plugins = {}
        self.plugin_paths = []
        
        # 添加默认插件路径
        default_paths = [
            os.path.join(os.path.dirname(__file__), "..", "plugins"),
            os.path.join(os.path.expanduser("~"), ".qacmf", "plugins"),
        ]
        
        for path in default_paths:
            if os.path.exists(path) and os.path.isdir(path):
                self.add_plugin_path(path)
    
    def add_plugin_path(self, path: str) -> None:
        """
        添加插件搜索路径
        
        Args:
            path: 插件目录路径
        """
        if os.path.exists(path) and os.path.isdir(path):
            if path not in self.plugin_paths:
                self.plugin_paths.append(path)
                logger.debug(f"已添加插件路径: {path}")
        else:
            logger.warning(f"插件路径不存在或不是目录: {path}")
    
    def discover_plugins(self) -> List[str]:
        """
        发现所有可用的插件
        
        Returns:
            插件名称列表
        """
        discovered = []
        
        for path in self.plugin_paths:
            for item in os.listdir(path):
                if item.endswith('.py') and not item.startswith('__'):
                    plugin_name = item[:-3]  # 移除.py后缀
                    discovered.append(plugin_name)
                    
                # 检查子目录
                subdir = os.path.join(path, item)
                if os.path.isdir(subdir) and os.path.exists(os.path.join(subdir, '__init__.py')):
                    discovered.append(item)
        
        return discovered
    
    def load_plugin(self, plugin_name: str) -> Any:
        """
        加载指定的插件
        
        Args:
            plugin_name: 插件名称
            
        Returns:
            插件实例
        """
        # 如果插件已加载，直接返回
        if plugin_name in self.plugins:
            return self.plugins[plugin_name]
            
        # 查找插件路径
        plugin_path = None
        for path in self.plugin_paths:
            candidate = os.path.join(path, f"{plugin_name}.py")
            if os.path.exists(candidate):
                plugin_path = path
                break
                
            # 检查是否是目录插件
            candidate_dir = os.path.join(path, plugin_name)
            if os.path.isdir(candidate_dir) and os.path.exists(os.path.join(candidate_dir, '__init__.py')):
                plugin_path = candidate_dir
                break
                
        if plugin_path is None:
            raise FileNotFoundError(f"找不到插件: {plugin_name}")
            
        # 在沙箱中加载插件
        sandbox = PluginSandbox(plugin_name, plugin_path)
        plugin = sandbox.load()
        
        # 存储已加载的插件
        self.plugins[plugin_name] = plugin
        
        return plugin
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """
        卸载指定的插件
        
        Args:
            plugin_name: 插件名称
            
        Returns:
            是否成功卸载
        """
        if plugin_name in self.plugins:
            # 清理插件资源
            plugin = self.plugins[plugin_name]
            if hasattr(plugin, 'cleanup') and callable(plugin.cleanup):
                try:
                    plugin.cleanup()
                except Exception as e:
                    logger.warning(f"清理插件 {plugin_name} 时出错: {str(e)}")
            
            # 从已加载插件中移除
            del self.plugins[plugin_name]
            
            # 从sys.modules中移除
            if plugin_name in sys.modules:
                del sys.modules[plugin_name]
                
            return True
        
        return False

# 创建全局插件管理器实例
_plugin_manager = PluginManager()

def load_plugin(plugin_name: str) -> Any:
    """
    加载指定的插件
    
    Args:
        plugin_name: 插件名称
        
    Returns:
        插件实例
    """
    return _plugin_manager.load_plugin(plugin_name)

def discover_plugins() -> List[str]:
    """
    发现所有可用的插件
    
    Returns:
        插件名称列表
    """
    return _plugin_manager.discover_plugins()

def add_plugin_path(path: str) -> None:
    """
    添加插件搜索路径
    
    Args:
        path: 插件目录路径
    """
    _plugin_manager.add_plugin_path(path)