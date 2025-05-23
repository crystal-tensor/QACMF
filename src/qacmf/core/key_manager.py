"""
多级密钥生命周期管理模块
负责密钥的生成、存储、轮换和销毁
"""
import os
import time
import logging
from typing import Dict, Tuple, Optional, Any
from datetime import datetime, timedelta

from ..utils.secure_storage import SecureStorage
from ..utils.config_manager import ConfigManager

logger = logging.getLogger(__name__)

class KeyManager:
    """多级密钥管理器，实现密钥的全生命周期管理"""
    
    def __init__(self, config_path: str = None):
        """
        初始化密钥管理器
        
        Args:
            config_path: 配置文件路径，默认使用系统配置
        """
        self.config = ConfigManager(config_path).get_config()
        self.storage = SecureStorage(self.config.get("storage", {}))
        self._initialize_key_layers()
        
    def _initialize_key_layers(self) -> None:
        """初始化密钥层次结构"""
        self.key_layers = self.config.get("algorithm_layers", {})
        for layer_name, layer_config in self.key_layers.items():
            if not self.storage.key_exists(layer_name):
                logger.info(f"正在为层 {layer_name} 生成新密钥")
                self._generate_key_for_layer(layer_name, layer_config)
    
    def _generate_key_for_layer(self, layer_name: str, layer_config: Dict) -> None:
        """
        为指定层生成密钥
        
        Args:
            layer_name: 层名称
            layer_config: 层配置
        """
        plugin_name = layer_config.get("plugin")
        if not plugin_name:
            raise ValueError(f"层 {layer_name} 未指定插件")
            
        from ..plugins import plugin_loader
        plugin = plugin_loader.load_plugin(plugin_name)
        
        # 生成密钥
        security_level = layer_config.get("security_level", 3)  # 默认安全级别
        public_key, private_key = plugin.keygen(security_level)
        
        # 计算下次轮换时间
        rotation_interval = layer_config.get("rotation_interval", "90d")
        next_rotation = self._calculate_next_rotation(rotation_interval)
        
        # 存储密钥和元数据
        key_metadata = {
            "created_at": datetime.now().isoformat(),
            "next_rotation": next_rotation.isoformat(),
            "plugin": plugin_name,
            "version": 1,
            "security_level": security_level
        }
        
        self.storage.store_key(layer_name, private_key, public_key, key_metadata)
        logger.info(f"已为层 {layer_name} 生成新密钥，下次轮换时间: {next_rotation}")
    
    def _calculate_next_rotation(self, interval_str: str) -> datetime:
        """
        计算下次密钥轮换时间
        
        Args:
            interval_str: 轮换间隔字符串，如 "90d", "6m", "1y"
            
        Returns:
            下次轮换的日期时间
        """
        now = datetime.now()
        unit = interval_str[-1]
        value = int(interval_str[:-1])
        
        if unit == 'd':
            return now + timedelta(days=value)
        elif unit == 'm':
            return now + timedelta(days=value*30)  # 简化处理
        elif unit == 'y':
            return now + timedelta(days=value*365)
        else:
            raise ValueError(f"不支持的时间间隔单位: {unit}")
    
    def get_key(self, layer_name: str) -> Tuple[bytes, bytes, Dict]:
        """
        获取指定层的密钥
        
        Args:
            layer_name: 层名称
            
        Returns:
            (私钥, 公钥, 元数据)元组
        """
        if not self.storage.key_exists(layer_name):
            raise KeyError(f"密钥层 {layer_name} 不存在")
            
        private_key, public_key, metadata = self.storage.retrieve_key(layer_name)
        
        # 检查是否需要轮换
        if self._should_rotate(metadata):
            logger.info(f"密钥 {layer_name} 需要轮换")
            self._rotate_key(layer_name)
            private_key, public_key, metadata = self.storage.retrieve_key(layer_name)
            
        return private_key, public_key, metadata
    
    def _should_rotate(self, metadata: Dict) -> bool:
        """
        检查密钥是否需要轮换
        
        Args:
            metadata: 密钥元数据
            
        Returns:
            如果需要轮换返回True，否则返回False
        """
        if "next_rotation" not in metadata:
            return False
            
        next_rotation = datetime.fromisoformat(metadata["next_rotation"])
        return datetime.now() >= next_rotation
    
    def _rotate_key(self, layer_name: str) -> None:
        """
        轮换指定层的密钥
        
        Args:
            layer_name: 层名称
        """
        layer_config = self.key_layers.get(layer_name, {})
        
        # 保存旧密钥用于过渡
        old_private, old_public, old_metadata = self.storage.retrieve_key(layer_name)
        old_version = old_metadata.get("version", 1)
        
        # 生成新密钥
        self._generate_key_for_layer(layer_name, layer_config)
        
        # 更新新密钥的版本号
        new_private, new_public, new_metadata = self.storage.retrieve_key(layer_name)
        new_metadata["version"] = old_version + 1
        new_metadata["previous_version"] = old_version
        
        # 存储更新后的元数据
        self.storage.update_key_metadata(layer_name, new_metadata)
        
        # 存储旧密钥用于过渡期
        archive_name = f"{layer_name}_v{old_version}"
        self.storage.store_key(archive_name, old_private, old_public, old_metadata)
        
        logger.info(f"已轮换密钥 {layer_name}，新版本: {old_version + 1}，旧版本已存档为 {archive_name}")
    
    def secure_erase(self, key_name: str) -> bool:
        """
        安全擦除密钥
        
        Args:
            key_name: 密钥名称
            
        Returns:
            操作是否成功
        """
        if not self.storage.key_exists(key_name):
            logger.warning(f"尝试擦除不存在的密钥: {key_name}")
            return False
            
        # 获取密钥数据进行覆盖
        private_key, public_key, _ = self.storage.retrieve_key(key_name)
        
        # 多次覆盖私钥内存
        for _ in range(3):
            if private_key:
                random_data = os.urandom(len(private_key))
                for i in range(len(private_key)):
                    if isinstance(private_key, bytearray):
                        private_key[i] = random_data[i]
                    else:
                        # 如果是不可变bytes，创建新的bytearray
                        private_key = bytearray(random_data)
                        break
        
        # 从存储中删除
        result = self.storage.delete_key(key_name)
        logger.info(f"已安全擦除密钥: {key_name}")
        
        return result