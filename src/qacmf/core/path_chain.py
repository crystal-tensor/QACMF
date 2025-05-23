import hashlib
import hmac
import time
import logging
from typing import List, Dict, Any, Optional, Tuple

from ..utils.exceptions import PathVerificationError

logger = logging.getLogger(__name__)

class PathChain:
    """抗量子哈希链的生成与验证逻辑
    
    实现基于哈希链的密钥路径验证，确保密钥更新的连续性和完整性。
    """
    
    def __init__(self, initial_seed: bytes):
        """初始化路径链
        
        Args:
            initial_seed: 初始种子值
        """
        self.chain: List[bytes] = [initial_seed]
        self.timestamps: List[float] = [time.time()]
        self.metadata: List[Dict[str, Any]] = [{"operation": "initialize"}]
        
        logger.debug("路径链初始化成功")
    
    def extend(self, key1: bytes, key2: bytes, metadata: Optional[Dict[str, Any]] = None) -> bytes:
        """扩展路径链
        
        Args:
            key1: 第一个密钥（通常是子密钥1）
            key2: 第二个密钥（通常是子密钥2）
            metadata: 附加元数据
            
        Returns:
            bytes: 新的路径哈希
        """
        if not self.chain:
            raise PathVerificationError("路径链为空，无法扩展")
        
        # 获取最后一个路径哈希
        last_path = self.chain[-1]
        
        # 计算新的路径哈希
        new_path = self._compute_path_hash(last_path, key1, key2)
        
        # 添加到链中
        self.chain.append(new_path)
        self.timestamps.append(time.time())
        
        # 添加元数据
        meta = metadata or {}
        meta["operation"] = "extend"
        self.metadata.append(meta)
        
        logger.debug("路径链扩展成功")
        return new_path
    
    def _compute_path_hash(self, previous_path: bytes, key1: bytes, key2: bytes) -> bytes:
        """计算新的路径哈希
        
        Args:
            previous_path: 前一个路径哈希
            key1: 第一个密钥
            key2: 第二个密钥
            
        Returns:
            bytes: 新的路径哈希
        """
        # 使用SHA3-256计算哈希
        # 实际实现可以使用更抗量子的哈希算法
        combined = previous_path + key1 + key2
        return hashlib.sha3_256(combined).digest()
    
    def verify(self, path_hash: bytes, position: Optional[int] = None) -> bool:
        """验证路径哈希是否在链中
        
        Args:
            path_hash: 要验证的路径哈希
            position: 预期位置，如果为None则检查整个链
            
        Returns:
            bool: 是否验证通过
        """
        if position is not None:
            # 验证特定位置
            if position < 0 or position >= len(self.chain):
                return False
            return hmac.compare_digest(self.chain[position], path_hash)
        else:
            # 在整个链中查找
            for chain_hash in self.chain:
                if hmac.compare_digest(chain_hash, path_hash):
                    return True
            return False
    
    def verify_next(self, key1: bytes, key2: bytes, expected_path: bytes) -> bool:
        """验证下一个路径哈希是否正确
        
        Args:
            key1: 第一个密钥
            key2: 第二个密钥
            expected_path: 预期的路径哈希
            
        Returns:
            bool: 是否验证通过
        """
        if not self.chain:
            return False
        
        # 计算预期的下一个路径哈希
        last_path = self.chain[-1]
        computed_path = self._compute_path_hash(last_path, key1, key2)
        
        # 比较哈希值
        return hmac.compare_digest(computed_path, expected_path)
    
    def get_latest_path(self) -> bytes:
        """获取最新的路径哈希
        
        Returns:
            bytes: 最新的路径哈希
        """
        if not self.chain:
            raise PathVerificationError("路径链为空")
        
        return self.chain[-1]
    
    def get_path_at(self, position: int) -> bytes:
        """获取指定位置的路径哈希
        
        Args:
            position: 位置索引
            
        Returns:
            bytes: 路径哈希
        """
        if position < 0 or position >= len(self.chain):
            raise IndexError(f"位置 {position} 超出路径链范围")
        
        return self.chain[position]
    
    def get_chain_length(self) -> int:
        """获取路径链长度
        
        Returns:
            int: 路径链长度
        """
        return len(self.chain)
    
    def export_chain(self, include_metadata: bool = False) -> List[Dict[str, Any]]:
        """导出路径链
        
        Args:
            include_metadata: 是否包含元数据
            
        Returns:
            List[Dict[str, Any]]: 路径链数据
        """
        result = []
        
        for i, path_hash in enumerate(self.chain):
            entry = {
                "position": i,
                "hash": path_hash.hex(),
                "timestamp": self.timestamps[i]
            }
            
            if include_metadata and i < len(self.metadata):
                entry["metadata"] = self.metadata[i]
            
            result.append(entry)