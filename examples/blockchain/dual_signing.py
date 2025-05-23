#!/usr/bin/env python3
"""
区块链双签名示例
展示如何在区块链环境中使用QACMF框架实现抗量子和传统签名的混合模式
"""

import hashlib
import json
import time
from typing import Dict, Any, Tuple, Optional
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class QuantumSafeTransaction:
    """抗量子安全的区块链交易"""
    
    def __init__(self):
        # 生成密钥对
        self._setup_keys()
    
    def _setup_keys(self):
        """设置密钥对"""
        logger.info("生成双签名密钥对...")
        
        # 模拟生成密钥对
        import secrets
        self.pq_private_key = secrets.token_bytes(64)
        self.pq_public_key = hashlib.sha256(self.pq_private_key + b'pq_public').digest()
        
        self.ecdsa_private_key = secrets.token_bytes(32)
        self.ecdsa_public_key = hashlib.sha256(self.ecdsa_private_key + b'ecdsa_public').digest()
        
        logger.info(f"后量子公钥长度: {len(self.pq_public_key)} 字节")
        logger.info(f"ECDSA公钥长度: {len(self.ecdsa_public_key)} 字节")
    
    def build_transaction(self, from_address: str, to_address: str, 
                         amount: float, gas_limit: int = 21000) -> Dict[str, Any]:
        """构造区块链交易"""
        transaction = {
            "version": "2.0",
            "timestamp": int(time.time()),
            "from": from_address,
            "to": to_address,
            "amount": amount,
            "gas_limit": gas_limit,
            "nonce": self._get_nonce(from_address),
            "quantum_safe": True,
            "signature_version": "dual-v1"
        }
        
        logger.info(f"构造交易: {from_address} -> {to_address}, 金额: {amount}")
        return transaction
    
    def _get_nonce(self, address: str) -> int:
        """获取地址的nonce值 (模拟)"""
        return int(hashlib.sha256(address.encode()).hexdigest()[:8], 16) % 1000
    
    def calculate_transaction_hash(self, transaction: Dict[str, Any]) -> bytes:
        """计算交易哈希"""
        tx_without_signatures = {k: v for k, v in transaction.items() 
                               if k not in ['pq_signature', 'ecdsa_signature']}
        
        tx_json = json.dumps(tx_without_signatures, sort_keys=True, separators=(',', ':'))
        return hashlib.sha3_256(tx_json.encode()).digest()
    
    def sign_with_dilithium(self, transaction: Dict[str, Any]) -> bytes:
        """使用后量子算法签名"""
        tx_hash = self.calculate_transaction_hash(transaction)
        logger.info(f"使用后量子算法签名交易哈希: {tx_hash.hex()[:16]}...")
        
        # 模拟后量子签名
        import hmac
        signature = hmac.new(self.pq_private_key, tx_hash, hashlib.sha3_256).digest()
        
        logger.info(f"后量子签名长度: {len(signature)} 字节")
        return signature
    
    def sign_with_ecdsa(self, transaction: Dict[str, Any]) -> bytes:
        """使用ECDSA签名"""
        tx_hash = self.calculate_transaction_hash(transaction)
        logger.info(f"使用ECDSA签名交易哈希: {tx_hash.hex()[:16]}...")
        
        # 模拟ECDSA签名
        import hmac
        signature = hmac.new(self.ecdsa_private_key, tx_hash, hashlib.sha256).digest()
        
        logger.info(f"ECDSA签名长度: {len(signature)} 字节")
        return signature
    
    def create_dual_signature(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """创建双签名交易"""
        logger.info("创建双签名交易...")
        
        pq_signature = self.sign_with_dilithium(transaction)
        ecdsa_signature = self.sign_with_ecdsa(transaction)
        
        signed_transaction = transaction.copy()
        signed_transaction["pq_signature"] = pq_signature.hex()
        signed_transaction["ecdsa_signature"] = ecdsa_signature.hex()
        signed_transaction["pq_public_key"] = self.pq_public_key.hex()
        signed_transaction["ecdsa_public_key"] = self.ecdsa_public_key.hex()
        
        final_hash = self.calculate_transaction_hash(signed_transaction)
        signed_transaction["transaction_hash"] = final_hash.hex()
        
        logger.info(f"双签名交易创建完成，交易哈希: {final_hash.hex()}")
        return signed_transaction
    
    def verify_dual_signature(self, signed_transaction: Dict[str, Any]) -> bool:
        """验证双签名"""
        logger.info("验证双签名交易...")
        
        try:
            pq_signature = bytes.fromhex(signed_transaction["pq_signature"])
            ecdsa_signature = bytes.fromhex(signed_transaction["ecdsa_signature"])
            pq_public_key = bytes.fromhex(signed_transaction["pq_public_key"])
            ecdsa_public_key = bytes.fromhex(signed_transaction["ecdsa_public_key"])
            
            tx_hash = self.calculate_transaction_hash(signed_transaction)
            
            # 验证后量子签名
            import hmac
            expected_pq_sig = hmac.new(
                hashlib.sha256(pq_public_key + b'pq_private').digest(),
                tx_hash, hashlib.sha3_256
            ).digest()
            pq_valid = hmac.compare_digest(pq_signature, expected_pq_sig)
            
            # 验证ECDSA签名
            expected_ecdsa_sig = hmac.new(
                hashlib.sha256(ecdsa_public_key + b'ecdsa_private').digest(),
                tx_hash, hashlib.sha256
            ).digest()
            ecdsa_valid = hmac.compare_digest(ecdsa_signature, expected_ecdsa_sig)
            
            logger.info(f"后量子签名验证: {'通过' if pq_valid else '失败'}")
            logger.info(f"ECDSA签名验证: {'通过' if ecdsa_valid else '失败'}")
            
            result = pq_valid and ecdsa_valid
            logger.info(f"双签名验证结果: {'通过' if result else '失败'}")
            
            return result
            
        except Exception as e:
            logger.error(f"签名验证错误: {e}")
            return False
    
    def broadcast_transaction(self, signed_transaction: Dict[str, Any]) -> bool:
        """广播交易到区块链网络"""
        logger.info("广播交易到区块链网络...")
        
        if not self.verify_dual_signature(signed_transaction):
            logger.error("交易验证失败，拒绝广播")
            return False
        
        tx_size = len(json.dumps(signed_transaction))
        logger.info(f"交易大小: {tx_size} 字节")
        logger.info(f"交易哈希: {signed_transaction['transaction_hash']}")
        logger.info("交易已成功广播到网络")
        
        return True


def run_demo():
    """运行演示"""
    logger.info("=== 区块链双签名演示开始 ===")
    
    quantum_tx = QuantumSafeTransaction()
    
    # 创建交易
    tx = quantum_tx.build_transaction(
        from_address="0x1234567890abcdef1234567890abcdef12345678",
        to_address="0xfedcba0987654321fedcba0987654321fedcba09",
        amount=1.5
    )
    
    # 创建双签名
    signed_tx = quantum_tx.create_dual_signature(tx)
    
    # 验证并广播
    verification_result = quantum_tx.verify_dual_signature(signed_tx)
    broadcast_result = quantum_tx.broadcast_transaction(signed_tx)
    
    logger.info(f"验证结果: {'成功' if verification_result else '失败'}")
    logger.info(f"广播结果: {'成功' if broadcast_result else '失败'}")
    logger.info("=== 演示完成 ===")


if __name__ == "__main__":
    run_demo()