#!/usr/bin/env python3
"""
TLS握手集成测试
测试混合TLS握手协议的完整流程
"""

import unittest
import asyncio
import tempfile
import shutil
from unittest.mock import Mock, patch
import time

from qacmf.adapters.tls_adapter import TLSAdapter
from qacmf.core.key_manager import KeyManager
from qacmf.plugins.kyber_plugin import Kyber1024Plugin
from qacmf.plugins.dilithium_plugin import Dilithium5Plugin


class TestTLSHandshake(unittest.TestCase):
    """TLS握手集成测试类"""

    def setUp(self):
        """测试前置设置"""
        self.temp_dir = tempfile.mkdtemp()
        self.key_manager = KeyManager(storage_path=self.temp_dir)
        self.tls_adapter = TLSAdapter()
        
        # 初始化插件
        self.kyber_plugin = Kyber1024Plugin()
        self.dilithium_plugin = Dilithium5Plugin()

    def tearDown(self):
        """测试后清理"""
        shutil.rmtree(self.temp_dir)

    def test_hybrid_tls_handshake(self):
        """测试混合TLS握手成功率与性能基线"""
        start_time = time.time()
        
        # 生成密钥对
        kyber_public, kyber_private = self.kyber_plugin.generate_keypair()
        dilithium_public, dilithium_private = self.dilithium_plugin.generate_keypair()
        
        # 模拟握手过程
        # 1. 密钥封装
        ciphertext, shared_secret = self.kyber_plugin.encapsulate(kyber_public)
        
        # 2. 密钥解封装
        recovered_secret = self.kyber_plugin.decapsulate(kyber_private, ciphertext)
        
        # 3. 验证共享密钥一致性
        self.assertEqual(shared_secret, recovered_secret)
        
        # 4. 签名验证
        message = b"TLS handshake verification"
        signature = self.dilithium_plugin.sign(message, dilithium_private)
        
        verification_result = self.dilithium_plugin.verify(
            message, signature, dilithium_public
        )
        self.assertTrue(verification_result)
        
        # 性能验证
        handshake_time = time.time() - start_time
        self.assertLess(handshake_time, 0.2)  # 小于200ms
        
        print(f"握手完成时间: {handshake_time*1000:.2f}ms")

    def test_tls_cipher_suite_negotiation(self):
        """测试TLS密码套件协商"""
        # 支持的密码套件
        supported_suites = [
            "TLS_KYBER_AES256_SHA384",
            "TLS_DILITHIUM_AES256_SHA384",
            "TLS_HYBRID_AES256_SHA384"
        ]
        
        # 客户端首选套件
        client_preference = ["TLS_KYBER_AES256_SHA384"]
        
        # 协商结果
        negotiated_suite = self.tls_adapter.negotiate_cipher_suite(
            client_preference, supported_suites
        )
        
        self.assertEqual(negotiated_suite, "TLS_KYBER_AES256_SHA384")

    def test_key_exchange_performance(self):
        """测试密钥交换性能"""
        iterations = 10
        total_time = 0
        
        for _ in range(iterations):
            start = time.time()
            
            # 生成密钥对
            public_key, private_key = self.kyber_plugin.generate_keypair()
            
            # 密钥封装
            ciphertext, shared_secret = self.kyber_plugin.encapsulate(public_key)
            
            # 密钥解封装
            recovered_secret = self.kyber_plugin.decapsulate(private_key, ciphertext)
            
            total_time += time.time() - start
            
            # 验证正确性
            self.assertEqual(shared_secret, recovered_secret)
        
        avg_time = total_time / iterations
        print(f"平均密钥交换时间: {avg_time*1000:.2f}ms")
        
        # 性能要求：平均时间小于50ms
        self.assertLess(avg_time, 0.05)

    def test_signature_performance(self):
        """测试数字签名性能"""
        iterations = 5
        message = b"Performance test message"
        
        # 生成密钥对
        public_key, private_key = self.dilithium_plugin.generate_keypair()
        
        # 签名性能测试
        sign_times = []
        verify_times = []
        
        for _ in range(iterations):
            # 签名
            start = time.time()
            signature = self.dilithium_plugin.sign(message, private_key)
            sign_times.append(time.time() - start)
            
            # 验证
            start = time.time()
            result = self.dilithium_plugin.verify(message, signature, public_key)
            verify_times.append(time.time() - start)
            
            self.assertTrue(result)
        
        avg_sign_time = sum(sign_times) / len(sign_times)
        avg_verify_time = sum(verify_times) / len(verify_times)
        
        print(f"平均签名时间: {avg_sign_time*1000:.2f}ms")
        print(f"平均验证时间: {avg_verify_time*1000:.2f}ms")
        
        # 性能要求
        self.assertLess(avg_sign_time, 0.1)   # 签名小于100ms
        self.assertLess(avg_verify_time, 0.05) # 验证小于50ms

    def test_session_key_derivation(self):
        """测试会话密钥派生"""
        shared_secret = b"shared_secret_for_testing"
        
        # 派生多个会话密钥
        client_key = self.tls_adapter.derive_session_key(
            shared_secret, b"client", b"session_key"
        )
        server_key = self.tls_adapter.derive_session_key(
            shared_secret, b"server", b"session_key"
        )
        
        # 验证密钥长度
        self.assertEqual(len(client_key), 32)  # 256位
        self.assertEqual(len(server_key), 32)  # 256位
        
        # 验证密钥不同
        self.assertNotEqual(client_key, server_key)
        
        # 验证派生的确定性
        client_key2 = self.tls_adapter.derive_session_key(
            shared_secret, b"client", b"session_key"
        )
        self.assertEqual(client_key, client_key2)

    def test_protocol_version_compatibility(self):
        """测试协议版本兼容性"""
        supported_versions = ["TLS1.3", "TLS1.2+PQ"]
        
        # 测试版本协商
        for version in supported_versions:
            result = self.tls_adapter.supports_version(version)
            if version in ["TLS1.3", "TLS1.2+PQ"]:
                self.assertTrue(result)
            else:
                self.assertFalse(result)

    def test_handshake_failure_recovery(self):
        """测试握手失败恢复机制"""
        # 模拟损坏的密文
        public_key, private_key = self.kyber_plugin.generate_keypair()
        _, shared_secret = self.kyber_plugin.encapsulate(public_key)
        
        # 创建损坏的密文
        corrupted_ciphertext = bytearray(1568)  # Kyber-1024密文长度
        corrupted_ciphertext[0] = 0xFF  # 损坏第一个字节
        
        # 尝试解封装应该失败
        with self.assertRaises(Exception):
            self.kyber_plugin.decapsulate(private_key, bytes(corrupted_ciphertext))

    def test_concurrent_handshakes(self):
        """测试并发握手处理"""
        async def perform_handshake():
            # 生成密钥对
            public_key, private_key = self.kyber_plugin.generate_keypair()
            
            # 执行密钥交换
            ciphertext, shared_secret = self.kyber_plugin.encapsulate(public_key)
            recovered_secret = self.kyber_plugin.decapsulate(private_key, ciphertext)
            
            return shared_secret == recovered_secret
        
        async def run_concurrent_test():
            # 并发执行多个握手
            tasks = [perform_handshake() for _ in range(5)]
            results = await asyncio.gather(*tasks)
            
            # 验证所有握手都成功
            self.assertTrue(all(results))
        
        # 运行异步测试
        asyncio.run(run_concurrent_test())

    def test_memory_usage(self):
        """测试内存使用情况"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # 执行多次握手操作
        for _ in range(100):
            public_key, private_key = self.kyber_plugin.generate_keypair()
            ciphertext, shared_secret = self.kyber_plugin.encapsulate(public_key)
            recovered_secret = self.kyber_plugin.decapsulate(private_key, ciphertext)
            
            del public_key, private_key, ciphertext, shared_secret, recovered_secret
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        print(f"内存增长: {memory_increase / 1024 / 1024:.2f} MB")
        
        # 内存增长应该在合理范围内（小于100MB）
        self.assertLess(memory_increase, 100 * 1024 * 1024)


class TestTLSAdapterIntegration(unittest.TestCase):
    """TLS适配器集成测试"""

    def setUp(self):
        """测试前置设置"""
        self.tls_adapter = TLSAdapter()

    def test_extension_handling(self):
        """测试TLS扩展处理"""
        # Kyber公钥扩展
        kyber_plugin = Kyber1024Plugin()
        public_key, _ = kyber_plugin.generate_keypair()
        
        extension = self.tls_adapter.create_kyber_extension(public_key)
        
        # 验证扩展格式
        self.assertEqual(extension[:2], b'\xFF\x01')  # 扩展类型
        
        # 解析扩展
        parsed_key = self.tls_adapter.parse_kyber_extension(extension)
        self.assertEqual(parsed_key, public_key)

    def test_record_layer_processing(self):
        """测试记录层处理"""
        test_data = b"Hello, TLS!"
        session_key = b"0" * 32  # 模拟会话密钥
        
        # 加密
        encrypted_record = self.tls_adapter.encrypt_record(test_data, session_key)
        
        # 解密
        decrypted_data = self.tls_adapter.decrypt_record(encrypted_record, session_key)
        
        self.assertEqual(test_data, decrypted_data)

    def test_alert_handling(self):
        """测试告警处理"""
        # 测试各种告警类型
        alert_types = [
            "close_notify",
            "unexpected_message",
            "bad_record_mac",
            "handshake_failure"
        ]
        
        for alert_type in alert_types:
            alert = self.tls_adapter.create_alert(alert_type)
            self.assertIsNotNone(alert)
            
            parsed_type = self.tls_adapter.parse_alert(alert)
            self.assertEqual(parsed_type, alert_type)


if __name__ == '__main__':
    unittest.main() 