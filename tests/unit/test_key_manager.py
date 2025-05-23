#!/usr/bin/env python3
"""
密钥管理器单元测试
测试多级密钥管理、密钥轮换、生命周期管理等功能
"""

import unittest
import tempfile
import shutil
import os
from unittest.mock import Mock, patch, MagicMock
import time

from qacmf.core.key_manager import KeyManager, KeyMetadata, KeyStatus
from qacmf.core.plugin_base import PluginType


class TestKeyManager(unittest.TestCase):
    """密钥管理器测试类"""

    def setUp(self):
        """测试前置设置"""
        self.temp_dir = tempfile.mkdtemp()
        self.key_manager = KeyManager(storage_path=self.temp_dir)
        
        # 模拟插件
        self.mock_plugin = Mock()
        self.mock_plugin.generate_keypair.return_value = (b'public_key', b'private_key')
        self.mock_plugin.metadata.return_value = {
            'name': 'test_plugin',
            'type': 'kem',
            'key_sizes': {'public_key': 32, 'private_key': 64}
        }

    def tearDown(self):
        """测试后清理"""
        shutil.rmtree(self.temp_dir)

    def test_generate_master_key(self):
        """测试主密钥生成"""
        master_key_id = self.key_manager.generate_master_key(
            algorithm='kyber-1024',
            security_level=5
        )
        
        self.assertIsNotNone(master_key_id)
        self.assertTrue(self.key_manager.key_exists(master_key_id))
        
        # 验证密钥元数据
        metadata = self.key_manager.get_key_metadata(master_key_id)
        self.assertEqual(metadata.key_type, 'master')
        self.assertEqual(metadata.algorithm, 'kyber-1024')
        self.assertEqual(metadata.security_level, 5)
        self.assertEqual(metadata.status, KeyStatus.ACTIVE)

    def test_derive_subkey(self):
        """测试子密钥派生"""
        # 先生成主密钥
        master_key_id = self.key_manager.generate_master_key(
            algorithm='kyber-1024',
            security_level=5
        )
        
        # 派生子密钥
        subkey_id = self.key_manager.derive_subkey(
            parent_key_id=master_key_id,
            algorithm='dilithium5',
            purpose='signature'
        )
        
        self.assertIsNotNone(subkey_id)
        self.assertTrue(self.key_manager.key_exists(subkey_id))
        
        # 验证子密钥元数据
        metadata = self.key_manager.get_key_metadata(subkey_id)
        self.assertEqual(metadata.key_type, 'subkey')
        self.assertEqual(metadata.algorithm, 'dilithium5')
        self.assertEqual(metadata.parent_key_id, master_key_id)
        self.assertEqual(metadata.purpose, 'signature')

    def test_key_rotation(self):
        """测试密钥轮换"""
        # 生成初始密钥
        key_id = self.key_manager.generate_master_key(
            algorithm='kyber-1024',
            security_level=5
        )
        
        # 执行密钥轮换
        new_key_id = self.key_manager.rotate_key(key_id)
        
        self.assertIsNotNone(new_key_id)
        self.assertNotEqual(key_id, new_key_id)
        
        # 验证旧密钥状态
        old_metadata = self.key_manager.get_key_metadata(key_id)
        self.assertEqual(old_metadata.status, KeyStatus.ROTATED)
        
        # 验证新密钥状态
        new_metadata = self.key_manager.get_key_metadata(new_key_id)
        self.assertEqual(new_metadata.status, KeyStatus.ACTIVE)

    def test_key_lifecycle(self):
        """测试密钥生命周期管理"""
        key_id = self.key_manager.generate_master_key(
            algorithm='kyber-1024',
            security_level=5
        )
        
        # 测试激活状态
        self.assertTrue(self.key_manager.is_key_active(key_id))
        
        # 测试暂停密钥
        self.key_manager.suspend_key(key_id)
        metadata = self.key_manager.get_key_metadata(key_id)
        self.assertEqual(metadata.status, KeyStatus.SUSPENDED)
        self.assertFalse(self.key_manager.is_key_active(key_id))
        
        # 测试恢复密钥
        self.key_manager.resume_key(key_id)
        metadata = self.key_manager.get_key_metadata(key_id)
        self.assertEqual(metadata.status, KeyStatus.ACTIVE)
        self.assertTrue(self.key_manager.is_key_active(key_id))
        
        # 测试吊销密钥
        self.key_manager.revoke_key(key_id, reason="测试吊销")
        metadata = self.key_manager.get_key_metadata(key_id)
        self.assertEqual(metadata.status, KeyStatus.REVOKED)
        self.assertFalse(self.key_manager.is_key_active(key_id))

    def test_key_expiration(self):
        """测试密钥过期处理"""
        # 生成短期密钥（1秒过期）
        key_id = self.key_manager.generate_master_key(
            algorithm='kyber-1024',
            security_level=5,
            validity_period=1  # 1秒
        )
        
        # 验证密钥初始状态
        self.assertTrue(self.key_manager.is_key_active(key_id))
        
        # 等待密钥过期
        time.sleep(2)
        
        # 检查过期处理
        self.key_manager._check_key_expiration()
        
        metadata = self.key_manager.get_key_metadata(key_id)
        self.assertEqual(metadata.status, KeyStatus.EXPIRED)
        self.assertFalse(self.key_manager.is_key_active(key_id))

    def test_hierarchical_key_structure(self):
        """测试层次化密钥结构"""
        # 生成主密钥
        master_key_id = self.key_manager.generate_master_key(
            algorithm='kyber-1024',
            security_level=5
        )
        
        # 生成多个子密钥
        subkey1_id = self.key_manager.derive_subkey(
            parent_key_id=master_key_id,
            algorithm='dilithium5',
            purpose='signature'
        )
        
        subkey2_id = self.key_manager.derive_subkey(
            parent_key_id=master_key_id,
            algorithm='aes-256',
            purpose='encryption'
        )
        
        # 生成孙密钥
        grandchild_key_id = self.key_manager.derive_subkey(
            parent_key_id=subkey1_id,
            algorithm='hmac-sha256',
            purpose='authentication'
        )
        
        # 验证层次结构
        children = self.key_manager.get_child_keys(master_key_id)
        self.assertIn(subkey1_id, children)
        self.assertIn(subkey2_id, children)
        
        grandchildren = self.key_manager.get_child_keys(subkey1_id)
        self.assertIn(grandchild_key_id, grandchildren)
        
        # 验证祖先关系
        ancestors = self.key_manager.get_key_ancestors(grandchild_key_id)
        self.assertIn(subkey1_id, ancestors)
        self.assertIn(master_key_id, ancestors)

    def test_key_backup_and_restore(self):
        """测试密钥备份和恢复"""
        # 生成密钥
        key_id = self.key_manager.generate_master_key(
            algorithm='kyber-1024',
            security_level=5
        )
        
        # 创建备份
        backup_data = self.key_manager.backup_key(key_id)
        self.assertIsNotNone(backup_data)
        
        # 删除原密钥
        self.key_manager.delete_key(key_id)
        self.assertFalse(self.key_manager.key_exists(key_id))
        
        # 从备份恢复
        restored_key_id = self.key_manager.restore_key(backup_data)
        self.assertTrue(self.key_manager.key_exists(restored_key_id))
        
        # 验证恢复的密钥元数据
        metadata = self.key_manager.get_key_metadata(restored_key_id)
        self.assertEqual(metadata.algorithm, 'kyber-1024')
        self.assertEqual(metadata.security_level, 5)

    def test_key_usage_tracking(self):
        """测试密钥使用情况跟踪"""
        key_id = self.key_manager.generate_master_key(
            algorithm='kyber-1024',
            security_level=5
        )
        
        # 记录密钥使用
        for _ in range(5):
            self.key_manager.record_key_usage(key_id, 'encryption')
        
        for _ in range(3):
            self.key_manager.record_key_usage(key_id, 'decryption')
        
        # 获取使用统计
        usage_stats = self.key_manager.get_key_usage_stats(key_id)
        self.assertEqual(usage_stats['encryption'], 5)
        self.assertEqual(usage_stats['decryption'], 3)
        self.assertEqual(usage_stats['total'], 8)

    def test_key_storage_encryption(self):
        """测试密钥存储加密"""
        # 使用加密存储的密钥管理器
        encrypted_key_manager = KeyManager(
            storage_path=self.temp_dir,
            encryption_enabled=True,
            master_password="test_password"
        )
        
        key_id = encrypted_key_manager.generate_master_key(
            algorithm='kyber-1024',
            security_level=5
        )
        
        # 验证密钥文件已加密
        key_file_path = os.path.join(self.temp_dir, f"{key_id}.key")
        self.assertTrue(os.path.exists(key_file_path))
        
        # 尝试不用密码读取应该失败
        with self.assertRaises(Exception):
            unencrypted_key_manager = KeyManager(
                storage_path=self.temp_dir,
                encryption_enabled=False
            )
            unencrypted_key_manager.get_key_metadata(key_id)

    def test_concurrent_key_operations(self):
        """测试并发密钥操作"""
        import threading
        import concurrent.futures
        
        key_ids = []
        
        def generate_key():
            key_id = self.key_manager.generate_master_key(
                algorithm='kyber-1024',
                security_level=5
            )
            key_ids.append(key_id)
            return key_id
        
        # 并发生成多个密钥
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(generate_key) for _ in range(10)]
            concurrent.futures.wait(futures)
        
        # 验证所有密钥都成功生成
        self.assertEqual(len(key_ids), 10)
        for key_id in key_ids:
            self.assertTrue(self.key_manager.key_exists(key_id))

    def test_key_policy_enforcement(self):
        """测试密钥策略执行"""
        # 设置密钥策略
        policy = {
            'max_key_age_days': 30,
            'require_key_rotation': True,
            'min_security_level': 3,
            'allowed_algorithms': ['kyber-1024', 'dilithium5']
        }
        
        self.key_manager.set_key_policy(policy)
        
        # 测试违反策略的操作
        with self.assertRaises(ValueError):
            self.key_manager.generate_master_key(
                algorithm='rsa-2048',  # 不在允许列表中
                security_level=5
            )
        
        with self.assertRaises(ValueError):
            self.key_manager.generate_master_key(
                algorithm='kyber-1024',
                security_level=2  # 低于最小安全级别
            )

    def test_key_audit_trail(self):
        """测试密钥审计跟踪"""
        key_id = self.key_manager.generate_master_key(
            algorithm='kyber-1024',
            security_level=5
        )
        
        # 执行一系列操作
        self.key_manager.suspend_key(key_id)
        self.key_manager.resume_key(key_id)
        self.key_manager.rotate_key(key_id)
        
        # 获取审计日志
        audit_trail = self.key_manager.get_key_audit_trail(key_id)
        
        # 验证审计记录
        self.assertGreater(len(audit_trail), 0)
        
        operations = [record['operation'] for record in audit_trail]
        self.assertIn('generate', operations)
        self.assertIn('suspend', operations)
        self.assertIn('resume', operations)
        self.assertIn('rotate', operations)


class TestKeyMetadata(unittest.TestCase):
    """密钥元数据测试类"""

    def test_key_metadata_creation(self):
        """测试密钥元数据创建"""
        metadata = KeyMetadata(
            key_id="test_key_001",
            key_type="master",
            algorithm="kyber-1024",
            security_level=5,
            purpose="key_exchange",
            status=KeyStatus.ACTIVE
        )
        
        self.assertEqual(metadata.key_id, "test_key_001")
        self.assertEqual(metadata.key_type, "master")
        self.assertEqual(metadata.algorithm, "kyber-1024")
        self.assertEqual(metadata.security_level, 5)
        self.assertEqual(metadata.status, KeyStatus.ACTIVE)

    def test_key_metadata_serialization(self):
        """测试密钥元数据序列化"""
        metadata = KeyMetadata(
            key_id="test_key_001",
            key_type="master",
            algorithm="kyber-1024",
            security_level=5,
            purpose="key_exchange",
            status=KeyStatus.ACTIVE
        )
        
        # 序列化
        serialized = metadata.to_dict()
        self.assertIsInstance(serialized, dict)
        self.assertEqual(serialized['key_id'], "test_key_001")
        
        # 反序列化
        deserialized = KeyMetadata.from_dict(serialized)
        self.assertEqual(deserialized.key_id, metadata.key_id)
        self.assertEqual(deserialized.algorithm, metadata.algorithm)


if __name__ == '__main__':
    unittest.main() 