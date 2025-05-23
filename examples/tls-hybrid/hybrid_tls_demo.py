#!/usr/bin/env python3
"""
TLS混合模式示例
展示如何使用QACMF框架实现抗量子TLS握手
"""

import asyncio
import ssl
import socket
from typing import Optional
import logging

from qacmf.core.key_manager import KeyManager
from qacmf.adapters.tls_adapter import TLSAdapter
from qacmf.plugins.kyber_plugin import Kyber1024Plugin
from qacmf.plugins.dilithium_plugin import Dilithium5Plugin

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HybridTLSServer:
    """混合TLS服务器示例"""
    
    def __init__(self, host: str = 'localhost', port: int = 8443):
        self.host = host
        self.port = port
        self.key_manager = KeyManager()
        self.tls_adapter = TLSAdapter()
        
        # 初始化插件
        self.kyber_plugin = Kyber1024Plugin()
        self.dilithium_plugin = Dilithium5Plugin()
        
        # 生成密钥对
        self._setup_keys()
    
    def _setup_keys(self):
        """设置密钥对"""
        logger.info("生成抗量子密钥对...")
        
        # 生成Kyber密钥对用于密钥交换
        self.kyber_public, self.kyber_private = self.kyber_plugin.generate_keypair()
        
        # 生成Dilithium密钥对用于数字签名
        self.dilithium_public, self.dilithium_private = self.dilithium_plugin.generate_keypair()
        
        logger.info(f"Kyber公钥长度: {len(self.kyber_public)} 字节")
        logger.info(f"Dilithium公钥长度: {len(self.dilithium_public)} 字节")
    
    async def handle_client(self, reader: asyncio.StreamReader, 
                          writer: asyncio.StreamWriter):
        """处理客户端连接"""
        client_addr = writer.get_extra_info('peername')
        logger.info(f"新客户端连接: {client_addr}")
        
        try:
            # 混合TLS握手
            await self._hybrid_handshake(reader, writer)
            
            # 处理应用数据
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                
                # 解密数据 (简化示例)
                decrypted_data = self._decrypt_data(data)
                logger.info(f"收到消息: {decrypted_data}")
                
                # 发送响应
                response = f"Echo: {decrypted_data}"
                encrypted_response = self._encrypt_data(response.encode())
                writer.write(encrypted_response)
                await writer.drain()
                
        except Exception as e:
            logger.error(f"处理客户端错误: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            logger.info(f"客户端连接关闭: {client_addr}")
    
    async def _hybrid_handshake(self, reader: asyncio.StreamReader, 
                               writer: asyncio.StreamWriter):
        """执行混合TLS握手"""
        logger.info("开始混合TLS握手...")
        
        # 1. 发送服务器Hello和证书
        server_hello = self._create_server_hello()
        writer.write(server_hello)
        await writer.drain()
        
        # 2. 接收客户端密钥交换
        client_key_exchange = await reader.read(2048)
        logger.info(f"收到客户端密钥交换: {len(client_key_exchange)} 字节")
        
        # 3. 解析Kyber密文并解封装
        ciphertext = client_key_exchange[4:]  # 跳过长度字段
        shared_secret = self.kyber_plugin.decapsulate(self.kyber_private, ciphertext)
        logger.info(f"成功解封装共享密钥: {len(shared_secret)} 字节")
        
        # 4. 生成会话密钥
        self.session_key = self._derive_session_key(shared_secret)
        
        # 5. 发送服务器完成消息
        server_finished = self._create_server_finished()
        writer.write(server_finished)
        await writer.drain()
        
        logger.info("混合TLS握手完成")
    
    def _create_server_hello(self) -> bytes:
        """创建服务器Hello消息"""
        # TLS记录头
        message = bytearray()
        message.extend(b'\x16')  # Handshake
        message.extend(b'\x03\x04')  # TLS 1.3
        
        # 服务器Hello内容
        hello_content = bytearray()
        hello_content.extend(b'\x02')  # ServerHello
        hello_content.extend(b'\x00\x00\x46')  # 长度占位符
        
        # 服务器随机数
        hello_content.extend(b'\x00' * 32)
        
        # 会话ID (空)
        hello_content.extend(b'\x00')
        
        # 密码套件 (自定义Kyber套件)
        hello_content.extend(b'\x13\x37')  # TLS_KYBER_AES256_SHA384
        
        # 压缩方法
        hello_content.extend(b'\x00')
        
        # 扩展
        extensions = bytearray()
        
        # Kyber公钥扩展
        kyber_ext = bytearray()
        kyber_ext.extend(b'\xFF\x01')  # 自定义扩展类型
        kyber_ext.extend(len(self.kyber_public).to_bytes(2, 'big'))
        kyber_ext.extend(self.kyber_public)
        
        extensions.extend(len(kyber_ext).to_bytes(2, 'big'))
        extensions.extend(kyber_ext)
        
        hello_content.extend(len(extensions).to_bytes(2, 'big'))
        hello_content.extend(extensions)
        
        # 更新长度
        hello_length = len(hello_content) - 4
        hello_content[1:4] = hello_length.to_bytes(3, 'big')
        
        message.extend(len(hello_content).to_bytes(2, 'big'))
        message.extend(hello_content)
        
        return bytes(message)
    
    def _create_server_finished(self) -> bytes:
        """创建服务器完成消息"""
        # 简化的完成消息
        message = bytearray()
        message.extend(b'\x16')  # Handshake
        message.extend(b'\x03\x04')  # TLS 1.3
        
        finished_content = bytearray()
        finished_content.extend(b'\x14')  # Finished
        finished_content.extend(b'\x00\x00\x20')  # 32字节长度
        
        # 计算完成消息哈希 (简化)
        verify_data = self._compute_verify_data()
        finished_content.extend(verify_data)
        
        message.extend(len(finished_content).to_bytes(2, 'big'))
        message.extend(finished_content)
        
        return bytes(message)
    
    def _derive_session_key(self, shared_secret: bytes) -> bytes:
        """从共享密钥派生会话密钥"""
        import hashlib
        
        # 使用HKDF派生会话密钥
        salt = b'QACMF-TLS-v2.0'
        info = b'session-key'
        
        # 简化的HKDF实现
        prk = hashlib.pbkdf2_hmac('sha256', shared_secret, salt, 1000)
        okm = hashlib.pbkdf2_hmac('sha256', prk, info, 1000, 32)
        
        return okm
    
    def _compute_verify_data(self) -> bytes:
        """计算验证数据"""
        # 简化实现，实际应该计算握手消息的哈希
        import hashlib
        handshake_hash = hashlib.sha256(b'handshake-messages').digest()
        return handshake_hash
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """加密应用数据"""
        # 简化的AES加密
        from cryptography.fernet import Fernet
        import base64
        
        key = base64.urlsafe_b64encode(self.session_key)
        f = Fernet(key)
        return f.encrypt(data)
    
    def _decrypt_data(self, data: bytes) -> bytes:
        """解密应用数据"""
        # 简化的AES解密
        from cryptography.fernet import Fernet
        import base64
        
        key = base64.urlsafe_b64encode(self.session_key)
        f = Fernet(key)
        return f.decrypt(data)
    
    async def start_server(self):
        """启动服务器"""
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        
        addr = server.sockets[0].getsockname()
        logger.info(f"混合TLS服务器启动在 {addr}")
        
        async with server:
            await server.serve_forever()


class HybridTLSClient:
    """混合TLS客户端示例"""
    
    def __init__(self):
        self.kyber_plugin = Kyber1024Plugin()
        self.dilithium_plugin = Dilithium5Plugin()
        self.session_key = None
    
    async def connect(self, host: str = 'localhost', port: int = 8443):
        """连接到服务器"""
        logger.info(f"连接到 {host}:{port}")
        
        reader, writer = await asyncio.open_connection(host, port)
        
        try:
            # 执行握手
            await self._hybrid_handshake(reader, writer)
            
            # 发送测试消息
            test_message = "Hello, Quantum-Safe TLS!"
            encrypted_msg = self._encrypt_data(test_message.encode())
            writer.write(encrypted_msg)
            await writer.drain()
            
            # 接收响应
            response = await reader.read(1024)
            decrypted_response = self._decrypt_data(response)
            logger.info(f"服务器响应: {decrypted_response}")
            
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _hybrid_handshake(self, reader: asyncio.StreamReader, 
                               writer: asyncio.StreamWriter):
        """执行混合TLS握手"""
        logger.info("开始客户端握手...")
        
        # 1. 接收服务器Hello
        server_hello = await reader.read(2048)
        logger.info(f"收到服务器Hello: {len(server_hello)} 字节")
        
        # 2. 解析服务器公钥
        server_public_key = self._parse_server_public_key(server_hello)
        
        # 3. 生成共享密钥并封装
        ciphertext, shared_secret = self.kyber_plugin.encapsulate(server_public_key)
        
        # 4. 发送客户端密钥交换
        key_exchange = self._create_client_key_exchange(ciphertext)
        writer.write(key_exchange)
        await writer.drain()
        
        # 5. 派生会话密钥
        self.session_key = self._derive_session_key(shared_secret)
        
        # 6. 接收服务器完成消息
        server_finished = await reader.read(1024)
        logger.info("收到服务器完成消息")
        
        logger.info("客户端握手完成")
    
    def _parse_server_public_key(self, server_hello: bytes) -> bytes:
        """解析服务器公钥"""
        # 简化的解析逻辑
        # 实际实现需要完整解析TLS消息格式
        
        # 跳过TLS记录头和Hello头部，查找Kyber扩展
        offset = 0
        while offset < len(server_hello) - 4:
            if (server_hello[offset:offset+2] == b'\xFF\x01'):  # Kyber扩展
                key_length = int.from_bytes(server_hello[offset+2:offset+4], 'big')
                return server_hello[offset+4:offset+4+key_length]
            offset += 1
        
        raise ValueError("未找到服务器Kyber公钥")
    
    def _create_client_key_exchange(self, ciphertext: bytes) -> bytes:
        """创建客户端密钥交换消息"""
        message = bytearray()
        message.extend(b'\x16')  # Handshake
        message.extend(b'\x03\x04')  # TLS 1.3
        
        # 密钥交换内容
        key_exchange_content = bytearray()
        key_exchange_content.extend(len(ciphertext).to_bytes(4, 'big'))
        key_exchange_content.extend(ciphertext)
        
        message.extend(len(key_exchange_content).to_bytes(2, 'big'))
        message.extend(key_exchange_content)
        
        return bytes(message)
    
    def _derive_session_key(self, shared_secret: bytes) -> bytes:
        """从共享密钥派生会话密钥"""
        import hashlib
        
        # 使用HKDF派生会话密钥
        salt = b'QACMF-TLS-v2.0'
        info = b'session-key'
        
        # 简化的HKDF实现
        prk = hashlib.pbkdf2_hmac('sha256', shared_secret, salt, 1000)
        okm = hashlib.pbkdf2_hmac('sha256', prk, info, 1000, 32)
        
        return okm
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """加密应用数据"""
        from cryptography.fernet import Fernet
        import base64
        
        key = base64.urlsafe_b64encode(self.session_key)
        f = Fernet(key)
        return f.encrypt(data)
    
    def _decrypt_data(self, data: bytes) -> bytes:
        """解密应用数据"""
        from cryptography.fernet import Fernet
        import base64
        
        key = base64.urlsafe_b64encode(self.session_key)
        f = Fernet(key)
        return f.decrypt(data)


async def run_server():
    """运行服务器"""
    server = HybridTLSServer()
    await server.start_server()


async def run_client():
    """运行客户端"""
    client = HybridTLSClient()
    await client.connect()


def main():
    """主函数"""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'client':
        asyncio.run(run_client())
    else:
        asyncio.run(run_server())


if __name__ == '__main__':
    main() 