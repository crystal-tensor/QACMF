#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
基础密码学工具

该模块提供了QACMF框架使用的基础密码学操作，包括随机数生成、哈希计算、
基本加密解密功能以及密码学安全的比较函数等。
"""

import os
import hashlib
import hmac
import base64
import secrets
from typing import Union, Optional, Tuple, List, Dict, Any
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

# 支持的哈希算法
HASH_ALGORITHMS = {
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512,
    'sha3_256': hashlib.sha3_256,
    'sha3_384': hashlib.sha3_384,
    'sha3_512': hashlib.sha3_512,
    'blake2b': hashlib.blake2b,
    'blake2s': hashlib.blake2s,
}

# 支持的对称加密算法
SYMMETRIC_ALGORITHMS = {
    'aes-128-cbc': (algorithms.AES, 16, modes.CBC),
    'aes-192-cbc': (algorithms.AES, 24, modes.CBC),
    'aes-256-cbc': (algorithms.AES, 32, modes.CBC),
    'aes-128-gcm': (algorithms.AES, 16, modes.GCM),
    'aes-192-gcm': (algorithms.AES, 24, modes.GCM),
    'aes-256-gcm': (algorithms.AES, 32, modes.GCM),
}

def generate_random_bytes(length: int) -> bytes:
    """生成指定长度的密码学安全随机字节
    
    Args:
        length: 要生成的随机字节长度
        
    Returns:
        随机字节
    """
    return os.urandom(length)

def generate_random_hex(length: int) -> str:
    """生成指定长度的密码学安全随机十六进制字符串
    
    Args:
        length: 要生成的随机字符串长度（字节数）
        
    Returns:
        十六进制随机字符串
    """
    return secrets.token_hex(length)

def generate_random_base64(length: int) -> str:
    """生成指定长度的密码学安全随机Base64字符串
    
    Args:
        length: 要生成的随机字节长度
        
    Returns:
        Base64编码的随机字符串
    """
    return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8').rstrip('=')

def compute_hash(data: Union[str, bytes], algorithm: str = 'sha256', encoding: str = 'utf-8') -> bytes:
    """计算数据的哈希值
    
    Args:
        data: 要计算哈希的数据
        algorithm: 哈希算法名称
        encoding: 如果data是字符串，则使用此编码转换为字节
        
    Returns:
        哈希值字节
        
    Raises:
        ValueError: 当指定的算法不支持时
    """
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"不支持的哈希算法: {algorithm}，支持的算法: {list(HASH_ALGORITHMS.keys())}")
    
    hash_func = HASH_ALGORITHMS[algorithm]()
    
    if isinstance(data, str):
        data = data.encode(encoding)
    
    hash_func.update(data)
    return hash_func.digest()

def compute_hmac(key: Union[str, bytes], data: Union[str, bytes], 
                algorithm: str = 'sha256', encoding: str = 'utf-8') -> bytes:
    """计算HMAC值
    
    Args:
        key: HMAC密钥
        data: 要计算HMAC的数据
        algorithm: 哈希算法名称
        encoding: 如果key或data是字符串，则使用此编码转换为字节
        
    Returns:
        HMAC值字节
        
    Raises:
        ValueError: 当指定的算法不支持时
    """
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"不支持的哈希算法: {algorithm}，支持的算法: {list(HASH_ALGORITHMS.keys())}")
    
    if isinstance(key, str):
        key = key.encode(encoding)
    
    if isinstance(data, str):
        data = data.encode(encoding)
    
    return hmac.new(key, data, getattr(hashlib, algorithm)).digest()

def constant_time_compare(a: Union[str, bytes], b: Union[str, bytes], encoding: str = 'utf-8') -> bool:
    """密码学安全的常量时间比较
    
    Args:
        a: 第一个值
        b: 第二个值
        encoding: 如果a或b是字符串，则使用此编码转换为字节
        
    Returns:
        如果两个值相等则为True，否则为False
    """
    if isinstance(a, str):
        a = a.encode(encoding)
    
    if isinstance(b, str):
        b = b.encode(encoding)
    
    return hmac.compare_digest(a, b)

def derive_key(password: Union[str, bytes], salt: Union[str, bytes], 
              length: int = 32, iterations: int = 100000, 
              algorithm: str = 'sha256', encoding: str = 'utf-8') -> bytes:
    """使用PBKDF2从密码派生密钥
    
    Args:
        password: 密码
        salt: 盐值
        length: 派生密钥的长度（字节）
        iterations: 迭代次数
        algorithm: 哈希算法名称
        encoding: 如果password或salt是字符串，则使用此编码转换为字节
        
    Returns:
        派生的密钥字节
    """
    if isinstance(password, str):
        password = password.encode(encoding)
    
    if isinstance(salt, str):
        salt = salt.encode(encoding)
    
    kdf = PBKDF2HMAC(
        algorithm=getattr(hashes, algorithm.upper())(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    
    return kdf.derive(password)

def encrypt_aes(data: Union[str, bytes], key: bytes, iv: Optional[bytes] = None,
               algorithm: str = 'aes-256-cbc', encoding: str = 'utf-8') -> Tuple[bytes, bytes]:
    """使用AES加密数据
    
    Args:
        data: 要加密的数据
        key: 加密密钥
        iv: 初始化向量，如果为None则随机生成
        algorithm: 加密算法和模式
        encoding: 如果data是字符串，则使用此编码转换为字节
        
    Returns:
        (密文, 初始化向量)元组
        
    Raises:
        ValueError: 当指定的算法不支持或密钥长度不正确时
    """
    if algorithm not in SYMMETRIC_ALGORITHMS:
        raise ValueError(f"不支持的加密算法: {algorithm}，支持的算法: {list(SYMMETRIC_ALGORITHMS.keys())}")
    
    alg_class, key_size, mode_class = SYMMETRIC_ALGORITHMS[algorithm]
    
    if len(key) != key_size:
        raise ValueError(f"密钥长度不正确，{algorithm}需要{key_size}字节的密钥")
    
    if isinstance(data, str):
        data = data.encode(encoding)
    
    # 如果未提供IV，则生成随机IV
    if iv is None:
        iv = os.urandom(16)  # AES块大小为16字节
    
    # 对数据进行填充
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # 创建加密器
    if 'gcm' in algorithm:
        encryptor = Cipher(alg_class(key), mode_class(iv, b'', 16)).encryptor()
    else:
        encryptor = Cipher(alg_class(key), mode_class(iv)).encryptor()
    
    # 加密数据
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # 对于GCM模式，需要包含认证标签
    if 'gcm' in algorithm:
        ciphertext += encryptor.tag
    
    return ciphertext, iv

def decrypt_aes(ciphertext: bytes, key: bytes, iv: bytes,
               algorithm: str = 'aes-256-cbc') -> bytes:
    """使用AES解密数据
    
    Args:
        ciphertext: 密文
        key: 解密密钥
        iv: 初始化向量
        algorithm: 解密算法和模式
        
    Returns:
        解密后的明文字节
        
    Raises:
        ValueError: 当指定的算法不支持或密钥长度不正确时
    """
    if algorithm not in SYMMETRIC_ALGORITHMS:
        raise ValueError(f"不支持的解密算法: {algorithm}，支持的算法: {list(SYMMETRIC_ALGORITHMS.keys())}")
    
    alg_class, key_size, mode_class = SYMMETRIC_ALGORITHMS[algorithm]
    
    if len(key) != key_size:
        raise ValueError(f"密钥长度不正确，{algorithm}需要{key_size}字节的密钥")
    
    # 对于GCM模式，需要分离认证标签
    tag = None
    if 'gcm' in algorithm:
        ciphertext, tag = ciphertext[:-16], ciphertext[-16:]
    
    # 创建解密器
    if 'gcm' in algorithm:
        decryptor = Cipher(alg_class(key), mode_class(iv, tag, 16)).decryptor()
    else:
        decryptor = Cipher(alg_class(key), mode_class(iv)).decryptor()
    
    # 解密数据
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 移除填充
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def encode_base64(data: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """Base64编码数据
    
    Args:
        data: 要编码的数据
        encoding: 如果data是字符串，则使用此编码转换为字节
        
    Returns:
        Base64编码的字符串
    """
    if isinstance(data, str):
        data = data.encode(encoding)
    
    return base64.b64encode(data).decode('ascii')

def decode_base64(data: str) -> bytes:
    """Base64解码数据
    
    Args:
        data: 要解码的Base64字符串
        
    Returns:
        解码后的字节
    """
    return base64.b64decode(data)

def encode_hex(data: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """十六进制编码数据
    
    Args:
        data: 要编码的数据
        encoding: 如果data是字符串，则使用此编码转换为字节
        
    Returns:
        十六进制编码的字符串
    """
    if isinstance(data, str):
        data = data.encode(encoding)
    
    return data.hex()

def decode_hex(data: str) -> bytes:
    """十六进制解码数据
    
    Args:
        data: 要解码的十六进制字符串
        
    Returns:
        解码后的字节
    """
    return bytes.fromhex(data)