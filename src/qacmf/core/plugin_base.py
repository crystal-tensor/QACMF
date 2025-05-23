# src/qacmf/core/plugin_base.py
import abc

class QuantumPluginBase(abc.ABC):
    """所有抗量子密码算法插件的抽象基类"""

    @abc.abstractmethod
    def metadata(self):
        """返回插件的元数据，如名称、类型、NIST级别、密钥大小等"""
        pass

    # KEM specific methods (optional, KEM plugins should implement these)
    def generate_keypair(self):
        """(KEM) 生成密钥对 (公钥, 私钥)"""
        raise NotImplementedError("This plugin does not support KEM keypair generation or it's not a KEM plugin.")

    def encapsulate_key(self, public_key):
        """(KEM) 使用公钥封装共享密钥，返回 (共享密钥, 密文)"""
        raise NotImplementedError("This plugin does not support KEM key encapsulation or it's not a KEM plugin.")

    def decapsulate_key(self, secret_key, ciphertext):
        """(KEM) 使用私钥解封装共享密钥，返回共享密钥"""
        raise NotImplementedError("This plugin does not support KEM key decapsulation or it's not a KEM plugin.")

    # Digital Signature specific methods (optional, Signature plugins should implement these)
    def sign(self, message, secret_key):
        """(Signature) 使用私钥对消息进行签名"""
        raise NotImplementedError("This plugin does not support signing or it's not a signature plugin.")

    def verify(self, message, signature, public_key):
        """(Signature) 使用公钥验证签名"""
        raise NotImplementedError("This plugin does not support signature verification or it's not a signature plugin.")

    # Hash function specific methods (optional, Hash plugins should implement these)
    def hash(self, data):
        """(Hash) 计算数据的哈希值"""
        raise NotImplementedError("This plugin does not support hashing or it's not a hash plugin.")

    # Other common methods can be added here
    def get_name(self):
        """获取插件名称"""
        meta = self.metadata()
        return meta.get("name", "UnknownPlugin")

    def get_type(self):
        """获取插件类型 (e.g., KEM, Signature, Hash)"""
        meta = self.metadata()
        return meta.get("type", "UnknownType")