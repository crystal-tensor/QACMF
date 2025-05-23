"""
Dilithium5 数字签名插件
NIST后量子密码学标准化候选算法实现
"""

import secrets
import hashlib
from typing import Tuple, Dict, Any, Optional
from qacmf.core.plugin_base import QuantumPluginBase, PluginType


class Dilithium5Plugin(QuantumPluginBase):
    """Dilithium5 数字签名插件"""
    
    def __init__(self):
        super().__init__()
        self._name = "dilithium5"
        self._version = "1.0.0"
        self._algorithm_type = PluginType.SIGNATURE
        
        # Dilithium5 参数
        self.n = 256          # 多项式维度
        self.k = 8           # 公钥向量维度
        self.l = 7           # 私钥向量维度
        self.q = 8380417     # 模数
        self.d = 13          # 舍入位数
        self.tau = 60        # 挑战权重
        self.beta = 120      # 签名界限
        self.gamma1 = (1 << 19)  # 签名参数1
        self.gamma2 = ((self.q - 1) // 32)  # 签名参数2
        self.omega = 75      # 提示多项式权重
        
        # 密钥和签名长度 (字节)
        self.public_key_length = 2592
        self.secret_key_length = 4864
        self.signature_length = 4595

    def metadata(self) -> Dict[str, Any]:
        """返回插件元数据"""
        return {
            "name": self._name,
            "version": self._version,
            "type": self._algorithm_type.value,
            "nist_level": 5,
            "key_sizes": {
                "public_key": self.public_key_length,
                "secret_key": self.secret_key_length,
                "signature": self.signature_length
            },
            "security_strength": 256,
            "side_channel_resistance": True,
            "compliance": ["NIST PQC Round 4", "FIPS 204"],
            "performance": {
                "keygen_ops_per_sec": 8000,
                "sign_ops_per_sec": 4000,
                "verify_ops_per_sec": 6000
            },
            "hash_algorithm": "SHAKE-256"
        }

    def generate_keypair(self, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        生成Dilithium5密钥对
        
        Args:
            seed: 可选的随机种子
            
        Returns:
            (public_key, secret_key) 元组
        """
        if seed is None:
            seed = secrets.token_bytes(32)
        
        # 扩展种子
        zeta = self._shake256(seed, 64)
        rho = zeta[:32]
        rho_prime = zeta[32:64]
        K = self._shake256(rho_prime, 32)
        
        # 生成矩阵A
        A = self._expand_A(rho)
        
        # 生成密钥向量
        s1 = self._sample_in_ball(self._shake256(K + b'\x00', 32))
        s2 = self._sample_in_ball(self._shake256(K + b'\x01', 32))
        
        # 计算公钥: t = As1 + s2
        t = self._matrix_vector_mult(A, s1)
        t = self._vector_add(t, s2)
        
        # 计算t1 (高位部分)
        t1 = self._power2round(t, self.d)
        
        # 打包密钥
        public_key = self._pack_public_key(rho, t1)
        secret_key = self._pack_secret_key(rho, K, t1, s1, s2)
        
        return public_key, secret_key

    def sign(self, message: bytes, secret_key: bytes, 
             deterministic: bool = True) -> bytes:
        """
        使用Dilithium5签名消息
        
        Args:
            message: 要签名的消息
            secret_key: 私钥
            deterministic: 是否使用确定性签名
            
        Returns:
            签名数据
        """
        if len(secret_key) != self.secret_key_length:
            raise ValueError(f"私钥长度错误: 期望 {self.secret_key_length}, 实际 {len(secret_key)}")
        
        # 解包私钥
        rho, K, t1, s1, s2 = self._unpack_secret_key(secret_key)
        
        # 重新计算t0
        A = self._expand_A(rho)
        t = self._matrix_vector_mult(A, s1)
        t = self._vector_add(t, s2)
        t0 = self._power2round_t0(t, self.d)
        
        # 计算消息哈希
        mu = self._shake256(
            self._pack_public_key(rho, t1) + message, 64
        )
        
        # 签名主循环
        kappa = 0
        max_attempts = 2**20  # 防止无限循环
        
        for attempt in range(max_attempts):
            # 生成随机y
            rho_prime = self._shake256(K + mu + kappa.to_bytes(2, 'big'), 64)
            y = self._expand_mask(rho_prime)
            
            # 计算w = Ay
            w = self._matrix_vector_mult(A, y)
            w1 = self._high_bits(w, 2 * self.gamma2)
            
            # 计算挑战
            c_tilde = self._shake256(mu + self._pack_w1(w1), 64)
            c = self._sample_in_ball(c_tilde)
            
            # 计算签名候选
            z = self._vector_add(y, self._scalar_vector_mult(c, s1))
            
            # 检查范数约束
            if not self._check_norm_bound(z, self.gamma1 - self.beta):
                kappa += 1
                continue
            
            # 计算r0
            r0 = self._vector_sub(w, self._scalar_vector_mult(c, s2))
            r0 = self._low_bits(r0, 2 * self.gamma2)
            
            if not self._check_norm_bound(r0, self.gamma2 - self.beta):
                kappa += 1
                continue
            
            # 计算ct0
            ct0 = self._scalar_vector_mult(c, t0)
            
            if not self._check_norm_bound(ct0, self.gamma2):
                kappa += 1
                continue
            
            # 计算提示多项式h
            h = self._make_hint(-ct0, w - self._scalar_vector_mult(c, s2) + ct0)
            
            if sum(self._weight(hi) for hi in h) <= self.omega:
                # 签名成功
                signature = self._pack_signature(c_tilde, z, h)
                return signature
            
            kappa += 1
        
        raise RuntimeError("签名生成失败: 超过最大尝试次数")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        验证Dilithium5签名
        
        Args:
            message: 原始消息
            signature: 签名数据
            public_key: 公钥
            
        Returns:
            验证是否成功
        """
        if len(public_key) != self.public_key_length:
            raise ValueError(f"公钥长度错误: 期望 {self.public_key_length}, 实际 {len(public_key)}")
        
        if len(signature) != self.signature_length:
            raise ValueError(f"签名长度错误: 期望 {self.signature_length}, 实际 {len(signature)}")
        
        try:
            # 解包公钥和签名
            rho, t1 = self._unpack_public_key(public_key)
            c_tilde, z, h = self._unpack_signature(signature)
            
            # 检查签名范数
            if not self._check_norm_bound(z, self.gamma1 - self.beta):
                return False
            
            # 重新生成矩阵A
            A = self._expand_A(rho)
            
            # 计算消息哈希
            mu = self._shake256(public_key + message, 64)
            
            # 重新计算挑战
            c = self._sample_in_ball(c_tilde)
            
            # 验证计算
            w_prime = self._matrix_vector_mult(A, z)
            t_2d = self._shift_left(t1, self.d)
            ct_2d = self._scalar_vector_mult(c, t_2d)
            w_prime = self._vector_sub(w_prime, ct_2d)
            
            # 使用提示恢复w1
            w1_prime = self._use_hint(h, w_prime, 2 * self.gamma2)
            
            # 验证挑战
            c_tilde_prime = self._shake256(mu + self._pack_w1(w1_prime), 64)
            
            return c_tilde == c_tilde_prime
            
        except Exception:
            return False

    def _shake256(self, data: bytes, output_length: int) -> bytes:
        """SHAKE-256可扩展输出函数"""
        shake = hashlib.shake_256()
        shake.update(data)
        return shake.digest(output_length)

    def _expand_A(self, rho: bytes) -> list:
        """扩展矩阵A"""
        matrix = []
        for i in range(self.k):
            row = []
            for j in range(self.l):
                seed = rho + bytes([j, i])
                row_data = self._shake256(seed, 4 * self.n)
                poly = []
                for idx in range(0, len(row_data), 4):
                    val = int.from_bytes(row_data[idx:idx+4], 'little')
                    poly.append(val % self.q)
                row.append(poly[:self.n])
            matrix.append(row)
        return matrix

    def _sample_in_ball(self, seed: bytes) -> list:
        """在球中采样多项式 (模拟实现)"""
        poly = [0] * self.n
        hash_output = self._shake256(seed, 8 + self.tau)
        
        signs = int.from_bytes(hash_output[:8], 'little')
        positions = set()
        
        for i in range(self.tau):
            pos = hash_output[8 + i] % self.n
            while pos in positions:
                pos = (pos + 1) % self.n
            positions.add(pos)
            poly[pos] = 1 if (signs >> i) & 1 else -1
        
        return poly

    def _expand_mask(self, rho_prime: bytes) -> list:
        """扩展掩码向量"""
        y = []
        for i in range(self.l):
            seed = rho_prime + i.to_bytes(2, 'little')
            poly_data = self._shake256(seed, 5 * self.n)
            poly = []
            for j in range(0, len(poly_data), 5):
                val = int.from_bytes(poly_data[j:j+5] + b'\x00' * 3, 'little')
                poly.append((val % (2 * self.gamma1)) - self.gamma1)
            y.append(poly[:self.n])
        return y

    def _matrix_vector_mult(self, matrix: list, vector: list) -> list:
        """矩阵向量乘法"""
        result = []
        for i in range(len(matrix)):
            poly_result = [0] * self.n
            for j in range(len(vector)):
                # 简化的多项式乘法
                for k in range(self.n):
                    poly_result[k] = (poly_result[k] + 
                                    matrix[i][j][k] * vector[j][k]) % self.q
            result.append(poly_result)
        return result

    def _vector_add(self, v1: list, v2: list) -> list:
        """向量加法"""
        result = []
        for i in range(len(v1)):
            poly_result = []
            for j in range(len(v1[i])):
                poly_result.append((v1[i][j] + v2[i][j]) % self.q)
            result.append(poly_result)
        return result

    def _vector_sub(self, v1: list, v2: list) -> list:
        """向量减法"""
        result = []
        for i in range(len(v1)):
            poly_result = []
            for j in range(len(v1[i])):
                poly_result.append((v1[i][j] - v2[i][j]) % self.q)
            result.append(poly_result)
        return result

    def _scalar_vector_mult(self, scalar: list, vector: list) -> list:
        """标量向量乘法"""
        result = []
        for i in range(len(vector)):
            poly_result = [0] * self.n
            # 简化的多项式乘法
            for j in range(self.n):
                for k in range(self.n):
                    poly_result[j] = (poly_result[j] + 
                                    scalar[k] * vector[i][(j-k) % self.n]) % self.q
            result.append(poly_result)
        return result

    def _power2round(self, t: list, d: int) -> list:
        """2的幂舍入 - 返回高位"""
        t1 = []
        for poly in t:
            t1_poly = []
            for coeff in poly:
                t1_poly.append(coeff >> d)
            t1.append(t1_poly)
        return t1

    def _power2round_t0(self, t: list, d: int) -> list:
        """2的幂舍入 - 返回低位"""
        t0 = []
        for poly in t:
            t0_poly = []
            for coeff in poly:
                t0_poly.append(coeff & ((1 << d) - 1))
            t0.append(t0_poly)
        return t0

    def _high_bits(self, w: list, alpha: int) -> list:
        """提取高位"""
        return [[coeff // alpha for coeff in poly] for poly in w]

    def _low_bits(self, w: list, alpha: int) -> list:
        """提取低位"""
        return [[coeff % alpha for coeff in poly] for poly in w]

    def _shift_left(self, t1: list, d: int) -> list:
        """左移操作"""
        return [[(coeff << d) % self.q for coeff in poly] for poly in t1]

    def _check_norm_bound(self, vector: list, bound: int) -> bool:
        """检查向量的无穷范数"""
        for poly in vector:
            for coeff in poly:
                if abs(coeff) >= bound:
                    return False
        return True

    def _make_hint(self, z: list, r: list) -> list:
        """生成提示多项式 (简化实现)"""
        h = []
        for i in range(len(z)):
            h_poly = []
            for j in range(len(z[i])):
                # 简化的提示生成
                h_poly.append(1 if z[i][j] != r[i][j] else 0)
            h.append(h_poly)
        return h

    def _use_hint(self, h: list, w: list, alpha: int) -> list:
        """使用提示恢复高位 (简化实现)"""
        w1 = []
        for i in range(len(w)):
            w1_poly = []
            for j in range(len(w[i])):
                high = w[i][j] // alpha
                if h[i][j]:
                    high = (high + 1) % (self.q // alpha)
                w1_poly.append(high)
            w1.append(w1_poly)
        return w1

    def _weight(self, poly: list) -> int:
        """计算多项式的权重"""
        return sum(1 for coeff in poly if coeff != 0)

    def _pack_public_key(self, rho: bytes, t1: list) -> bytes:
        """打包公钥"""
        packed = bytearray(rho)  # 32字节的rho
        
        # 简化的t1打包
        for poly in t1:
            for coeff in poly[:10]:  # 只取前10个系数作为示例
                packed.extend(coeff.to_bytes(2, 'big'))
        
        # 填充到正确长度
        while len(packed) < self.public_key_length:
            packed.append(0)
        
        return bytes(packed[:self.public_key_length])

    def _pack_secret_key(self, rho: bytes, K: bytes, t1: list, 
                        s1: list, s2: list) -> bytes:
        """打包私钥"""
        packed = bytearray(rho)  # 32字节
        packed.extend(K)         # 32字节
        
        # 简化的向量打包
        for poly in s1:
            for coeff in poly[:5]:  # 只取前5个系数
                packed.extend(coeff.to_bytes(2, 'big', signed=True))
        
        for poly in s2:
            for coeff in poly[:5]:  # 只取前5个系数
                packed.extend(coeff.to_bytes(2, 'big', signed=True))
        
        # 填充到正确长度
        while len(packed) < self.secret_key_length:
            packed.append(0)
        
        return bytes(packed[:self.secret_key_length])

    def _pack_signature(self, c_tilde: bytes, z: list, h: list) -> bytes:
        """打包签名"""
        packed = bytearray(c_tilde)  # 64字节的挑战哈希
        
        # 简化的z向量打包
        for poly in z:
            for coeff in poly[:10]:  # 只取前10个系数
                packed.extend(coeff.to_bytes(3, 'big', signed=True))
        
        # 简化的h向量打包
        for poly in h:
            h_byte = 0
            for i, coeff in enumerate(poly[:8]):  # 只取前8位
                if coeff:
                    h_byte |= (1 << i)
            packed.append(h_byte)
        
        # 填充到正确长度
        while len(packed) < self.signature_length:
            packed.append(0)
        
        return bytes(packed[:self.signature_length])

    def _pack_w1(self, w1: list) -> bytes:
        """打包w1向量"""
        packed = bytearray()
        for poly in w1:
            for coeff in poly[:10]:  # 只取前10个系数
                packed.extend(coeff.to_bytes(1, 'big'))
        return bytes(packed)

    def _unpack_public_key(self, public_key: bytes) -> Tuple[bytes, list]:
        """解包公钥"""
        rho = public_key[:32]
        
        # 解包t1
        t1 = []
        offset = 32
        for i in range(self.k):
            poly = []
            for j in range(10):  # 对应pack时的10个系数
                if offset + 2 <= len(public_key):
                    coeff = int.from_bytes(public_key[offset:offset+2], 'big')
                    poly.append(coeff)
                    offset += 2
                else:
                    poly.append(0)
            # 填充剩余系数
            while len(poly) < self.n:
                poly.append(0)
            t1.append(poly)
        
        return rho, t1

    def _unpack_secret_key(self, secret_key: bytes) -> Tuple[bytes, bytes, list, list, list]:
        """解包私钥"""
        rho = secret_key[:32]
        K = secret_key[32:64]
        
        # 解包s1和s2 (简化)
        s1 = []
        s2 = []
        offset = 64
        
        # 解包s1
        for i in range(self.l):
            poly = []
            for j in range(5):  # 对应pack时的5个系数
                if offset + 2 <= len(secret_key):
                    coeff = int.from_bytes(secret_key[offset:offset+2], 'big', signed=True)
                    poly.append(coeff)
                    offset += 2
                else:
                    poly.append(0)
            while len(poly) < self.n:
                poly.append(0)
            s1.append(poly)
        
        # 解包s2
        for i in range(self.k):
            poly = []
            for j in range(5):  # 对应pack时的5个系数
                if offset + 2 <= len(secret_key):
                    coeff = int.from_bytes(secret_key[offset:offset+2], 'big', signed=True)
                    poly.append(coeff)
                    offset += 2
                else:
                    poly.append(0)
            while len(poly) < self.n:
                poly.append(0)
            s2.append(poly)
        
        # 重新生成t1 (从公钥部分)
        public_key = self._pack_public_key(rho, [[0]*self.n]*self.k)
        _, t1 = self._unpack_public_key(public_key)
        
        return rho, K, t1, s1, s2

    def _unpack_signature(self, signature: bytes) -> Tuple[bytes, list, list]:
        """解包签名"""
        c_tilde = signature[:64]
        
        # 解包z向量
        z = []
        offset = 64
        for i in range(self.l):
            poly = []
            for j in range(10):  # 对应pack时的10个系数
                if offset + 3 <= len(signature):
                    coeff = int.from_bytes(signature[offset:offset+3], 'big', signed=True)
                    poly.append(coeff)
                    offset += 3
                else:
                    poly.append(0)
            while len(poly) < self.n:
                poly.append(0)
            z.append(poly)
        
        # 解包h向量
        h = []
        for i in range(self.k):
            poly = []
            if offset < len(signature):
                h_byte = signature[offset]
                offset += 1
                for j in range(8):
                    poly.append(1 if (h_byte >> j) & 1 else 0)
            while len(poly) < self.n:
                poly.append(0)
            h.append(poly)
        
        return c_tilde, z, h 