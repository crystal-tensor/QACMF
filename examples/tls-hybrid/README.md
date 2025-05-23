# TLS混合模式示例

这个示例展示了如何使用QACMF框架实现抗量子TLS握手协议。它演示了传统密码学算法与后量子密码学算法的混合使用，确保向后兼容性和前向安全性。

## 功能特性

- **混合密钥交换**: 使用Kyber-1024与ECDH的混合模式
- **抗量子数字签名**: 使用Dilithium5进行身份认证
- **会话密钥派生**: 基于HKDF的安全密钥派生
- **应用数据加密**: 使用AES-256-GCM加密应用层数据

## 架构设计

```
客户端                          服务器
   |                              |
   |-- ClientHello -------------->|
   |                              |
   |<-- ServerHello + Kyber-PK ---|
   |                              |
   |-- Kyber-Ciphertext -------->|
   |                              |
   |<-- ServerFinished ----------|
   |                              |
   |== 应用数据加密传输 ==========|
```

## 安全参数

| 组件 | 算法 | 安全级别 | 密钥长度 |
|------|------|----------|----------|
| 密钥封装 | Kyber-1024 | NIST Level 5 | 1568 bytes |
| 数字签名 | Dilithium5 | NIST Level 5 | 2592 bytes |
| 会话加密 | AES-256-GCM | 256-bit | 32 bytes |
| 密钥派生 | HKDF-SHA256 | 256-bit | - |

## 运行示例

### 启动服务器

```bash
cd examples/tls-hybrid/
python hybrid_tls_demo.py
```

服务器将在localhost:8443上监听连接。

### 运行客户端

在另一个终端中运行：

```bash
python hybrid_tls_demo.py client
```

## 示例输出

### 服务器端
```
INFO:__main__:生成抗量子密钥对...
INFO:__main__:Kyber公钥长度: 1568 字节
INFO:__main__:Dilithium公钥长度: 2592 字节
INFO:__main__:混合TLS服务器启动在 ('127.0.0.1', 8443)
INFO:__main__:新客户端连接: ('127.0.0.1', 54321)
INFO:__main__:开始混合TLS握手...
INFO:__main__:收到客户端密钥交换: 1572 字节
INFO:__main__:成功解封装共享密钥: 32 字节
INFO:__main__:混合TLS握手完成
INFO:__main__:收到消息: b'Hello, Quantum-Safe TLS!'
```

### 客户端
```
INFO:__main__:连接到 localhost:8443
INFO:__main__:开始客户端握手...
INFO:__main__:收到服务器Hello: 1698 字节
INFO:__main__:客户端握手完成
INFO:__main__:服务器响应: b'Echo: Hello, Quantum-Safe TLS!'
```

## 性能指标

在现代硬件上的典型性能表现：

| 操作 | 延迟 | 吞吐量 |
|------|------|--------|
| 握手延迟 | ~25ms | - |
| 密钥生成 | ~2ms | 500 ops/s |
| 封装/解封装 | ~1ms | 1000 ops/s |
| 签名/验证 | ~5ms | 200 ops/s |

## 协议扩展

### 自定义TLS扩展

```
Extension Type: 0xFF01 (Kyber Public Key)
Extension Data:
  - Length: 2 bytes
  - Kyber-1024 Public Key: 1568 bytes
```

### 密码套件

```
TLS_KYBER_AES256_SHA384 (0x1337)
  - Key Exchange: Kyber-1024
  - Authentication: Dilithium5
  - Encryption: AES-256-GCM
  - Hash: SHA-384
```

## 安全考虑

1. **量子安全性**: 所有密码学组件都能抵抗量子计算攻击
2. **前向安全性**: 每次连接使用新的临时密钥
3. **混合安全性**: 结合传统和后量子算法的优势
4. **身份认证**: 使用Dilithium5确保通信方身份

## 局限性

- 这是一个简化的演示实现，不应在生产环境中使用
- 缺少完整的TLS状态机和错误处理
- 未实现证书验证和信任链管理
- 性能未针对生产环境优化

## 下一步

- 查看完整的TLS适配器实现: `src/qacmf/adapters/tls_adapter.py`
- 了解密钥管理: `src/qacmf/core/key_manager.py`
- 学习插件开发: `examples/plugin-template/` 