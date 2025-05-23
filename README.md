# QACMF - 多级联动和可插拔密钥组件的抗量子密码迁移安全协议和框架

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

QACMF (Quantum-Aware Cryptography Migration Framework) 是一个全面的框架，旨在帮助组织和开发者将现有的密码系统迁移到抗量子密码学解决方案。随着量子计算的快速发展，传统的密码算法（如RSA和ECC）面临着被量子计算机破解的风险。QACMF提供了一套工具和方法，使这种迁移过程更加简单、安全和可靠。

## 主要特性

- **多层密钥管理**：实现主密钥和子密钥的分层管理，支持密钥的生成、存储、轮换和销毁
- **抗量子哈希链**：使用抗量子哈希算法实现密钥路径验证，确保密钥更新的连续性和完整性
- **插件系统**：支持动态加载不同的密码算法实现，包括后量子密码算法
- **安全沙箱**：为插件提供隔离的执行环境，防止恶意代码执行
- **配置管理**：灵活的配置系统，支持不同环境和应用场景
- **适配器接口**：提供与现有系统集成的适配器，简化迁移过程

### 1. **标准化算法集成**  
| 类型              | 算法组件（内置插件）                      | 合规认证               |  
|-------------------|------------------------------------------|-----------------------|  
| **密钥封装**      | CRYSTALS-Kyber、BIKE、NTRU                | NIST PQC Round 4 Finalist |  
| **数字签名**      | CRYSTALS-Dilithium、FALCON、SPHINCS+      | ISO/IEC 14888-3      |  
| **哈希与抗量子KDF**| SHA3-512、BLAKE3、PTHash（专利抗量子哈希）| NIST SP 800-208       |  
| **国密扩展**      | SM2/SM3/SM4抗量子变种（GM/T 0044-2023）   | 中国商用密码管理局认证 | 

## 项目根目录结构​​
```tree
qacmf-framework/
├── docs/                         # 文档中心
│   ├── framework-spec-v2.md      # 框架技术说明文档（Markdown）
│   ├── developer-guide.md        # 开发者插件开发指南
│   └── api-reference.md          # 核心API接口文档
├── src/                          # 核心代码
│   ├── qacmf/                    # Python包主模块
│   │   ├── core/                 # 核心引擎
│   │   ├── plugins/              # 内置算法插件
│   │   ├── adapters/             # 协议适配器
│   │   └── utils/                # 工具类
│   └── scripts/                  # 辅助脚本
├── tests/                        # 测试套件
│   ├── unit/                     # 单元测试
│   ├── integration/              # 集成测试
│   └── compliance/               # 合规性测试
├── examples/                     # 示例代码
│   ├── tls-hybrid/               # TLS混合模式示例
│   └── blockchain/               # 区块链双签名示例
├── config/                       # 配置文件模板
│   ├── default.yaml              # 默认配置
│   └── hsm-config.json           # HSM硬件配置模板
├── plugins/                      # 第三方插件目录
│   ├── kyber-1024/               # 插件示例
│   └── dilithium5/               # 插件示例
├── deployments/                  # 部署配置
│   ├── docker/
│   └── kubernetes/
├── .github/                      # CI/CD配置
│   └── workflows/
└── pyproject.toml                # 项目构建配置
```

## 二、核心代码文件说明
1. 核心引擎模块 (src/qacmf/core/)
```
| 文件名           | 功能说明                                    |
|------------------|--------------------------------------------|
| key_manager.py   | 多级密钥生命周期管理（生成 / 轮换 / 销毁）   |
| plugin_loader.py | 插件动态加载与沙箱隔离引擎                  |
| path_chain.py    | 抗量子哈希链的生成与验证逻辑                |
| quantum_rng.py   | 量子安全随机数生成器（集成 ANU QRNG API）    |
| policy_engine.py | 迁移策略决策引擎（自动回滚 / 算法切换）      |
```
2. 协议适配器 (src/qacmf/adapters/)
```
| 文件名               | 支持协议                          |
|----------------------|-----------------------------------|
| tls_adapter.py       | TLS 1.3 + 混合握手协议扩展        |
| ssh_adapter.py       | SSHv2 抗量子密钥交换实现          |
| blockchain_adapter.py| 区块链双签名交易协议封装          |
| ipsec_adapter.py     | IPSec/IKEv2 抗量子封装            |
```
3. 内置插件 (src/qacmf/plugins/)
```
| 文件名             | 算法类型                   |
|--------------------|---------------------------|
| kyber_plugin.py    | Kyber-1024 密钥封装        |
| dilithium_plugin.py| Dilithium5 数字签名        |
| xmss_plugin.py     | XMSS 抗量子哈希树          |
| sm2_pqc_plugin.py  | 国密 SM2 抗量子变种        |
```
## 三、关键配置文件​​
​​1. 主配置文件 (config/default.yaml)​​
```yaml
algorithm_layers:
  master_key:
    plugin: "pthash-v2"  # 抗量子哈希算法
    rotation_interval: "90d"
  sub_key1:
    plugin: "kyber-1024"
    hybrid_mode: "ecdh-secp384r1"
  path_chain:
    plugin: "xmss-l16"

protocols:
  tls:
    enabled: true
    cipher_suites: ["TLS_KYBER_AES256_SHA384"]
  blockchain:
    dual_signature: true

hardware:
  tpm:
    enabled: false
  hsm:
    config_path: "/etc/qacmf/hsm.json"
```
2. HSM硬件配置 (config/hsm-config.json)​
```
{
  "vendor": "Thales",
  "model": "Luna HSM 7",
  "key_slots": {
    "master_key": {"slot_id": 0, "access_policy": "dual_control"},
    "session_keys": {"slot_id": 1, "auto_rotate": true}
  }
}
```
## 四、测试与合规性文件​​
​​1. 测试用例 (tests/integration/test_tls_handshake.py)​
```
def test_hybrid_tls_handshake():
    client = TLSClient(config="hybrid")
    server = TLSServer()
    # 验证握手成功率与性能基线
    assert client.handshake(server) < 200ms
```
2. 合规性测试套件 (tests/compliance/nist_pqc_test.py)​
```
def test_kyber_nist_vectors():
    for vector in NIST_KYBER_VECTORS:
        assert validate_kyber(vector)
```
## 五、部署与运维文件​​
​​1. Docker镜像构建 (deployments/docker/Dockerfile)​
```
FROM python:3.11-slim
COPY src/qacmf /app/qacmf
RUN pip install . --no-cache-dir
CMD ["qacmf", "start", "--config", "/etc/qacmf/config.yaml"]
```
2. Kubernetes部署 (deployments/kubernetes/qacmf-deployment.yaml)​
```
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: qacmf
          image: qacmf:2.0
          volumeMounts:
            - name: hsm-keys
              mountPath: /etc/qacmf/keys
```

### 2. **硬件加速与可信执行环境**  
```yaml  
hardware_support:  
  - Intel QAT:  
      enabled: true  
      priority_algo: ["kyber-1024", "aes-256-gcm"]  
  - ARM TrustZone:  
      secure_enclave: true  
      key_storage: "/tee/qacmf_keys"  
  - TPM 2.0:  
      pq_extensions: ["kyber", "dilithium"]
```
##六、开发者工具与示例​​
​​1. 插件开发模板 (examples/plugin-template/)​
```
# kyber_plugin.py
class Kyber1024Plugin(QuantumPluginBase):
    def metadata(self):
        return {
            "type": "kem",
            "nist_level": 3,
            "key_sizes": {"kyber-1024": 1568}
        }
```
2. 区块链双签名示例 (examples/blockchain/dual_signing.py)​
```
tx = build_transaction(receiver="0x...")
tx_signed = sign_with_dilithium(tx) + sign_with_ecdsa(tx)
broadcast(tx_signed)
```

## 核心架构升级说明​​
## 1. ​​多级联动分层模型（增强版）​​
```
┌──────────────┐       ┌──────────────┐       ┌──────────────┐  
│ 主密钥层      │──派生──▶│ 子密钥层1     │──派生──▶│ 协议适配层     │  
│ (PQ根密钥)    │       │ (KEM/签名)    │       │ (TLS/IPSec)   │  
└──────┬────────┘       └──────┬────────┘       └──────┬────────┘  
       │                       │                       │  
       ▼                       ▼                       ▼  
┌──────────────┐       ┌──────────────┐       ┌────────────────┐  
│ 路径验证层    │◀──哈希链─┤ 子密钥层2     │◀──加密─┤ 量子安全熵源    │  
│ (XMSS/SHA3)  │       │ (对称加密)     │       │ (QRNG/TRNG)   │  
└──────────────┘       └──────────────┘       └────────────────┘  
```
二、核心架构升级说明
联动规则​​：
```
class QuantumPluginBase:  
    def metadata(self) -> dict:  
        return {  
            "type": "kem/signature/hash",  
            "nist_level": 1/2/3,  
            "key_sizes": {"kyber-1024": 1568},  
            "side_channel_resistance": True  
        }  
```
主密钥层仅用于派生初始子密钥
每个子密钥层支持独立插件替换
路径验证层强制绑定所有层级变更记录
2. ​​插件化扩展协议​​
​​插件接口规范（V2.0）​​：


## 插件热加载流程​​：
![image](https://github.com/user-attachments/assets/09712f5c-640c-42ce-b740-eb5ce2956648)

## 三、核心协议增强设计
1. ​​混合加密握手协议（Hybrid PQ-TLS）​​
​​性能指标​​：
```
场景	握手延迟（ms）	带宽开销（KB）
纯RSA-3072	120	2.1
Kyber-1024混合模式	145 (+20%)	5.8 (+176%)
```
2. ​​抗量子区块链交易协议​​
```
def sign_transaction(tx_data):  
    return {  
        "tx": tx_data,  
        "pq_signature": dilithium.sign(tx_hash),  
        "legacy_signature": ecdsa.sign(tx_hash)  
    }
```
## 3. ​​密钥生命周期管理协议​​
​​密钥轮换策略​​：
```
key_rotation:  
  master_key:  
    trigger: "time-based"  
    interval: "90 days"
```
## 四、迁移实施与运维
1. ​​三阶段迁移路线图​​
```
阶段	时间线	关键动作
​​试点验证​​	2024-2025	内部系统部署混合TLS
​​混合过渡​​	2026-2028	金融系统启用Dilithium签名
​​全面迁移​​	2029-2035	全行业淘汰RSA/ECC
```
3. ​​运维监控体系​​
# 安全态势扫描  
$ qacmf scan --target=*.example.com --protocol=tls  
五、开源生态与社区治理

## 七、典型应用场景
## 金融支付系统迁移
![image](https://github.com/user-attachments/assets/71bdd473-18f0-4e70-aaec-8db514ea8c5d)

2. ​​物联网设备升级​​
​​轻量级协议栈​​：
```
algorithm_layers:
  subkey_layer1:
    algorithm: "falcon-512"  # 签名算法
    optimized_for: "arm-cortex-m4"
  subkey_layer2:
    algorithm: "chacha20-poly1305"  # 轻量级加密
```

## 安装
### 使用 pip 安装

```bash
pip install qacmf
```
## 八、获取与贡献​​
​​项目地址​​：[[https://github.com/crystal-tensor/QACMF](https://github.com/crystal-tensor/QACMF)]
​​社区参与​​：提交插件需通过自动化合规测试，附抗量子安全证明。

## 贡献指南
## 我们欢迎并感谢所有形式的贡献。如果您想为QACMF做出贡献，请遵循以下步骤：

1. Fork 项目仓库
2. 创建您的特性分支 ( git checkout -b feature/amazing-feature )
3. 提交您的更改 ( git commit -m 'Add some amazing feature' )
4. 推送到分支 ( git push origin feature/amazing-feature )
5. 打开一个 Pull Request
## 许可证
## 本项目采用 MIT 许可证 - 详情请参阅 LICENSE 文件。

## 结语​​
## QACMF V2.0通过模块化架构、全协议覆盖和开放治理模型，为后量子迁移提供企业级解决方案。框架将持续跟踪NIST标准化进程，动态集成最优抗量子实践，构建量子安全新生态。
