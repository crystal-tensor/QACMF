# QACMF 框架技术说明文档（V2.0）

## 1. 项目简介
QACMF（Quantum-Aware Cryptography Migration Framework）是面向抗量子安全迁移的企业级密码框架，支持多层密钥管理、插件化算法扩展、协议适配与合规性测试。

## 2. 架构设计
- 多级密钥生命周期管理
- 抗量子哈希链路径验证
- 插件热加载与沙箱隔离
- 协议适配层（TLS、SSH、区块链、IPSec等）
- 配置与硬件加速支持

## 3. 主要模块
- core：核心引擎（key_manager、plugin_loader、path_chain、quantum_rng、policy_engine）
- adapters：协议适配器
- plugins：内置及第三方算法插件
- utils：通用工具

## 4. 算法与协议支持
- Kyber、Dilithium、XMSS、SM2 PQC等
- TLS 1.3混合模式、SSH PQ-KEX、区块链双签名、IPSec PQ扩展

## 5. 配置与部署
- 支持YAML/JSON配置模板
- Docker/Kubernetes一键部署

## 6. 合规与测试
- NIST PQC、国密、ISO/IEC 14888-3等标准
- 单元、集成、合规性测试套件

## 7. 贡献与社区
- 插件开发接口与热加载规范
- 自动化合规测试与社区治理

---
详细技术细节请参考各子模块源码与API文档。