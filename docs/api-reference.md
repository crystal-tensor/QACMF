# QACMF 核心API接口文档

## 1. 概述
本文件描述QACMF框架核心模块、插件、适配器等API接口，便于开发者集成与二次开发。

## 2. 核心引擎API
### key_manager.py
- `generate_master_key()`：生成主密钥
- `rotate_key()`：密钥轮换
- `destroy_key()`：销毁密钥

### plugin_loader.py
- `load_plugin(name: str)`：动态加载插件
- `sandbox_execute(plugin, data)`：沙箱隔离执行

### path_chain.py
- `generate_chain()`：生成抗量子哈希链
- `verify_chain()`：验证链完整性

### quantum_rng.py
- `get_random_bytes(n: int)`：获取量子安全随机数

### policy_engine.py
- `decide_policy(context)`：迁移策略决策

## 3. 协议适配器API
### tls_adapter.py
- `init_tls_handshake()`：初始化TLS混合握手
### ssh_adapter.py
- `init_ssh_kex()`：SSH PQ密钥交换
### blockchain_adapter.py
- `sign_transaction(tx)`：区块链双签名
### ipsec_adapter.py
- `init_ipsec_session()`：IPSec PQ会话

## 4. 插件接口API
- `metadata()`：返回插件元信息
- `encrypt(data)`/`decrypt(data)`：加解密
- `sign(data)`/`verify(data, sig)`：签名与验签

## 5. 工具与脚本API
- 通用工具函数、配置加载、日志等

---
详细参数与用法请参考源码及开发者指南。