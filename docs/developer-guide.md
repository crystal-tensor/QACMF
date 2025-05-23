# QACMF 插件开发指南

## 1. 插件架构概述
QACMF 支持插件化扩展，开发者可通过实现标准接口快速集成新算法。

## 2. 插件类型
- 密钥封装（KEM）
- 数字签名（Signature）
- 哈希/密钥派生（Hash/KDF）
- 国密扩展

## 3. 插件目录结构
```
plugins/
  ├── your_plugin/
  │   ├── __init__.py
  │   └── your_plugin.py
```

## 4. 插件接口规范
```python
class QuantumPluginBase:
    def metadata(self) -> dict:
        pass
    def encrypt(self, data: bytes) -> bytes:
        pass
    def decrypt(self, data: bytes) -> bytes:
        pass
```

## 5. 插件注册与热加载
- 插件需在 `pyproject.toml` 或 `setup.py` 中声明 entry_points
- 支持运行时动态加载与沙箱隔离

## 6. 合规性与测试
- 插件需通过自动化合规测试
- 提供 NIST/国密标准向量验证

## 7. 贡献流程
1. Fork 仓库并新建分支
2. 按模板开发插件
3. 补充测试用例
4. 提交 Pull Request

---
详细接口与示例请参考 `examples/plugin-template/` 目录。