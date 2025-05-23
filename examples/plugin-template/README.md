# QACMF插件开发模板

这个目录包含了开发QACMF框架插件的完整模板和指南。使用这些模板，开发者可以快速创建符合QACMF标准的量子安全算法插件。

## 目录结构

```
plugin-template/
├── README.md              # 本文档
├── plugin_template.py     # 插件模板代码
├── example_usage.py       # 使用示例
├── plugin_manifest.json   # 插件清单文件
└── tests/
    ├── test_template.py   # 模板测试
    └── performance_test.py # 性能测试
```

## 支持的插件类型

### 1. 密钥封装机制 (KEM)
- **用途**: 用于密钥交换和建立共享密钥
- **典型算法**: Kyber, SIKE, Classic McEliece
- **必须实现的方法**:
  - `generate_keypair()` - 生成密钥对
  - `encapsulate()` - 密钥封装
  - `decapsulate()` - 密钥解封装

### 2. 数字签名 (Signature)
- **用途**: 用于身份认证和数据完整性
- **典型算法**: Dilithium, Falcon, SPHINCS+
- **必须实现的方法**:
  - `generate_keypair()` - 生成密钥对
  - `sign()` - 数字签名
  - `verify()` - 签名验证

### 3. 哈希函数 (Hash)
- **用途**: 用于数据完整性和派生函数
- **典型算法**: SHAKE, Blake3-PQ
- **必须实现的方法**:
  - `hash()` - 计算哈希值
  - `hmac()` - 计算HMAC

## 快速开始

### 1. 创建新插件

```bash
# 复制模板
cp -r examples/plugin-template my-new-plugin/
cd my-new-plugin/

# 重命名主文件
mv plugin_template.py my_algorithm_plugin.py
```

### 2. 修改插件信息

编辑插件文件，设置基本信息：

```python
def __init__(self):
    super().__init__()
    
    # 设置插件基本信息
    self._name = "my-algorithm"          # 算法名称
    self._version = "1.0.0"              # 版本号
    self._algorithm_type = PluginType.KEM # 算法类型
    
    # 设置算法参数
    self.security_level = 3              # NIST安全级别
    self.public_key_length = 1568        # 公钥长度
    self.secret_key_length = 3168        # 私钥长度
```

### 3. 实现算法逻辑

根据算法类型，实现相应的核心方法：

```python
# KEM算法示例
def _perform_encapsulation(self, public_key: bytes, shared_secret: bytes) -> bytes:
    # TODO: 实现您的密钥封装算法
    pass

def _perform_decapsulation(self, secret_key: bytes, ciphertext: bytes) -> bytes:
    # TODO: 实现您的密钥解封装算法
    pass
```

### 4. 测试插件

```bash
# 运行基本测试
python my_algorithm_plugin.py

# 运行完整测试套件
python -m pytest tests/
```

## 插件清单文件

每个插件都需要一个 `plugin_manifest.json` 文件：

```json
{
  "name": "my-algorithm",
  "version": "1.0.0",
  "description": "我的量子安全算法插件",
  "author": "开发者姓名",
  "email": "developer@example.com",
  "license": "MIT",
  "algorithm_type": "kem",
  "nist_level": 3,
  "compliance": ["NIST PQC", "FIPS-Ready"],
  "dependencies": {
    "python": ">=3.8",
    "numpy": ">=1.20.0"
  },
  "entry_point": "my_algorithm_plugin:MyAlgorithmPlugin",
  "test_vectors": "tests/test_vectors.json"
}
```

## 开发指南

### 1. 安全考虑

- **常数时间实现**: 确保算法实现具有常数时间特性
- **侧信道抵抗**: 防范时序攻击、功耗分析等侧信道攻击
- **内存安全**: 及时清理敏感数据，防止内存泄露
- **随机数安全**: 使用密码学安全的随机数生成器

```python
def _secure_random(self, length: int) -> bytes:
    """生成密码学安全的随机数"""
    import secrets
    return secrets.token_bytes(length)

def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
    """常数时间比较"""
    import hmac
    return hmac.compare_digest(a, b)
```

### 2. 性能优化

- **预计算**: 预计算常用的值和表格
- **缓存**: 合理使用缓存机制
- **批处理**: 支持批量操作
- **内存管理**: 优化内存使用模式

```python
class OptimizedPlugin(TemplatePlugin):
    def __init__(self):
        super().__init__()
        # 预计算查找表
        self._precomputed_table = self._build_lookup_table()
    
    def _build_lookup_table(self):
        """构建预计算表"""
        # 实现预计算逻辑
        pass
```

### 3. 错误处理

```python
def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
    try:
        # 验证输入
        if not self._validate_public_key(public_key):
            raise ValueError("无效的公钥格式")
        
        # 执行算法
        return self._perform_encapsulation(public_key)
        
    except Exception as e:
        # 记录错误并重新抛出
        logger.error(f"密钥封装失败: {e}")
        raise
```

### 4. 测试覆盖

- **功能测试**: 验证算法正确性
- **边界测试**: 测试边界条件和异常情况
- **性能测试**: 验证性能要求
- **安全测试**: 验证安全属性
- **合规测试**: 验证NIST标准向量

```python
# tests/test_my_plugin.py
import unittest
from my_algorithm_plugin import MyAlgorithmPlugin

class TestMyAlgorithmPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = MyAlgorithmPlugin()
    
    def test_keypair_generation(self):
        """测试密钥对生成"""
        public_key, secret_key = self.plugin.generate_keypair()
        self.assertEqual(len(public_key), self.plugin.public_key_length)
        self.assertEqual(len(secret_key), self.plugin.secret_key_length)
    
    def test_encapsulation_decapsulation(self):
        """测试封装解封装"""
        public_key, secret_key = self.plugin.generate_keypair()
        ciphertext, shared_secret1 = self.plugin.encapsulate(public_key)
        shared_secret2 = self.plugin.decapsulate(secret_key, ciphertext)
        self.assertEqual(shared_secret1, shared_secret2)
```

## 性能基准

不同安全级别的性能要求：

| 操作 | Level 1 | Level 3 | Level 5 |
|------|---------|---------|---------|
| 密钥生成 | <5ms | <10ms | <20ms |
| 封装/签名 | <2ms | <5ms | <10ms |
| 解封装/验证 | <2ms | <5ms | <10ms |

## 集成到QACMF

### 1. 安装插件

```bash
# 安装到QACMF插件目录
cp -r my-new-plugin/ $QACMF_HOME/plugins/

# 或者使用pip安装
pip install my-qacmf-plugin
```

### 2. 注册插件

在配置文件中注册插件：

```yaml
# config/default.yaml
plugins:
  my-algorithm:
    enabled: true
    path: "plugins/my-new-plugin"
    priority: 1
```

### 3. 使用插件

```python
from qacmf.core.plugin_manager import PluginManager

# 加载插件
plugin_manager = PluginManager()
my_plugin = plugin_manager.get_plugin("my-algorithm")

# 使用插件
public_key, secret_key = my_plugin.generate_keypair()
```

## 发布插件

### 1. 创建包结构

```
my-qacmf-plugin/
├── setup.py
├── README.md
├── LICENSE
├── my_qacmf_plugin/
│   ├── __init__.py
│   └── plugin.py
└── tests/
    └── test_plugin.py
```

### 2. 编写setup.py

```python
from setuptools import setup, find_packages

setup(
    name="my-qacmf-plugin",
    version="1.0.0",
    description="My QACMF quantum-safe algorithm plugin",
    packages=find_packages(),
    install_requires=[
        "qacmf>=2.0.0",
    ],
    entry_points={
        'qacmf.plugins': [
            'my-algorithm = my_qacmf_plugin:MyAlgorithmPlugin',
        ],
    },
)
```

### 3. 发布到PyPI

```bash
# 构建包
python setup.py sdist bdist_wheel

# 发布
twine upload dist/*
```

## 常见问题

### Q: 如何处理大数运算？
A: 推荐使用 `gmpy2` 或 `sympy` 库进行高精度数学运算。

### Q: 如何优化内存使用？
A: 使用 `__slots__`、及时释放大对象、考虑使用生成器。

### Q: 如何确保线程安全？
A: 避免全局状态、使用锁机制、考虑使用不可变对象。

### Q: 如何添加自定义配置？
A: 在插件中实现 `load_config()` 方法，支持自定义配置参数。

## 支持和贡献

- **文档**: [QACMF插件开发指南](https://qacmf.readthedocs.io/plugins/)
- **示例**: [官方插件仓库](https://github.com/qacmf/plugins)
- **社区**: [开发者论坛](https://forum.qacmf.org/)
- **问题反馈**: [GitHub Issues](https://github.com/qacmf/framework/issues)

欢迎贡献代码和改进建议！ 