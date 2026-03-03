# 贡献指南

感谢你考虑为 OpenClaw Security Guard 做贡献！

## 🤝 如何贡献

### 报告Bug

如果你发现了bug，请：

1. 检查是否已经有相同的问题被报告
2. 创建一个新的Issue，包含：
   - 详细的问题描述
   - 复现步骤
   - 期望行为
   - 实际行为
   - 环境信息（Python版本、操作系统等）

### 提出新功能

如果你有新功能的想法：

1. 先创建一个Issue讨论你的想法
2. 等待维护者反馈
3. 实现功能并提交Pull Request

### 提交代码

1. Fork这个仓库
2. 创建你的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交你的修改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启一个Pull Request

## 📝 代码规范

### Python代码

- 遵循 PEP 8 规范
- 使用 Black 格式化代码
- 添加类型提示
- 编写文档字符串

```python
def scan_file(filepath: Path) -> List[Threat]:
    """
    扫描文件并返回发现的威胁列表
    
    Args:
        filepath: 要扫描的文件路径
        
    Returns:
        发现的威胁列表
        
    Raises:
        FileNotFoundError: 文件不存在
    """
    # 实现...
```

### 测试

- 为新功能编写测试
- 确保所有测试通过
- 保持测试覆盖率

```bash
# 运行测试
pytest tests/

# 查看覆盖率
pytest --cov=security_guard tests/
```

## 🏗️ 开发环境设置

```bash
# 克隆仓库
git clone https://github.com/yourusername/openclaw-security-guard.git
cd openclaw-security-guard

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或 venv\Scripts\activate  # Windows

# 安装开发依赖
pip install -r requirements-dev.txt

# 安装pre-commit钩子
pre-commit install
```

## 📋 Pull Request检查清单

- [ ] 代码遵循项目的代码规范
- [ ] 进行了自我审查
- [ ] 添加了必要的注释
- [ ] 更新了相关文档
- [ ] 添加了测试
- [ ] 所有测试通过
- [ ] 代码通过静态分析

## 💰 支持项目

如果你无法贡献代码，也可以通过其他方式支持：

### 加密货币捐赠

**Ethereum / BSC / Base:**
```
0x2F2E602b8fa520e9363773361A2e671d67f91902
```

**支持网络:**
- Ethereum Mainnet
- Binance Smart Chain (BSC)
- Base Network

### 其他方式

- ⭐ Star这个仓库
- 📢 推广给其他人
- 💬 在社交媒体上分享
- 🐛 报告bug
- 💡 提出改进建议

## 📜 许可证

通过贡献代码，你同意你的代码将以MIT许可证发布。

## 🙏 感谢

感谢所有贡献者的付出！

---

**Happy Coding! 🎉**
