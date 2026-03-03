# OpenClaw Security Guard 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-Compatible-green.svg)](https://github.com/openclaw/openclaw)

🛡️ **全面的安全防护套件，为OpenClaw AI助手提供企业级安全保护**

[English](#english) | [中文](#中文)

---

## 中文

### 🎯 功能特性

#### 1. **实时威胁监控**
- 🔍 Skills代码安全扫描
- 🚨 恶意行为检测
- 📊 安全评分系统
- 🔔 实时告警通知

#### 2. **配置安全审计**
- 🔐 敏感信息检测（API密钥、密码等）
- 📝 配置文件验证
- 🛡️ 权限最小化检查
- ✅ 最佳实践建议

#### 3. **运行时保护**
- 📁 文件系统监控
- 🌐 网络请求审计
- ⚙️ 命令执行限制
- 🔒 沙箱隔离

#### 4. **安全报告**
- 📈 详细的安全报告
- 📊 可视化仪表板
- 📋 合规性检查
- 🔄 定期审计计划

### 🚀 快速开始

#### 安装

```bash
# 从GitHub安装
git clone https://github.com/yourusername/openclaw-security-guard.git
cd openclaw-security-guard
pip install -r requirements.txt

# 或使用pip安装（即将推出）
pip install openclaw-security-guard
```

#### 基本使用

```python
from security_guard import OpenClawSecurityGuard

# 初始化安全卫士
guard = OpenClawSecurityGuard()

# 扫描所有skills
report = guard.scan_all_skills()
print(report.summary())

# 实时监控
guard.start_realtime_monitoring()
```

#### 命令行使用

```bash
# 完整扫描
python -m security_guard scan --all

# 快速检查
python -m security_guard quick-check

# 生成报告
python -m security_guard report --output security_report.html

# 实时监控
python -m security_guard monitor
```

### 📊 安全评分系统

每个skill都会获得一个安全评分（0-100）：

| 分数 | 等级 | 说明 |
|------|------|------|
| 90-100 | 🟢 优秀 | 完全符合安全最佳实践 |
| 70-89 | 🟡 良好 | 有轻微问题需改进 |
| 50-69 | 🟠 中等 | 存在安全风险需处理 |
| 0-49 | 🔴 危险 | 严重安全问题，建议删除 |

### 🛡️ 检测能力

#### 恶意代码检测
- ✅ 代码注入（eval/exec）
- ✅ 反向Shell
- ✅ 数据窃取
- ✅ 挖矿代码
- ✅ 勒索软件

#### 配置安全
- ✅ 硬编码密钥
- ✅ 弱密码
- ✅ 不安全权限
- ✅ 敏感信息泄露

#### 行为监控
- ✅ 异常网络请求
- ✅ 可疑文件操作
- ✅ 危险命令执行
- ✅ 资源滥用

### 📈 使用统计

```bash
# 查看统计数据
python -m security_guard stats

输出示例：
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  OpenClaw Security Guard 统计
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
总Skills数:      63
安全Skills:      56
警告Skills:      5
危险Skills:      2
总扫描次数:      128
发现威胁:        7
已修复:          5
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 🔧 配置示例

```yaml
# security_guard.yaml
security_guard:
  scan:
    enable_deep_scan: true
    check_network: true
    check_files: true
    check_commands: true

  monitoring:
    enable_realtime: true
    alert_threshold: medium
    notification:
      email: admin@example.com
      telegram: "123456789"

  whitelist:
    - weather
    - stock-monitor
    - healthcheck

  rules:
    max_file_size: 10MB
    allowed_domains:
      - api.github.com
      - api.openai.com
    forbidden_commands:
      - rm -rf /
      - dd if=/dev/zero
```

### 🤝 贡献

欢迎贡献代码、报告bug或提出新功能建议！

```bash
# 开发环境设置
git clone https://github.com/yourusername/openclaw-security-guard.git
cd openclaw-security-guard
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

# 运行测试
pytest tests/

# 代码格式化
black security_guard/
```

### 💰 支持项目

如果这个项目对你有帮助，欢迎支持开发：

#### 加密货币捐赠

**Ethereum / BSC / Base:**
```
0x2F2E602b8fa520e9363773361A2e671d67f91902
```

**支持网络:**
- Ethereum Mainnet
- Binance Smart Chain (BSC)
- Base Network

#### 其他支持方式
- ⭐ Star这个仓库
- 🐛 报告Bug
- 💡 提出新功能建议
- 📢 推广给其他人

### 📜 许可证

MIT License - 详见 [LICENSE](LICENSE)

### 🙏 致谢

感谢所有为OpenClaw生态系统做出贡献的开发者！

---

## English

### 🎯 Features

#### 1. **Real-time Threat Monitoring**
- 🔍 Skills code security scanning
- 🚨 Malicious behavior detection
- 📊 Security scoring system
- 🔔 Real-time alerts

#### 2. **Configuration Security Audit**
- 🔐 Sensitive information detection
- 📝 Configuration validation
- 🛡️ Least privilege checking
- ✅ Best practices recommendations

#### 3. **Runtime Protection**
- 📁 Filesystem monitoring
- 🌐 Network request auditing
- ⚙️ Command execution restrictions
- 🔒 Sandbox isolation

#### 4. **Security Reports**
- 📈 Detailed security reports
- 📊 Visual dashboards
- 📋 Compliance checks
- 🔄 Scheduled audits

### 🚀 Quick Start

#### Installation

```bash
# Install from GitHub
git clone https://github.com/yourusername/openclaw-security-guard.git
cd openclaw-security-guard
pip install -r requirements.txt
```

#### Basic Usage

```python
from security_guard import OpenClawSecurityGuard

# Initialize security guard
guard = OpenClawSecurityGuard()

# Scan all skills
report = guard.scan_all_skills()
print(report.summary())

# Real-time monitoring
guard.start_realtime_monitoring()
```

### 💰 Support the Project

If this project helps you, consider supporting development:

#### Cryptocurrency Donations

**Ethereum / BSC / Base:**
```
0x2F2E602b8fa520e9363773361A2e671d67f91902
```

**Supported Networks:**
- Ethereum Mainnet
- Binance Smart Chain (BSC)
- Base Network

#### Other Ways to Support
- ⭐ Star this repo
- 🐛 Report bugs
- 💡 Suggest new features
- 📢 Spread the word

### 📜 License

MIT License - see [LICENSE](LICENSE)

---

## 📞 Contact

- GitHub Issues: [Report a bug](https://github.com/yourusername/openclaw-security-guard/issues)
- Email: security@example.com
- Discord: [Join our community](https://discord.gg/clawd)

---

**Made with ❤️ by the OpenClaw Community**
