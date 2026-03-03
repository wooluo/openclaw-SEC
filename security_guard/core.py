"""
OpenClaw Security Guard - 核心安全引擎
企业级安全防护套件
"""

import os
import re
import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

class RiskLevel(Enum):
    """风险等级"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Threat:
    """威胁定义"""
    category: str
    description: str
    severity: RiskLevel
    location: str
    code_snippet: str
    recommendation: str

@dataclass
class SecurityReport:
    """安全报告"""
    skill_name: str
    scan_time: str
    score: int
    risk_level: RiskLevel
    threats: List[Threat] = field(default_factory=list)
    safe_items: List[str] = field(default_factory=list)
    
    def summary(self) -> str:
        """生成摘要"""
        emoji_map = {
            RiskLevel.SAFE: "🟢",
            RiskLevel.LOW: "🟢",
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.HIGH: "🟠",
            RiskLevel.CRITICAL: "🔴"
        }
        
        emoji = emoji_map[self.risk_level]
        summary = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  {emoji} {self.skill_name} 安全报告
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
扫描时间: {self.scan_time}
安全评分: {self.score}/100
风险等级: {self.risk_level.value.upper()}
威胁数量: {len(self.threats)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        return summary

class SecurityScanner:
    """安全扫描器"""
    
    def __init__(self, skills_dir: str = "/usr/lib/node_modules/openclaw/skills"):
        self.skills_dir = Path(skills_dir)
        self.logger = self._setup_logger()
        
        # 威胁模式库
        self.threat_patterns = {
            # 高危威胁
            "code_injection": {
                "patterns": [
                    r'exec\s*\(\s*base64',
                    r'eval\s*\(\s*base64',
                    r'compile\s*\(\s*base64',
                    r'__import__\s*\(\s*[\'"]base64',
                ],
                "severity": RiskLevel.CRITICAL,
                "description": "代码注入风险",
                "recommendation": "移除动态代码执行，使用安全的替代方案"
            },
            "reverse_shell": {
                "patterns": [
                    r'socket\.connect.*subprocess',
                    r'os\.system.*nc\s+',
                    r'subprocess\.Popen.*bash\s+-i',
                ],
                "severity": RiskLevel.CRITICAL,
                "description": "可能的反向Shell",
                "recommendation": "删除反向Shell代码，审查网络连接逻辑"
            },
            
            # 中危威胁
            "hardcoded_secrets": {
                "patterns": [
                    r'(password|passwd|pwd)\s*=\s*[\'"][^\'"]{8,}[\'"]',
                    r'(api_key|apikey)\s*=\s*[\'"][a-zA-Z0-9]{20,}[\'"]',
                    r'(secret|token)\s*=\s*[\'"][a-zA-Z0-9]{16,}[\'"]',
                ],
                "severity": RiskLevel.HIGH,
                "description": "硬编码的敏感信息",
                "recommendation": "使用环境变量或配置文件管理敏感信息"
            },
            "dangerous_commands": {
                "patterns": [
                    r'os\.system\s*\(\s*[\'"]rm\s+-rf',
                    r'subprocess\.(call|run).*rm\s+-rf',
                    r'shutil\.rmtree\s*\([^)]*\)',
                ],
                "severity": RiskLevel.HIGH,
                "description": "危险的系统命令",
                "recommendation": "添加安全确认，限制删除范围"
            },
            "unrestricted_network": {
                "patterns": [
                    r'requests\.(get|post)\s*\([^)]*user_input',
                    r'urllib\.request\.urlopen\s*\([^)]*\+',
                ],
                "severity": RiskLevel.MEDIUM,
                "description": "不受限制的网络请求",
                "recommendation": "添加URL白名单验证"
            },
            
            # 低危威胁
            "weak_crypto": {
                "patterns": [
                    r'hashlib\.md5\s*\(',
                    r'hashlib\.sha1\s*\(',
                ],
                "severity": RiskLevel.LOW,
                "description": "弱加密算法",
                "recommendation": "使用SHA256或更强的加密算法"
            },
            "debug_code": {
                "patterns": [
                    r'print\s*\([^)]*password',
                    r'logging\.(debug|info)\s*\([^)]*secret',
                ],
                "severity": RiskLevel.LOW,
                "description": "调试代码可能泄露信息",
                "recommendation": "移除调试输出"
            }
        }
        
        # 白名单（已知安全的skills）
        self.whitelist = {
            "weather", "stock-monitor", "stock-quote", "stock-trading",
            "finance-news", "skill-creator", "healthcheck"
        }
    
    def _setup_logger(self):
        """设置日志"""
        logger = logging.getLogger("OpenClawSecurityGuard")
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def scan_skill(self, skill_path: Path) -> SecurityReport:
        """扫描单个skill"""
        skill_name = skill_path.name
        
        # 白名单检查
        if skill_name in self.whitelist:
            return SecurityReport(
                skill_name=skill_name,
                scan_time=datetime.now().isoformat(),
                score=100,
                risk_level=RiskLevel.SAFE,
                safe_items=["白名单skill，已确认安全"]
            )
        
        threats = []
        safe_items = []
        
        # 扫描Python文件
        for py_file in skill_path.rglob("*.py"):
            file_threats, file_safe = self._scan_python_file(py_file, skill_name)
            threats.extend(file_threats)
            safe_items.extend(file_safe)
        
        # 扫描Shell脚本
        for sh_file in skill_path.rglob("*.sh"):
            file_threats, file_safe = self._scan_shell_file(sh_file, skill_name)
            threats.extend(file_threats)
            safe_items.extend(file_safe)
        
        # 扫描配置文件
        for config_file in skill_path.rglob("*.json"):
            file_threats, file_safe = self._scan_config_file(config_file, skill_name)
            threats.extend(file_threats)
            safe_items.extend(file_safe)
        
        # 计算安全评分
        score = self._calculate_score(threats)
        risk_level = self._determine_risk_level(score)
        
        return SecurityReport(
            skill_name=skill_name,
            scan_time=datetime.now().isoformat(),
            score=score,
            risk_level=risk_level,
            threats=threats,
            safe_items=safe_items
        )
    
    def _scan_python_file(self, file_path: Path, skill_name: str) -> Tuple[List[Threat], List[str]]:
        """扫描Python文件"""
        threats = []
        safe_items = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # 检查威胁模式
            for threat_type, threat_info in self.threat_patterns.items():
                for pattern in threat_info["patterns"]:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                        
                        threat = Threat(
                            category=threat_type,
                            description=threat_info["description"],
                            severity=threat_info["severity"],
                            location=f"{file_path.relative_to(self.skills_dir)}:{line_num}",
                            code_snippet=line_content[:100],
                            recommendation=threat_info["recommendation"]
                        )
                        threats.append(threat)
            
            # 检查安全实践
            if 'import logging' in content:
                safe_items.append(f"{file_path.name}: 使用日志记录")
            
            if re.search(r'raise\s+\w+Error', content):
                safe_items.append(f"{file_path.name}: 使用异常处理")
            
            if 'os.environ.get' in content:
                safe_items.append(f"{file_path.name}: 使用环境变量")
                
        except Exception as e:
            self.logger.error(f"扫描文件失败 {file_path}: {e}")
        
        return threats, safe_items
    
    def _scan_shell_file(self, file_path: Path, skill_name: str) -> Tuple[List[Threat], List[str]]:
        """扫描Shell脚本"""
        threats = []
        safe_items = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 检查危险命令
            dangerous_commands = [
                (r'curl.*\|\s*bash', "远程代码执行"),
                (r'wget.*\|\s*bash', "远程代码执行"),
                (r'rm\s+-rf\s+/', "递归删除根目录"),
            ]
            
            for pattern, desc in dangerous_commands:
                if re.search(pattern, content):
                    threat = Threat(
                        category="dangerous_command",
                        description=f"Shell脚本中的危险命令: {desc}",
                        severity=RiskLevel.CRITICAL,
                        location=str(file_path.relative_to(self.skills_dir)),
                        code_snippet=pattern,
                        recommendation="移除危险命令，使用安全的替代方案"
                    )
                    threats.append(threat)
            
            # 检查安全实践
            if 'set -e' in content:
                safe_items.append(f"{file_path.name}: 使用错误退出")
            
            if re.search(r'\$\{1:\?', content):
                safe_items.append(f"{file_path.name}: 参数验证")
                
        except Exception as e:
            self.logger.error(f"扫描Shell文件失败 {file_path}: {e}")
        
        return threats, safe_items
    
    def _scan_config_file(self, file_path: Path, skill_name: str) -> Tuple[List[Threat], List[str]]:
        """扫描配置文件"""
        threats = []
        safe_items = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 检查敏感信息
            sensitive_patterns = [
                (r'"password"\s*:\s*"[^"]{8,}"', "密码"),
                (r'"api_key"\s*:\s*"[a-zA-Z0-9]{20,}"', "API密钥"),
                (r'"secret"\s*:\s*"[a-zA-Z0-9]{16,}"', "密钥"),
            ]
            
            for pattern, info_type in sensitive_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    # 检查是否是占位符
                    if not re.search(r'(your_|xxx|sample|placeholder)', content, re.IGNORECASE):
                        threat = Threat(
                            category="sensitive_data",
                            description=f"配置文件中包含实际的{info_type}",
                            severity=RiskLevel.HIGH,
                            location=str(file_path.relative_to(self.skills_dir)),
                            code_snippet=f"包含{info_type}",
                            recommendation="使用环境变量替换敏感信息"
                        )
                        threats.append(threat)
            
            # 检查安全实践
            if 'timeout' in content:
                safe_items.append(f"{file_path.name}: 设置超时")
                
        except Exception as e:
            pass  # 忽略JSON解析错误
        
        return threats, safe_items
    
    def _calculate_score(self, threats: List[Threat]) -> int:
        """计算安全评分"""
        score = 100
        
        for threat in threats:
            if threat.severity == RiskLevel.CRITICAL:
                score -= 30
            elif threat.severity == RiskLevel.HIGH:
                score -= 20
            elif threat.severity == RiskLevel.MEDIUM:
                score -= 10
            elif threat.severity == RiskLevel.LOW:
                score -= 5
        
        return max(0, score)
    
    def _determine_risk_level(self, score: int) -> RiskLevel:
        """确定风险等级"""
        if score >= 90:
            return RiskLevel.SAFE
        elif score >= 70:
            return RiskLevel.LOW
        elif score >= 50:
            return RiskLevel.MEDIUM
        elif score >= 30:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

class OpenClawSecurityGuard:
    """OpenClaw安全卫士主类"""
    
    def __init__(self, skills_dir: str = "/usr/lib/node_modules/openclaw/skills"):
        self.scanner = SecurityScanner(skills_dir)
        self.logger = self.scanner.logger
    
    def scan_all_skills(self) -> Dict:
        """扫描所有skills"""
        self.logger.info("开始扫描所有skills...")
        
        skills = [d for d in self.scanner.skills_dir.iterdir() if d.is_dir()]
        reports = []
        
        for skill_dir in skills:
            self.logger.info(f"扫描: {skill_dir.name}")
            report = self.scanner.scan_skill(skill_dir)
            reports.append(report)
        
        # 生成汇总报告
        summary = self._generate_summary(reports)
        
        return {
            "reports": reports,
            "summary": summary
        }
    
    def _generate_summary(self, reports: List[SecurityReport]) -> str:
        """生成汇总报告"""
        total = len(reports)
        safe = sum(1 for r in reports if r.risk_level in [RiskLevel.SAFE, RiskLevel.LOW])
        warning = sum(1 for r in reports if r.risk_level == RiskLevel.MEDIUM)
        danger = sum(1 for r in reports if r.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL])
        
        avg_score = sum(r.score for r in reports) / total if total > 0 else 0
        
        summary = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  OpenClaw Security Guard 汇总报告
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Skills总数: {total}
平均安全分: {avg_score:.1f}/100

安全状态分布:
  🟢 安全: {safe} ({safe/total*100:.1f}%)
  🟡 警告: {warning} ({warning/total*100:.1f}%)
  🔴 危险: {danger} ({danger/total*100:.1f}%)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        return summary
    
    def quick_check(self) -> bool:
        """快速安全检查"""
        self.logger.info("执行快速安全检查...")
        
        # 检查关键安全问题
        critical_issues = []
        
        # 1. 检查硬编码密钥
        for py_file in self.scanner.skills_dir.rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                if re.search(r'(api_key|password|secret)\s*=\s*["\'][a-zA-Z0-9]{16,}["\']', content):
                    critical_issues.append(f"{py_file}: 硬编码敏感信息")
            except:
                pass
        
        # 2. 检查远程代码执行
        for sh_file in self.scanner.skills_dir.rglob("*.sh"):
            try:
                with open(sh_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                if re.search(r'(curl|wget).*\|\s*(bash|sh)', content):
                    critical_issues.append(f"{sh_file}: 远程代码执行")
            except:
                pass
        
        if critical_issues:
            self.logger.warning(f"发现 {len(critical_issues)} 个关键安全问题:")
            for issue in critical_issues:
                self.logger.warning(f"  - {issue}")
            return False
        else:
            self.logger.info("✅ 快速检查通过")
            return True

def main():
    """主函数"""
    guard = OpenClawSecurityGuard()
    
    # 扫描所有skills
    result = guard.scan_all_skills()
    print(result["summary"])
    
    # 显示危险skills
    for report in result["reports"]:
        if report.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            print(report.summary())
            for threat in report.threats:
                print(f"  ❌ {threat.description}")
                print(f"     位置: {threat.location}")
                print(f"     建议: {threat.recommendation}")

if __name__ == '__main__':
    main()
