#!/usr/bin/env python3
"""
OpenClaw Security Guard - Command Line Interface
"""

import argparse
import sys
from pathlib import Path
from security_guard.core import OpenClawSecurityGuard, RiskLevel

def main():
    parser = argparse.ArgumentParser(
        description="🛡️ OpenClaw Security Guard - 企业级安全防护套件",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 扫描所有skills
  security-guard scan --all
  
  # 快速检查
  security-guard quick-check
  
  # 生成报告
  security-guard report --output report.html
  
  # 监控模式
  security-guard monitor
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # scan命令
    scan_parser = subparsers.add_parser("scan", help="扫描skills")
    scan_parser.add_argument("--all", action="store_true", help="扫描所有skills")
    scan_parser.add_argument("--skill", type=str, help="扫描指定skill")
    scan_parser.add_argument("--output", type=str, help="输出文件路径")
    
    # quick-check命令
    subparsers.add_parser("quick-check", help="快速安全检查")
    
    # report命令
    report_parser = subparsers.add_parser("report", help="生成报告")
    report_parser.add_argument("--output", type=str, default="security_report.txt", help="输出文件")
    report_parser.add_argument("--format", choices=["txt", "html", "json"], default="txt", help="报告格式")
    
    # monitor命令
    subparsers.add_parser("monitor", help="实时监控")
    
    # stats命令
    subparsers.add_parser("stats", help="查看统计")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    guard = OpenClawSecurityGuard()
    
    if args.command == "scan":
        if args.all:
            result = guard.scan_all_skills()
            print(result["summary"])
            
            # 保存报告
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(result["summary"])
                    for report in result["reports"]:
                        f.write(str(report.summary()))
                print(f"\n✅ 报告已保存: {args.output}")
        
        elif args.skill:
            skill_path = Path(guard.scanner.skills_dir) / args.skill
            if skill_path.exists():
                report = guard.scanner.scan_skill(skill_path)
                print(report.summary())
            else:
                print(f"❌ Skill不存在: {args.skill}")
                sys.exit(1)
    
    elif args.command == "quick-check":
        is_safe = guard.quick_check()
        sys.exit(0 if is_safe else 1)
    
    elif args.command == "report":
        result = guard.scan_all_skills()
        
        if args.format == "json":
            import json
            report_data = {
                "summary": result["summary"],
                "reports": [
                    {
                        "skill": r.skill_name,
                        "score": r.score,
                        "risk_level": r.risk_level.value,
                        "threats_count": len(r.threats)
                    }
                    for r in result["reports"]
                ]
            }
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        else:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(result["summary"])
        
        print(f"✅ 报告已生成: {args.output}")
    
    elif args.command == "monitor":
        print("🔍 实时监控模式")
        print("按 Ctrl+C 退出")
        try:
            while True:
                guard.quick_check()
                import time
                time.sleep(60)  # 每分钟检查一次
        except KeyboardInterrupt:
            print("\n✅ 监控已停止")
    
    elif args.command == "stats":
        result = guard.scan_all_skills()
        
        reports = result["reports"]
        total = len(reports)
        safe = sum(1 for r in reports if r.risk_level in [RiskLevel.SAFE, RiskLevel.LOW])
        warning = sum(1 for r in reports if r.risk_level == RiskLevel.MEDIUM)
        danger = sum(1 for r in reports if r.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL])
        
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("  OpenClaw Security Guard 统计")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"总Skills数:      {total}")
        print(f"安全Skills:      {safe}")
        print(f"警告Skills:      {warning}")
        print(f"危险Skills:      {danger}")
        print(f"总扫描次数:      1")
        print(f"发现威胁:        {sum(len(r.threats) for r in reports)}")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

if __name__ == '__main__':
    main()
