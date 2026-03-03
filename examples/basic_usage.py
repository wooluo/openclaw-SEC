#!/usr/bin/env python3
"""
OpenClaw Security Guard - 使用示例
"""

from security_guard import OpenClawSecurityGuard, RiskLevel

def example_basic_scan():
    """基本扫描示例"""
    print("="*60)
    print("  示例1: 基本扫描")
    print("="*60)
    print()
    
    # 创建安全卫士实例
    guard = OpenClawSecurityGuard()
    
    # 扫描所有skills
    result = guard.scan_all_skills()
    
    # 打印汇总
    print(result["summary"])
    
    # 显示危险skills
    print("\n🔴 危险Skills:")
    for report in result["reports"]:
        if report.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            print(f"\n  {report.skill_name}:")
            print(f"    评分: {report.score}/100")
            print(f"    威胁: {len(report.threats)}个")
            for threat in report.threats[:3]:  # 只显示前3个
                print(f"      - {threat.description}")

def example_quick_check():
    """快速检查示例"""
    print("\n" + "="*60)
    print("  示例2: 快速安全检查")
    print("="*60)
    print()
    
    guard = OpenClawSecurityGuard()
    
    # 快速检查
    is_safe = guard.quick_check()
    
    if is_safe:
        print("✅ 系统安全，未发现关键问题")
    else:
        print("❌ 发现安全问题，需要立即处理")

def example_specific_skill():
    """扫描特定skill示例"""
    print("\n" + "="*60)
    print("  示例3: 扫描特定Skill")
    print("="*60)
    print()
    
    from pathlib import Path
    from security_guard import SecurityScanner
    
    scanner = SecurityScanner()
    
    # 扫描weather skill（已知安全）
    weather_path = Path("/usr/lib/node_modules/openclaw/skills/weather")
    if weather_path.exists():
        report = scanner.scan_skill(weather_path)
        print(report.summary())
        
        if report.safe_items:
            print("\n安全实践:")
            for item in report.safe_items[:5]:
                print(f"  ✅ {item}")

def example_save_report():
    """保存报告示例"""
    print("\n" + "="*60)
    print("  示例4: 生成并保存报告")
    print("="*60)
    print()
    
    guard = OpenClawSecurityGuard()
    result = guard.scan_all_skills()
    
    # 保存文本报告
    report_file = "/tmp/security_report.txt"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(result["summary"])
        for report in result["reports"]:
            f.write(str(report.summary()))
    
    print(f"✅ 报告已保存: {report_file}")

def example_monitor_mode():
    """监控模式示例"""
    print("\n" + "="*60)
    print("  示例5: 监控模式")
    print("="*60)
    print()
    
    import time
    
    guard = OpenClawSecurityGuard()
    
    print("🔍 开始监控... (模拟3次检查)")
    for i in range(3):
        print(f"\n第 {i+1} 次检查:")
        is_safe = guard.quick_check()
        
        if is_safe:
            print("  ✅ 安全")
        else:
            print("  ❌ 发现问题")
        
        time.sleep(1)
    
    print("\n✅ 监控结束")

def example_statistics():
    """统计示例"""
    print("\n" + "="*60)
    print("  示例6: 安全统计")
    print("="*60)
    print()
    
    guard = OpenClawSecurityGuard()
    result = guard.scan_all_skills()
    
    reports = result["reports"]
    total = len(reports)
    
    # 统计各级别数量
    safe = sum(1 for r in reports if r.risk_level in [RiskLevel.SAFE, RiskLevel.LOW])
    warning = sum(1 for r in reports if r.risk_level == RiskLevel.MEDIUM)
    danger = sum(1 for r in reports if r.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL])
    
    # 统计威胁总数
    total_threats = sum(len(r.threats) for r in reports)
    
    # 计算平均分
    avg_score = sum(r.score for r in reports) / total if total > 0 else 0
    
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  安全统计")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"Skills总数:      {total}")
    print(f"平均安全分:      {avg_score:.1f}/100")
    print(f"安全Skills:      {safe} ({safe/total*100:.1f}%)")
    print(f"警告Skills:      {warning} ({warning/total*100:.1f}%)")
    print(f"危险Skills:      {danger} ({danger/total*100:.1f}%)")
    print(f"发现威胁:        {total_threats}个")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

if __name__ == '__main__':
    print("\n🛡️ OpenClaw Security Guard - 使用示例\n")
    
    # 运行所有示例
    example_basic_scan()
    example_quick_check()
    example_specific_skill()
    example_save_report()
    example_monitor_mode()
    example_statistics()
    
    print("\n✅ 所有示例运行完成！\n")
