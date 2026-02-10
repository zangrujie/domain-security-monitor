#!/usr/bin/env python3
"""
验证Web界面数据加载
"""

import sys
import os
import json
from pathlib import Path

# 添加模块路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def verify_web_data():
    """验证Web界面数据加载"""
    
    print("验证Web界面数据加载")
    print("=" * 50)
    
    base_dir = Path('.')
    
    # 1. 检查domain_variants目录
    print("\n1. 检查domain_variants目录:")
    variants_dir = base_dir / "domain_variants"
    if variants_dir.exists():
        dirs = [d for d in variants_dir.iterdir() if d.is_dir()]
        print(f"   ✅ 存在，包含 {len(dirs)} 个域名目录")
        
        # 检查deepseek.com目录
        deepseek_dir = variants_dir / "deepseek.com"
        if deepseek_dir.exists():
            print(f"   ✅ deepseek.com目录存在")
            files = list(deepseek_dir.iterdir())
            print(f"     包含 {len(files)} 个文件:")
            for f in files:
                if f.is_file():
                    print(f"     - {f.name}")
                    
                    # 读取文件内容示例
                    if f.name == "high_risk.txt":
                        try:
                            with open(f, 'r', encoding='utf-8') as file:
                                lines = [line.strip() for line in file if line.strip()]
                                print(f"       高风险变体数量: {len(lines)}")
                                if lines:
                                    print(f"       示例: {lines[:3]}...")
                        except:
                            pass
        else:
            print(f"   ❌ deepseek.com目录不存在")
    else:
        print(f"   ❌ domain_variants目录不存在")
    
    # 2. 检查monitoring_results目录
    print("\n2. 检查monitoring_results目录:")
    results_dir = base_dir / "monitoring_results"
    if results_dir.exists():
        files = list(results_dir.iterdir())
        print(f"   ✅ 存在，包含 {len(files)} 个文件")
        
        # 检查各结果文件
        result_files = {
            "http_scan_results.json": "HTTP扫描结果",
            "whois_results.json": "WHOIS查询结果",
            "threat_intel_results.json": "威胁情报结果",
            "comprehensive_results.json": "综合评估结果"
        }
        
        for filename, description in result_files.items():
            file_path = results_dir / filename
            if file_path.exists():
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                    print(f"   ✅ {description}: {len(data) if isinstance(data, list) else '有效数据'}")
                    
                    # 检查是否有deepseek.com相关数据
                    if isinstance(data, list) and data:
                        deepseek_count = sum(1 for item in data if isinstance(item, dict) and 'domain' in item and 'deepseek' in item['domain'].lower())
                        if deepseek_count > 0:
                            print(f"       包含 {deepseek_count} 个deepseek.com相关记录")
                        else:
                            print(f"       不包含deepseek.com相关记录")
                except Exception as e:
                    print(f"   ⚠️  {description}: 读取失败 ({e})")
            else:
                print(f"   ❌ {description}: 文件不存在")
    else:
        print(f"   ❌ monitoring_results目录不存在")
    
    # 3. 检查数据库连接
    print("\n3. 检查数据库连接:")
    try:
        from modules.database.connection import DatabaseConnection
        db = DatabaseConnection()
        if db.connect():
            print("   ✅ 数据库连接成功")
            
            # 检查表
            try:
                from modules.database.dao import get_data_manager
                data_manager = get_data_manager()
                
                # 获取域名统计
                domain_stats = data_manager.get_domain_stats()
                if domain_stats:
                    print(f"   ✅ 获取域名统计成功")
                    print(f"      总计域名: {domain_stats.get('total_domains', 0)}")
                    print(f"      高风险域名: {domain_stats.get('high_risk_domains', 0)}")
                else:
                    print(f"   ⚠️  域名统计为空")
                    
                # 获取最近域名
                recent_domains = data_manager.get_recent_domains(limit=5)
                print(f"   ✅ 最近域名数量: {len(recent_domains)}")
                for domain in recent_domains[:3]:
                    print(f"      - {domain.get('domain')} ({domain.get('risk_level')})")
                    
            except Exception as e:
                print(f"   ❌ 数据库查询失败: {e}")
        else:
            print(f"   ❌ 数据库连接失败")
    except Exception as e:
        print(f"   ❌ 数据库模块导入失败: {e}")
    
    # 4. 测试Web API
    print("\n4. 测试Web API (本地连接):")
    try:
        import requests
        import json as json_module
        
        base_url = "http://127.0.0.1:5000"
        
        # 测试仪表板统计
        try:
            response = requests.get(f"{base_url}/api/dashboard/stats", timeout=5)
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ 仪表板统计API: 成功")
                stats = data.get('data', {})
                print(f"      总计域名: {stats.get('total_domains', 0)}")
                print(f"      高风险域名: {stats.get('high_risk_domains', 0)}")
            else:
                print(f"   ❌ 仪表板统计API: 状态码 {response.status_code}")
        except Exception as e:
            print(f"   ❌ 仪表板统计API: {e}")
            
        # 测试最近域名API
        try:
            response = requests.get(f"{base_url}/api/dashboard/recent-domains?limit=3", timeout=5)
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ 最近域名API: 成功")
                domains = data.get('data', [])
                print(f"      域名数量: {len(domains)}")
                for domain in domains[:2]:
                    print(f"      - {domain.get('domain')} ({domain.get('risk_level')})")
            else:
                print(f"   ❌ 最近域名API: 状态码 {response.status_code}")
        except Exception as e:
            print(f"   ❌ 最近域名API: {e}")
            
    except Exception as e:
        print(f"   ❌ Web API测试失败: {e}")
    
    # 5. 创建测试数据文件用于Web界面
    print("\n5. 创建测试数据文件:")
    test_domain = "deepseek.com"
    test_dir = variants_dir / test_domain
    
    if test_dir.exists():
        print(f"   ✅ {test_domain}目录已存在")
        
        # 创建简单的测试结果文件
        test_results = []
        try:
            # 读取变体文件
            variants_file = test_dir / "all_variants.txt"
            if variants_file.exists():
                with open(variants_file, 'r', encoding='utf-8') as f:
                    variants = [line.strip() for line in f if line.strip()]
                
                # 创建测试数据
                for i, variant in enumerate(variants[:20]):  # 只取前20个
                    test_results.append({
                        "domain": variant,
                        "original_target": test_domain,
                        "scan_time": "2026-02-09 20:00:00",
                        "risk_level": "high" if i % 5 == 0 else "medium" if i % 3 == 0 else "low",
                        "risk_score": 80 if i % 5 == 0 else 50 if i % 3 == 0 else 20,
                        "variant_count": len(variants)
                    })
                
                # 保存到临时文件供Web界面使用
                temp_file = base_dir / "test_web_data.json"
                with open(temp_file, 'w') as f:
                    json.dump(test_results, f, indent=2)
                
                print(f"   ✅ 创建测试数据文件: {temp_file}")
                print(f"      包含 {len(test_results)} 个测试域名记录")
                
                # 更新Web应用管理器以使用测试数据
                print(f"   ℹ️  测试数据已准备好，刷新Web界面查看效果")
            else:
                print(f"   ⚠️  变体文件不存在")
        except Exception as e:
            print(f"   ❌ 创建测试数据失败: {e}")
    else:
        print(f"   ❌ {test_domain}目录不存在，无法创建测试数据")
    
    print("\n" + "=" * 50)
    print("验证完成")
    
    # 建议
    print("\n建议:")
    print("1. 检查扫描是否完成 (当前HTTP扫描可能还在进行)")
    print("2. 刷新Web界面查看最新数据")
    print("3. 如果数据为空，可以手动添加测试数据")
    print("4. 确保数据库连接正常")

if __name__ == "__main__":
    verify_web_data()