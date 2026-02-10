#!/usr/bin/env python3
"""
测试扫描deepseek.com
"""

import sys
import os
import time
from pathlib import Path

# 添加模块路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_scan_deepseek():
    """测试扫描deepseek.com"""
    
    print("开始测试扫描deepseek.com")
    print("=" * 50)
    
    try:
        # 导入数据管道
        from modules.data_pipeline import DomainMonitoringPipeline
        
        # 创建管道实例
        pipeline = DomainMonitoringPipeline('.')
        
        # 运行完整管道
        print(f"正在扫描域名: deepseek.com")
        start_time = time.time()
        
        success = pipeline.run_full_pipeline("deepseek.com")
        
        elapsed_time = time.time() - start_time
        
        if success:
            print(f"\n✅ 扫描成功完成!")
            print(f"   耗时: {elapsed_time:.2f} 秒")
            
            # 检查生成的目录
            variants_dir = Path("domain_variants") / "deepseek.com"
            if variants_dir.exists():
                print(f"\n生成的目录: {variants_dir}")
                files = list(variants_dir.iterdir())
                print(f"生成的文件:")
                for f in files:
                    print(f"  - {f.name}")
                
                # 检查all_variants.txt
                all_variants = variants_dir / "all_variants.txt"
                if all_variants.exists():
                    with open(all_variants, 'r', encoding='utf-8') as f:
                        count = len(f.readlines())
                    print(f"生成的变体数量: {count}")
                
                # 检查high_risk.txt
                high_risk = variants_dir / "high_risk.txt"
                if high_risk.exists():
                    with open(high_risk, 'r', encoding='utf-8') as f:
                        count = len(f.readlines())
                    print(f"高风险变体数量: {count}")
            else:
                print(f"❌ 未生成目录: {variants_dir}")
                
        else:
            print(f"\n❌ 扫描失败!")
            
    except Exception as e:
        print(f"\n❌ 扫描过程中出错:")
        import traceback
        traceback.print_exc()

def test_scan_from_web():
    """测试从Web界面调用扫描功能"""
    
    print("\n测试Web界面扫描调用")
    print("=" * 50)
    
    try:
        import subprocess
        
        # 构建命令
        cmd = ["python", "modules/data_pipeline.py", "-d", "deepseek.com"]
        print(f"执行命令: {' '.join(cmd)}")
        
        # 执行命令
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        
        print(f"\n返回码: {result.returncode}")
        if result.stdout:
            print(f"标准输出:\n{result.stdout[:2000]}...")
        if result.stderr:
            print(f"错误输出:\n{result.stderr[:1000]}...")
            
    except Exception as e:
        print(f"\n❌ 测试Web界面调用失败:")
        import traceback
        traceback.print_exc()

def check_current_data():
    """检查当前已有数据"""
    
    print("\n检查当前已有数据")
    print("=" * 50)
    
    base_dir = Path('.')
    
    # 检查domain_variants目录
    variants_dir = base_dir / "domain_variants"
    if variants_dir.exists():
        print(f"domain_variants目录: 存在")
        dirs = [d for d in variants_dir.iterdir() if d.is_dir()]
        print(f"已有域名数量: {len(dirs)}")
        for d in dirs:
            print(f"  - {d.name}")
            
            # 检查文件
            files = list(d.iterdir())
            if files:
                for f in files:
                    if f.is_file():
                        print(f"    * {f.name}")
    else:
        print(f"domain_variants目录: 不存在")
    
    # 检查monitoring_results目录
    results_dir = base_dir / "monitoring_results"
    if results_dir.exists():
        print(f"\nmonitoring_results目录: 存在")
        files = list(results_dir.iterdir())
        print(f"结果文件数量: {len(files)}")
        for f in files[:10]:  # 只显示前10个
            print(f"  - {f.name}")

if __name__ == "__main__":
    check_current_data()
    print("\n" + "=" * 50)
    
    # 先测试扫描功能
    test_scan_deepseek()
    print("\n" + "=" * 50)
    
    # 测试Web界面调用
    test_scan_from_web()