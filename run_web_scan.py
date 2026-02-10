#!/usr/bin/env python3
"""
Web应用扫描启动脚本
用于从Web界面调用扫描流程
"""

import sys
import os
import json
import subprocess
from datetime import datetime
from pathlib import Path

# 添加项目根目录到路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def start_scan_from_web(domain: str) -> dict:
    """
    从Web应用启动域名扫描
    
    Args:
        domain: 目标域名
        
    Returns:
        dict: 扫描结果信息
    """
    try:
        print(f"开始扫描域名: {domain}")
        
        # 验证域名格式
        if '.' not in domain:
            return {
                "success": False,
                "error": "域名格式不正确",
                "domain": domain
            }
        
        # 清理域名
        domain = domain.strip().lower()
        
        # 方法1: 直接调用数据管道（推荐）
        try:
            from modules.data_pipeline import DomainMonitoringPipeline
            
            print(f"使用数据管道扫描: {domain}")
            pipeline = DomainMonitoringPipeline()
            
            # 运行完整的扫描管道
            success = pipeline.run_full_pipeline(domain)
            
            if success:
                return {
                    "success": True,
                    "message": f"域名扫描完成: {domain}",
                    "domain": domain,
                    "scan_id": f"scan_{int(datetime.now().timestamp())}",
                    "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "completed",
                    "method": "data_pipeline"
                }
            else:
                return {
                    "success": False,
                    "error": "数据管道执行失败",
                    "domain": domain,
                    "method": "data_pipeline"
                }
                
        except ImportError as e:
            print(f"数据管道导入失败: {e}")
            
        # 方法2: 使用命令行调用（备选方案）
        try:
            print(f"尝试命令行调用: {domain}")
            
            # 构造命令
            cmd = [sys.executable, "modules/data_pipeline.py", "--domain", domain]
            
            # 执行命令
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent,
                encoding='utf-8',
                errors='replace'
            )
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "message": f"命令行扫描完成: {domain}",
                    "domain": domain,
                    "scan_id": f"cmd_scan_{int(datetime.now().timestamp())}",
                    "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "completed",
                    "method": "command_line",
                    "output": result.stdout[:1000]  # 截取部分输出
                }
            else:
                error_msg = f"命令执行失败: {result.returncode}"
                if result.stderr:
                    error_msg += f", 错误: {result.stderr[:500]}"
                
                return {
                    "success": False,
                    "error": error_msg,
                    "domain": domain,
                    "method": "command_line"
                }
                
        except Exception as e:
            print(f"命令行调用失败: {e}")
            
        # 方法3: 仅生成变体（最简方案）
        try:
            print(f"尝试仅生成域名变体: {domain}")
            
            # 使用Go程序生成变体
            go_cmd = ["go", "run", "main.go", "-domain", domain]
            
            result = subprocess.run(
                go_cmd,
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent,
                encoding='utf-8',
                errors='replace'
            )
            
            if result.returncode == 0:
                # 检查生成的变体文件
                variants_dir = Path(__file__).parent / "domain_variants"
                domain_dir = variants_dir / domain.replace('.', '_')
                
                if not domain_dir.exists():
                    domain_dir = variants_dir / domain
                
                if domain_dir.exists():
                    punycode_file = domain_dir / "puny_only.txt"
                    if punycode_file.exists():
                        count = len(punycode_file.read_text(encoding='utf-8').strip().splitlines())
                        
                        return {
                            "success": True,
                            "message": f"域名变体生成完成: {count} 个变体",
                            "domain": domain,
                            "scan_id": f"variant_gen_{int(datetime.now().timestamp())}",
                            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "status": "completed",
                            "method": "variant_generation",
                            "variant_count": count
                        }
            
            return {
                "success": False,
                "error": "无法生成域名变体",
                "domain": domain,
                "method": "variant_generation"
            }
            
        except Exception as e:
            print(f"变体生成失败: {e}")
        
        # 所有方法都失败
        return {
            "success": False,
            "error": "所有扫描方法都失败",
            "domain": domain
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"扫描过程异常: {str(e)}",
            "domain": domain
        }

def get_scan_status(scan_id: str) -> dict:
    """
    获取扫描状态
    
    Args:
        scan_id: 扫描ID
        
    Returns:
        dict: 状态信息
    """
    try:
        # 这里应该根据scan_id查询实际状态
        # 暂时返回模拟状态
        return {
            "success": True,
            "scan_id": scan_id,
            "status": "completed",
            "progress": 100,
            "message": "扫描已完成"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "scan_id": scan_id
        }

def quick_scan_domain(domain: str, options: dict = None) -> dict:
    """
    快速扫描域名（简化版，适合Web界面）
    
    Args:
        domain: 目标域名
        options: 扫描选项
        
    Returns:
        dict: 扫描结果
    """
    if options is None:
        options = {}
    
    # 默认选项
    scan_options = {
        "dns": options.get("dns", True),
        "http": options.get("http", True),
        "whois": options.get("whois", True),
        "threat": options.get("threat", True),
        "generate_variants": options.get("generate_variants", True)
    }
    
    try:
        print(f"快速扫描: {domain}, 选项: {scan_options}")
        
        # 创建结果目录
        results_dir = Path(__file__).parent / "monitoring_results"
        results_dir.mkdir(exist_ok=True)
        
        # 保存扫描配置
        config_file = results_dir / f"scan_config_{domain}.json"
        with open(config_file, 'w') as f:
            json.dump({
                "domain": domain,
                "options": scan_options,
                "start_time": datetime.now().isoformat()
            }, f, indent=2)
        
        # 这里应该调用实际的扫描逻辑
        # 暂时返回成功消息
        return {
            "success": True,
            "message": f"快速扫描已启动: {domain}",
            "domain": domain,
            "scan_id": f"quick_{int(datetime.now().timestamp())}",
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "processing",
            "options": scan_options
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "domain": domain
        }

if __name__ == "__main__":
    # 命令行测试
    import argparse
    
    parser = argparse.ArgumentParser(description='Web扫描脚本')
    parser.add_argument('-d', '--domain', required=True, help='目标域名')
    parser.add_argument('-q', '--quick', action='store_true', help='快速扫描模式')
    parser.add_argument('-s', '--status', help='查询扫描状态')
    
    args = parser.parse_args()
    
    if args.status:
        result = get_scan_status(args.status)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.quick:
        result = quick_scan_domain(args.domain)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        result = start_scan_from_web(args.domain)
        print(json.dumps(result, indent=2, ensure_ascii=False))