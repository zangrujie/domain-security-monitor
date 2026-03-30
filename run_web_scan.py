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
from uuid import uuid4
from dotenv import load_dotenv
load_dotenv()  # 从当前目录的 .env 读取并设置 os.environ
import os
print('VT:', bool(os.getenv('VT_API_KEY')), 'VIRUSTOTAL:', bool(os.getenv('VIRUSTOTAL_API_KEY')))

# 添加项目根目录到路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from modules.domain_input import DomainInputError, normalize_domain_input


def _status_file(scan_id: str) -> Path:
    results_dir = Path(__file__).parent / "monitoring_results"
    results_dir.mkdir(exist_ok=True)
    return results_dir / f"scan_status_{scan_id}.json"


def _write_scan_status(scan_id: str, payload: dict):
    try:
        path = _status_file(scan_id)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def start_scan_from_web(domain: str) -> dict:
    """
    从Web应用启动域名扫描
    
    Args:
        domain: 目标域名
        
    Returns:
        dict: 扫描结果信息
    """
    scan_id = f"scan_{int(datetime.now().timestamp())}_{uuid4().hex[:8]}"
    started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    _write_scan_status(scan_id, {
        "success": True,
        "scan_id": scan_id,
        "domain": domain,
        "status": "running",
        "progress": 10,
        "message": "扫描任务已启动",
        "start_time": started_at,
        "updated_at": datetime.now().isoformat(),
    })

    try:
        print(f"开始扫描域名: {domain}")
        
        try:
            domain = normalize_domain_input(domain)
        except DomainInputError as e:
            result = {
                "success": False,
                "error": f"域名格式不正确: {e}",
                "domain": domain,
                "scan_id": scan_id,
                "status": "failed",
                "progress": 100,
                "start_time": started_at,
            }
            _write_scan_status(scan_id, {**result, "updated_at": datetime.now().isoformat()})
            return result
        
        # 方法1: 直接调用数据管道（推荐）
        try:
            from modules.data_pipeline import DomainMonitoringPipeline
            
            print(f"使用数据管道扫描: {domain}")
            pipeline = DomainMonitoringPipeline()
            
            # 运行完整的扫描管道
            success = pipeline.run_full_pipeline(domain)
            
            if success:
                result = {
                    "success": True,
                    "message": f"域名扫描完成: {domain}",
                    "domain": domain,
                    "scan_id": scan_id,
                    "start_time": started_at,
                    "status": "completed",
                    "progress": 100,
                    "method": "data_pipeline"
                }
                _write_scan_status(scan_id, {**result, "updated_at": datetime.now().isoformat()})
                return result
            else:
                result = {
                    "success": False,
                    "error": "数据管道执行失败",
                    "domain": domain,
                    "scan_id": scan_id,
                    "start_time": started_at,
                    "status": "failed",
                    "progress": 100,
                    "method": "data_pipeline"
                }
                _write_scan_status(scan_id, {**result, "updated_at": datetime.now().isoformat()})
                return result
                
        except ImportError as e:
            print(f"数据管道导入失败: {e}")
            
        # 方法2: 使用命令行调用（备选方案）
        try:
            print(f"尝试命令行调用: {domain}")

            # 构造命令：优先使用项目内的 Python 脚本调用数据管道
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
                output = result.stdout[:1000]
                payload = {
                    "success": True,
                    "message": f"命令行扫描完成: {domain}",
                    "domain": domain,
                    "scan_id": scan_id,
                    "start_time": started_at,
                    "status": "completed",
                    "progress": 100,
                    "method": "command_line",
                    "output": output
                }
                _write_scan_status(scan_id, {**payload, "updated_at": datetime.now().isoformat()})
                return payload
            else:
                error_msg = f"命令执行失败: {result.returncode}"
                if result.stderr:
                    error_msg += f", 错误: {result.stderr[:500]}"
                
                payload = {
                    "success": False,
                    "error": error_msg,
                    "domain": domain,
                    "scan_id": scan_id,
                    "start_time": started_at,
                    "status": "failed",
                    "progress": 100,
                    "method": "command_line"
                }
                _write_scan_status(scan_id, {**payload, "updated_at": datetime.now().isoformat()})
                return payload
                
        except Exception as e:
            print(f"命令行调用失败: {e}")
            
        # 方法3: 仅生成变体（最简方案）
        try:
            print(f"尝试仅生成域名变体: {domain}")
            
            # 使用 Go 程序生成变体 — 尝试查找 main.go 的合理路径
            go_cmd = None
            base_dir = Path(__file__).parent
            candidates = [
                base_dir / "main.go",
                base_dir / "MySecurityProject" / "main.go",
                base_dir.parent / "main.go",
            ]
            for p in candidates:
                if p.exists():
                    go_cmd = ["go", "run", str(p), "-domain", domain]
                    break

            # 如果项目自身是一个 Go module，优先使用 `go run .`
            if go_cmd is None and (base_dir / "go.mod").exists():
                go_cmd = ["go", "run", ".", "-domain", domain]

            # 最后兜底仍尝试原始调用（可能失败但保持兼容）
            if go_cmd is None:
                go_cmd = ["go", "run", "main.go", "-domain", domain]

            result = subprocess.run(
                go_cmd,
                capture_output=True,
                text=True,
                cwd=base_dir,
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
                        
                        payload = {
                            "success": True,
                            "message": f"域名变体生成完成: {count} 个变体",
                            "domain": domain,
                            "scan_id": scan_id,
                            "start_time": started_at,
                            "status": "completed",
                            "progress": 100,
                            "method": "variant_generation",
                            "variant_count": count
                        }
                        _write_scan_status(scan_id, {**payload, "updated_at": datetime.now().isoformat()})
                        return payload
                        
            
            payload = {
                "success": False,
                "error": "无法生成域名变体",
                "domain": domain,
                "scan_id": scan_id,
                "start_time": started_at,
                "status": "failed",
                "progress": 100,
                "method": "variant_generation"
            }
            _write_scan_status(scan_id, {**payload, "updated_at": datetime.now().isoformat()})
            return payload
            
        except Exception as e:
            print(f"变体生成失败: {e}")
        
        # 所有方法都失败
        payload = {
            "success": False,
            "error": "所有扫描方法都失败",
            "domain": domain,
            "scan_id": scan_id,
            "start_time": started_at,
            "status": "failed",
            "progress": 100,
        }
        _write_scan_status(scan_id, {**payload, "updated_at": datetime.now().isoformat()})
        return payload
        
    except Exception as e:
        payload = {
            "success": False,
            "error": f"扫描过程异常: {str(e)}",
            "domain": domain,
            "scan_id": scan_id,
            "start_time": started_at,
            "status": "failed",
            "progress": 100,
        }
        _write_scan_status(scan_id, {**payload, "updated_at": datetime.now().isoformat()})
        return payload

def get_scan_status(scan_id: str) -> dict:
    """
    获取扫描状态
    
    Args:
        scan_id: 扫描ID
        
    Returns:
        dict: 状态信息
    """
    try:
        path = _status_file(scan_id)
        if not path.exists():
            return {
                "success": False,
                "scan_id": scan_id,
                "status": "not_found",
                "error": "未找到对应扫描状态"
            }

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            return {
                "success": False,
                "scan_id": scan_id,
                "status": "invalid",
                "error": "状态文件格式无效"
            }

        data.setdefault("success", True)
        data.setdefault("scan_id", scan_id)
        return data
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

        # 复用完整扫描逻辑，并回传 options 便于前端展示
        result = start_scan_from_web(domain)
        if isinstance(result, dict):
            result["options"] = scan_options
            result.setdefault("mode", "quick")
        return result
        
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
