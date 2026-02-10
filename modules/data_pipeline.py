#!/usr/bin/env python3
"""
数据处理管道 - 协调各模块执行完整的域名监控流程
包含数据库存储功能的第二阶段实现
"""

import json
import time
import logging
import subprocess
import sys
import os
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from pathlib import Path

# 添加模块路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.data_schemas import (
    DomainInfo,
    HTTPResult,
    WhoisResult,
    ThreatIntelligenceResult,
    ComprehensiveRiskScore,
    DomainMonitoringResult,
    create_http_result_from_scanner,
    create_whois_result_from_enhanced,
    create_threat_intel_result_from_scanner,
    create_comprehensive_risk_assessment,
    save_results_to_json
)

# 第二阶段新增：数据库模块
try:
    from modules.database.connection import init_database, DatabaseSession
    from modules.database.dao import get_data_manager, DomainDataManager
    DATABASE_ENABLED = True
except ImportError as e:
    logging.warning(f"数据库模块导入失败: {e}，将仅使用文件存储")
    DATABASE_ENABLED = False

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DomainMonitoringPipeline:
    """
    域名监控数据处理管道
    协调各模块执行：域名变体生成 → DNS探测 → HTTP扫描 → WHOIS查询 → 威胁情报 → 风险评估
    """
    
    def __init__(self, base_dir: str = "."):
        self.base_dir = Path(base_dir)
        self.results_dir = self.base_dir / "monitoring_results"
        self.results_dir.mkdir(exist_ok=True)
        
        # 各模块的输出文件路径
        self.domain_variants_file = self.base_dir / "domain_variants" / "example.com_puny_only.txt"
        self.xdig_results_file = self.base_dir / "active_domains.txt"
        self.http_results_file = self.results_dir / "http_scan_results.json"
        self.whois_results_file = self.results_dir / "whois_results.json"
        self.threat_results_file = self.results_dir / "threat_intel_results.json"
        self.final_results_file = self.results_dir / "comprehensive_results.json"
        
    def step1_generate_domain_variants(self, target_domain: str) -> bool:
        """
        步骤1: 使用main.go生成域名变体
        """
        logger.info(f"步骤1: 生成域名变体 - {target_domain}")
        
        try:
            # 构建命令
            cmd = ["go", "run", "main.go", "-domain", target_domain]
            
            logger.info(f"执行命令: {' '.join(cmd)}")
            
            # 执行命令 - 使用正确的编码处理输出
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                cwd=self.base_dir,
                encoding='utf-8',
                errors='replace'  # 替换无法解码的字符
            )
            
            if result.returncode == 0:
                logger.info("域名变体生成成功")
                
                # 检查生成的punycode文件 - 根据新的目录结构
                domain_output_dir = self.base_dir / "domain_variants" / target_domain.replace('.', '_')
                punycode_file = domain_output_dir / "puny_only.txt"
                
                # 如果上述路径不存在，尝试直接域名作为目录名
                if not punycode_file.exists():
                    domain_output_dir = self.base_dir / "domain_variants" / target_domain
                    punycode_file = domain_output_dir / "puny_only.txt"
                
                if punycode_file.exists():
                    self.domain_variants_file = punycode_file
                    count = len(punycode_file.read_text(encoding='utf-8').strip().splitlines())
                    logger.info(f"生成 {count} 个域名变体")
                    return True
                else:
                    logger.warning(f"未找到punycode文件: {punycode_file}")
                    # 列出目录内容帮助调试
                    try:
                        if domain_output_dir.exists():
                            files = list(domain_output_dir.iterdir())
                            logger.info(f"目录内容: {[f.name for f in files]}")
                    except:
                        pass
                    return False
            else:
                logger.error(f"域名变体生成失败，返回码: {result.returncode}")
                if result.stdout:
                    logger.error(f"标准输出: {result.stdout[:500]}")
                if result.stderr:
                    logger.error(f"错误输出: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"执行域名变体生成时出错: {e}")
            return False
    
    def step2_run_xdig_scan(self, target_domain: str) -> bool:
        """
        步骤2: 使用xdig进行DNS探测
        注意：xdig在dry模式下不会生成实际输出文件，因此我们创建模拟存活域名文件
        """
        logger.info("步骤2: 运行xdig进行DNS探测")
        
        if not self.domain_variants_file.exists():
            logger.error(f"域名变体文件不存在: {self.domain_variants_file}")
            return False
        
        try:
            # 构建xdig命令 - 根据xdig的实际参数调整
            xdig_executable = self.base_dir / "xdig.exe"
            if not xdig_executable.exists():
                xdig_executable = self.base_dir / "xdig"
            
            if not xdig_executable.exists():
                logger.error("xdig可执行文件不存在")
                return False
            
            output_file = self.base_dir / f"active_domains_{target_domain}.txt"
            
            # xdig的实际参数是-domainfile，不是-f
            cmd = [
                str(xdig_executable),
                "-domainfile", str(self.domain_variants_file),
                "-dry"  # 使用dry模式以避免需要网络权限
            ]
            
            logger.info(f"执行命令: {' '.join(cmd)}")
            
            # 执行命令
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.base_dir, encoding='utf-8', errors='replace')
            
            if result.returncode == 0:
                logger.info("xdig扫描成功（dry模式）")
                
                # 从输出中提取域名（dry模式格式: domain,DNS_server）
                active_domains = []
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and ',' in line:
                        domain = line.split(',')[0].strip()
                        if domain and not domain.startswith('#') and ' ' not in domain:
                            active_domains.append(domain)
                
                if not active_domains:
                    # 如果无法从输出中提取，从punycode文件中读取所有域名
                    logger.warning("无法从xdig输出提取域名，从punycode文件读取")
                    with open(self.domain_variants_file, 'r', encoding='utf-8') as f:
                        active_domains = [line.strip() for line in f if line.strip()]
                
                # 创建模拟的存活域名文件（假设所有域名都存活）
                with open(output_file, 'w', encoding='utf-8') as f:
                    for domain in active_domains:
                        f.write(f"{domain},1\n")  # 格式: domain,1 表示存活
                
                self.xdig_results_file = output_file
                logger.info(f"创建模拟存活域名文件: {len(active_domains)} 个域名（所有域名都标记为存活）")
                
                return True
            else:
                logger.error(f"xdig扫描失败，返回码: {result.returncode}")
                if result.stdout:
                    logger.error(f"标准输出: {result.stdout[:500]}")
                if result.stderr:
                    logger.error(f"错误输出: {result.stderr[:500]}")
                return False
                
        except Exception as e:
            logger.error(f"执行xdig扫描时出错: {e}")
            return False
    
    def extract_active_domains_from_xdig(self) -> List[str]:
        """
        从xdig结果中提取存活的域名列表
        """
        active_domains = []
        
        try:
            with open(self.xdig_results_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.endswith(',1'):  # 存活域名
                        domain = line.split(',')[0]
                        active_domains.append(domain)
            
            logger.info(f"从xdig结果中提取了 {len(active_domains)} 个存活域名")
            return active_domains
            
        except Exception as e:
            logger.error(f"提取存活域名时出错: {e}")
            return []
    
    def step3_run_http_scan(self, active_domains: List[str]) -> bool:
        """
        步骤3: 运行HTTP扫描器
        """
        logger.info(f"步骤3: 运行HTTP扫描器 - {len(active_domains)} 个域名")
        
        if not active_domains:
            logger.warning("没有存活的域名需要扫描")
            return False
        
        try:
            # 创建临时域名列表文件
            temp_domains_file = self.results_dir / "active_domains_list.txt"
            with open(temp_domains_file, 'w') as f:
                for domain in active_domains:
                    f.write(f"{domain}\n")
            
            # 导入HTTP扫描器
            from modules.http_scanner.scanner import scan_file
            
            # 运行扫描
            results = scan_file(
                input_file=str(temp_domains_file),
                output_file=str(self.http_results_file),
                concurrency=5,
                timeout=10
            )
            
            logger.info(f"HTTP扫描完成: {len(results)} 个结果")
            
            # 保存结果
            with open(self.http_results_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            return len(results) > 0
            
        except Exception as e:
            logger.error(f"执行HTTP扫描时出错: {e}")
            return False
    
    def step4_run_whois_queries(self, active_domains: List[str]) -> bool:
        """
        步骤4: 运行WHOIS查询
        """
        logger.info(f"步骤4: 运行WHOIS查询 - {len(active_domains)} 个域名")
        
        if not active_domains:
            logger.warning("没有存活的域名需要查询")
            return False
        
        try:
            # 创建临时域名列表文件
            temp_domains_file = self.results_dir / "active_domains_list.txt"
            with open(temp_domains_file, 'w') as f:
                for domain in active_domains:
                    f.write(f"{domain}\n")
            
            # 导入WHOIS增强模块
            from modules.whois_enhanced import query_whois_file
            
            # 运行查询
            results = query_whois_file(
                input_file=str(temp_domains_file),
                output_file=str(self.whois_results_file),
                max_workers=3,
                delay=2.0
            )
            
            logger.info(f"WHOIS查询完成: {len(results)} 个结果")
            
            return len(results) > 0
            
        except Exception as e:
            logger.error(f"执行WHOIS查询时出错: {e}")
            return False
    
    def step5_run_threat_intelligence(self, active_domains: List[str]) -> bool:
        """
        步骤5: 运行威胁情报检查
        """
        logger.info(f"步骤5: 运行威胁情报检查 - {len(active_domains)} 个域名")
        
        if not active_domains:
            logger.warning("没有存活的域名需要检查")
            return False
        
        try:
            # 创建临时域名列表文件
            temp_domains_file = self.results_dir / "active_domains_list.txt"
            with open(temp_domains_file, 'w') as f:
                for domain in active_domains:
                    f.write(f"{domain}\n")
            
            # 导入威胁情报模块
            from modules.threat_intelligence.intel_scanner import scan_file
            
            # 运行检查
            results = scan_file(
                input_file=str(temp_domains_file),
                output_file=str(self.threat_results_file),
                max_workers=3
            )
            
            logger.info(f"威胁情报检查完成: {len(results)} 个结果")
            
            return len(results) > 0
            
        except Exception as e:
            logger.error(f"执行威胁情报检查时出错: {e}")
            return False
    
    def step6_generate_comprehensive_report(self, target_domain: str) -> bool:
        """
        步骤6: 生成综合风险评估报告并保存到数据库
        """
        logger.info("步骤6: 生成综合风险评估报告")
        
        try:
            # 加载各模块的结果
            http_results = []
            whois_results = []
            threat_results = []
            
            if self.http_results_file.exists():
                with open(self.http_results_file, 'r') as f:
                    http_results = json.load(f)
            
            if self.whois_results_file.exists():
                with open(self.whois_results_file, 'r') as f:
                    whois_results = json.load(f)
            
            if self.threat_results_file.exists():
                with open(self.threat_results_file, 'r') as f:
                    threat_results = json.load(f)
            
            # 创建域名到结果的映射
            http_by_domain = {r['domain']: r for r in http_results}
            whois_by_domain = {r['domain']: r for r in whois_results}
            threat_by_domain = {r['domain']: r for r in threat_results}
            
            # 获取所有域名
            all_domains = set(list(http_by_domain.keys()) + 
                             list(whois_by_domain.keys()) + 
                             list(threat_by_domain.keys()))
            
            # 生成综合报告
            monitoring_results = []
            db_stats_summary = {}
            
            for domain in sorted(all_domains):
                # 获取各维度数据
                http_data = http_by_domain.get(domain)
                whois_data = whois_by_domain.get(domain)
                threat_data = threat_by_domain.get(domain)
                
                # 创建域名基础信息
                # 注意：这里需要从main.go的输出获取视觉相似度，暂时使用默认值
                domain_info = DomainInfo(
                    domain=domain,
                    original_target=target_domain,
                    visual_similarity=0.0,  # 需要从main.go解析
                    generation_method="unknown",
                    first_seen=datetime.now().isoformat()
                )
                
                # 创建HTTP结果
                http_result = None
                if http_data:
                    http_result = create_http_result_from_scanner(http_data)
                
                # 创建WHOIS结果
                whois_result = None
                if whois_data:
                    whois_result = create_whois_result_from_enhanced(whois_data)
                
                # 创建威胁情报结果
                threat_result = None
                if threat_data:
                    threat_result = create_threat_intel_result_from_scanner(threat_data)
                
                # 创建综合风险评估
                risk_assessment = None
                if http_result or whois_result or threat_result:
                    # 获取各维度风险评分
                    visual_score = 0.0  # 需要从main.go解析
                    whois_score = whois_result.whois_risk_score if whois_result else 0.0
                    http_score = http_result.http_risk_score if http_result else 0.0
                    threat_score = threat_result.threat_risk_score if threat_result else 0.0
                    
                    risk_assessment = create_comprehensive_risk_assessment(
                        domain=domain,
                        visual_similarity_score=visual_score,
                        whois_risk_score=whois_score,
                        http_risk_score=http_score,
                        threat_risk_score=threat_score
                    )
                
                # 创建完整监控结果
                monitoring_result = DomainMonitoringResult(
                    domain_info=domain_info,
                    http_result=http_result,
                    whois_result=whois_result,
                    threat_intel_result=threat_result,
                    risk_assessment=risk_assessment
                )
                
                monitoring_results.append(monitoring_result)
                
                # 第二阶段新增：保存到数据库
                if DATABASE_ENABLED:
                    try:
                        # 准备监控数据字典
                        monitoring_data = {
                            'visual_similarity': domain_info.visual_similarity,
                            'generation_method': domain_info.generation_method
                        }
                        
                        # 添加DNS结果（如果有）
                        # 注意：DNS结果需要从xdig结果中提取
                        
                        # 添加HTTP结果
                        if http_data:
                            monitoring_data['http_result'] = http_data
                        
                        # 添加WHOIS结果
                        if whois_data:
                            monitoring_data['whois_result'] = whois_data
                        
                        # 添加威胁情报结果
                        if threat_data:
                            monitoring_data['threat_intel_result'] = threat_data
                        
                        # 添加风险评估结果
                        if risk_assessment:
                            monitoring_data['risk_assessment'] = {
                                'visual_similarity_score': risk_assessment.visual_similarity_score,
                                'whois_risk_score': risk_assessment.whois_risk_score,
                                'http_risk_score': risk_assessment.http_risk_score,
                                'threat_risk_score': risk_assessment.threat_risk_score,
                                'weighted_total_score': risk_assessment.weighted_total_score,
                                'risk_level': risk_assessment.risk_level,
                                'risk_factors': risk_assessment.risk_factors,
                                'confidence': risk_assessment.confidence
                            }
                        
                        # 保存到数据库
                        data_manager = get_data_manager()
                        db_stats = data_manager.save_complete_monitoring_result(
                            domain=domain,
                            original_target=target_domain,
                            monitoring_data=monitoring_data
                        )
                        
                        # 收集统计信息
                        for key, value in db_stats.items():
                            if key not in db_stats_summary:
                                db_stats_summary[key] = 0
                            if isinstance(value, bool) and value:
                                db_stats_summary[key] += 1
                            elif isinstance(value, (int, float)):
                                db_stats_summary[key] += value
                        
                    except Exception as db_error:
                        logger.warning(f"保存域名 {domain} 到数据库时出错: {db_error}")
            
            # 保存综合报告到文件
            save_results_to_json(monitoring_results, str(self.final_results_file))
            
            # 生成统计信息
            critical_count = sum(1 for r in monitoring_results 
                               if r.risk_assessment and r.risk_assessment.risk_level == "critical")
            high_count = sum(1 for r in monitoring_results 
                           if r.risk_assessment and r.risk_assessment.risk_level == "high")
            medium_count = sum(1 for r in monitoring_results 
                             if r.risk_assessment and r.risk_assessment.risk_level == "medium")
            
            logger.info(f"综合报告生成完成: {len(monitoring_results)} 个域名")
            logger.info(f"风险统计: 严重 {critical_count}, 高 {high_count}, 中 {medium_count}")
            
            # 第二阶段新增：报告数据库保存统计
            if DATABASE_ENABLED and db_stats_summary:
                logger.info("数据库保存统计:")
                for key, count in db_stats_summary.items():
                    logger.info(f"  - {key}: {count}")
            
            # 打印高风险域名
            high_risk_domains = []
            for result in monitoring_results:
                if result.risk_assessment and result.risk_assessment.risk_level in ["critical", "high"]:
                    high_risk_domains.append((
                        result.domain_info.domain,
                        result.risk_assessment.weighted_total_score,
                        result.risk_assessment.risk_level
                    ))
            
            if high_risk_domains:
                logger.info("高风险域名:")
                for domain, score, level in sorted(high_risk_domains, key=lambda x: x[1], reverse=True)[:10]:
                    logger.info(f"  {domain}: {score} ({level})")
            
            return True
            
        except Exception as e:
            logger.error(f"生成综合报告时出错: {e}")
            return False

    def run_full_pipeline(self, target_domain: str) -> bool:
        """
        运行完整的监控管道
        """
        logger.info(f"开始运行域名监控管道 - 目标域名: {target_domain}")
        logger.info(f"临时权重配置: 视觉相似度25%, WHOIS20%, HTTP35%, 威胁情报20%, DNS0%")
        
        start_time = time.time()
        
        try:
            # 步骤1: 生成域名变体
            if not self.step1_generate_domain_variants(target_domain):
                logger.error("步骤1失败，停止管道执行")
                return False
            
            # 步骤2: DNS探测
            if not self.step2_run_xdig_scan(target_domain):
                logger.error("步骤2失败，停止管道执行")
                return False
            
            # 提取存活域名
            active_domains = self.extract_active_domains_from_xdig()
            if not active_domains:
                logger.warning("未发现存活域名，停止后续步骤")
                return True  # 不算失败，只是没有存活域名
            
            logger.info(f"发现 {len(active_domains)} 个存活域名，继续后续步骤")
            
            # 步骤3-5: 并行执行HTTP扫描、WHOIS查询、威胁情报检查
            steps_success = []
            
            # 由于可能独立运行，我们按顺序执行
            steps_success.append(self.step3_run_http_scan(active_domains))
            steps_success.append(self.step4_run_whois_queries(active_domains))
            steps_success.append(self.step5_run_threat_intelligence(active_domains))
            
            if not any(steps_success):
                logger.error("步骤3-5全部失败，停止管道执行")
                return False
            
            # 步骤6: 生成综合报告
            if not self.step6_generate_comprehensive_report(target_domain):
                logger.error("步骤6失败")
                return False
            
            elapsed_time = time.time() - start_time
            logger.info(f"管道执行完成，总耗时: {elapsed_time:.2f} 秒")
            
            # 输出结果文件路径
            logger.info(f"结果文件:")
            logger.info(f"  - HTTP扫描结果: {self.http_results_file}")
            logger.info(f"  - WHOIS查询结果: {self.whois_results_file}")
            logger.info(f"  - 威胁情报结果: {self.threat_results_file}")
            logger.info(f"  - 综合评估报告: {self.final_results_file}")
            
            return True
            
        except Exception as e:
            logger.error(f"管道执行过程中出错: {e}")
            return False

def main():
    """
    命令行入口点
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='域名监控数据处理管道')
    parser.add_argument('-d', '--domain', required=True, help='目标域名（例如: example.com）')
    parser.add_argument('-b', '--base-dir', default='.', help='项目基础目录（默认当前目录）')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 创建并运行管道
    pipeline = DomainMonitoringPipeline(args.base_dir)
    success = pipeline.run_full_pipeline(args.domain)
    
    if success:
        print(f"\n✅ 监控管道执行成功!")
        print(f"   结果文件保存在: {pipeline.results_dir}")
        
        # 检查综合报告文件
        if pipeline.final_results_file.exists():
            try:
                with open(pipeline.final_results_file, 'r') as f:
                    data = json.load(f)
                
                high_risk_count = sum(1 for item in data 
                                    if item.get('risk_assessment', {}).get('risk_level') in ['critical', 'high'])
                
                print(f"   总计域名: {len(data)}")
                print(f"   高风险域名: {high_risk_count}")
                
            except:
                pass
    else:
        print(f"\n❌ 监控管道执行失败!")
        sys.exit(1)

if __name__ == "__main__":
    main()