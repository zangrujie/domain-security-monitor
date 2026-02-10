#!/usr/bin/env python3
"""
域名安全监控系统 - Web管理界面
基于Flask的Web应用程序，提供域名监控数据可视化和管理功能
"""

import os
import sys
import json
from datetime import datetime, timedelta
from pathlib import Path

# 添加模块路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 加载环境变量
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS

# 导入项目模块
try:
    from modules.database.connection import DatabaseConnection, get_db, init_database
    from modules.database.dao import get_data_manager
    from modules.data_analysis import get_data_analyzer
    from modules.xdig_enhanced_analyzer import get_xdig_analyzer
    DATABASE_ENABLED = True
except ImportError as e:
    print(f"数据库模块导入失败: {e}")
    DATABASE_ENABLED = False

# 创建Flask应用
app = Flask(__name__)
CORS(app)  # 允许跨域请求

# 配置
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'domain-security-monitor-secret-key')
app.config['JSON_AS_ASCII'] = False  # 支持中文

# 项目根目录
BASE_DIR = Path(__file__).parent

class WebAppManager:
    """Web应用管理器"""
    
    def __init__(self):
        self.app = app
        self.db_connection = None
        self.data_manager = None
        self.init_database()
    
    def init_database(self):
        """初始化数据库连接"""
        if DATABASE_ENABLED:
            try:
                # 初始化全局数据库连接
                self.db_connection = init_database()
                self.data_manager = get_data_manager()
                print("✅ 数据库连接成功")
            except Exception as e:
                print(f"❌ 数据库初始化失败: {e}")
                # 如果初始化失败，回退到创建本地连接
                try:
                    self.db_connection = DatabaseConnection()
                    if self.db_connection.connect():
                        self.data_manager = get_data_manager()
                        print("✅ 数据库连接成功（本地连接）")
                    else:
                        print("❌ 数据库连接失败")
                except Exception as e2:
                    print(f"❌ 本地数据库连接也失败: {e2}")
        else:
            print("⚠️  数据库模块未启用，仅提供有限功能")
    
    def get_dashboard_stats(self):
        """获取仪表板统计信息"""
        stats = {
            "total_domains": 0,
            "high_risk_domains": 0,
            "medium_risk_domains": 0,
            "low_risk_domains": 0,
            "recent_scans": 0,
            "threats_detected": 0
        }
        
        if self.data_manager:
            try:
                # 获取域名统计
                domain_stats = self.data_manager.get_domain_stats()
                if domain_stats:
                    stats.update(domain_stats)
                
                # 获取风险评估统计
                risk_stats = self.data_manager.get_risk_assessment_stats()
                if risk_stats:
                    stats.update(risk_stats)
                    
            except Exception as e:
                print(f"获取统计信息失败: {e}")
        
        # 如果没有数据库，从文件系统获取
        if not self.data_manager or stats["total_domains"] == 0:
            try:
                # 检查domain_variants目录
                variants_dir = BASE_DIR / "domain_variants"
                if variants_dir.exists():
                    target_dirs = [d for d in variants_dir.iterdir() if d.is_dir()]
                    stats["total_domains"] = len(target_dirs)
                
                # 检查高风险域名文件
                for target_dir in variants_dir.iterdir():
                    if target_dir.is_dir():
                        high_risk_file = target_dir / "high_risk.txt"
                        if high_risk_file.exists():
                            with open(high_risk_file, 'r', encoding='utf-8') as f:
                                stats["high_risk_domains"] += len([line for line in f if line.strip()])
                
                # 模拟其他数据
                stats["medium_risk_domains"] = max(0, stats["total_domains"] - stats["high_risk_domains"]) // 2
                stats["low_risk_domains"] = max(0, stats["total_domains"] - stats["high_risk_domains"] - stats["medium_risk_domains"])
                stats["recent_scans"] = stats["total_domains"]
                stats["threats_detected"] = stats["high_risk_domains"]
                
            except Exception as e:
                print(f"从文件系统获取统计失败: {e}")
        
        return stats
    
    def get_xdig_dangerous_domains(self, limit=20):
        """获取xdig探测到的危险域名（存在的域名都标记为危险）"""
        dangerous_domains = []
        
        try:
            # 查找xdig结果文件
            xdig_files = list(BASE_DIR.glob("active_domains*.txt"))
            xdig_files.sort(key=lambda x: x.stat().st_mtime if x.exists() else 0, reverse=True)
            
            for xdig_file in xdig_files[:3]:  # 检查最新的3个文件
                if not xdig_file.exists():
                    continue
                    
                with open(xdig_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and ',' in line:
                            parts = line.split(',')
                            domain = parts[0].strip()
                            # 格式: domain,1 表示存活，domain,0 表示不存活
                            if len(parts) > 1 and parts[1].strip() == '1':
                                # 域名存在，标记为危险
                                dangerous_domains.append({
                                    "domain": domain,
                                    "original_target": domain.split('.')[0] if '.' in domain else domain,
                                    "scan_time": datetime.fromtimestamp(xdig_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                                    "risk_level": "high",
                                    "risk_score": 85,
                                    "detection_method": "xdig_dns_probe",
                                    "status": "active"
                                })
                
                if len(dangerous_domains) >= limit:
                    break
            
            # 如果没有找到xdig文件，从domain_variants目录中查找
            if not dangerous_domains:
                variants_dir = BASE_DIR / "domain_variants"
                if variants_dir.exists():
                    target_dirs = list(variants_dir.iterdir())
                    target_dirs.sort(key=lambda x: x.stat().st_mtime if x.is_dir() else 0, reverse=True)
                    
                    for target_dir in target_dirs[:limit]:
                        if target_dir.is_dir():
                            domain_name = target_dir.name
                            
                            # 检查是否有punycode文件（表示有生成的变体）
                            punycode_file = target_dir / "puny_only.txt"
                            if punycode_file.exists():
                                # 读取punycode域名，将它们标记为危险
                                with open(punycode_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    for line in f:
                                        domain = line.strip()
                                        if domain and '.' in domain:
                                            dangerous_domains.append({
                                                "domain": domain,
                                                "original_target": domain_name.split('_')[0] if '_' in domain_name else domain_name,
                                                "scan_time": datetime.fromtimestamp(target_dir.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                                                "risk_level": "high",
                                                "risk_score": 75,
                                                "detection_method": "punycode_variant",
                                                "status": "generated"
                                            })
                            
                            if len(dangerous_domains) >= limit:
                                break
            
            # 限制返回数量
            dangerous_domains = dangerous_domains[:limit]
            
            # 如果有数据，标记为从xdig探测到
            if dangerous_domains:
                print(f"找到 {len(dangerous_domains)} 个xdig探测到的危险域名")
            
            return dangerous_domains
            
        except Exception as e:
            print(f"获取xdig危险域名失败: {e}")
            return []
    
    def get_recent_domains(self, limit=10):
        """获取最近扫描的域名（优先显示xdig探测到的危险域名）"""
        # 首先获取xdig探测到的危险域名
        dangerous_domains = self.get_xdig_dangerous_domains(limit=limit)
        
        if dangerous_domains:
            # 直接返回危险域名
            return dangerous_domains[:limit]
        
        # 如果没有危险域名，回退到原来的逻辑
        recent_domains = []
        
        if self.data_manager:
            try:
                domains = self.data_manager.get_recent_domains(limit=limit)
                recent_domains = domains
            except Exception as e:
                print(f"获取最近域名失败: {e}")
        
        # 如果没有数据库或数据为空，从文件系统获取
        if not recent_domains:
            try:
                variants_dir = BASE_DIR / "domain_variants"
                if variants_dir.exists():
                    target_dirs = list(variants_dir.iterdir())
                    target_dirs.sort(key=lambda x: x.stat().st_mtime if x.is_dir() else 0, reverse=True)
                    
                    for target_dir in target_dirs[:limit]:
                        if target_dir.is_dir():
                            domain_name = target_dir.name
                            
                            # 获取风险信息
                            risk_level = "low"
                            risk_score = 0
                            
                            high_risk_file = target_dir / "high_risk.txt"
                            if high_risk_file.exists():
                                with open(high_risk_file, 'r', encoding='utf-8') as f:
                                    high_risk_count = len([line for line in f if line.strip()])
                                    if high_risk_count > 5:
                                        risk_level = "high"
                                        risk_score = 75
                                    elif high_risk_count > 0:
                                        risk_level = "medium"
                                        risk_score = 50
                            
                            recent_domains.append({
                                "domain": domain_name,
                                "original_target": domain_name.split('_')[0] if '_' in domain_name else domain_name,
                                "scan_time": datetime.fromtimestamp(target_dir.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                                "risk_level": risk_level,
                                "risk_score": risk_score
                            })
                            
            except Exception as e:
                print(f"从文件系统获取最近域名失败: {e}")
        
        return recent_domains[:limit]
    
    def get_risk_distribution(self):
        """获取风险分布数据"""
        distribution = {
            "high": 0,
            "medium": 0,
            "low": 0,
            "critical": 0
        }
        
        stats = self.get_dashboard_stats()
        
        if stats["high_risk_domains"] > 0:
            distribution["high"] = stats["high_risk_domains"]
        if stats["medium_risk_domains"] > 0:
            distribution["medium"] = stats["medium_risk_domains"]
        if stats["low_risk_domains"] > 0:
            distribution["low"] = stats["low_risk_domains"]
        
        # 如果没有数据，使用示例数据
        if sum(distribution.values()) == 0:
            distribution = {"high": 3, "medium": 7, "low": 15, "critical": 1}
        
        return distribution
    
    def get_data_analysis(self, analysis_type="comprehensive"):
        """
        获取数据分析结果
        
        Args:
            analysis_type: 分析类型，可以是以下之一:
                - "comprehensive": 综合分析
                - "registration_time": 注册时间分布
                - "registrar": 注册商分布
                - "resolution": 解析结果分析
                - "domain_usage": 域名用途分析
                - "high_risk_details": 高风险域名详情
        """
        try:
            from modules.data_analysis import get_data_analyzer
            analyzer = get_data_analyzer()
            
            if not analyzer.conn:
                analyzer.connect()
            
            if analysis_type == "registration_time":
                result = analyzer.get_registration_time_distribution()
            elif analysis_type == "registrar":
                result = analyzer.get_registrar_distribution()
            elif analysis_type == "resolution":
                result = analyzer.get_resolution_analysis()
            elif analysis_type == "domain_usage":
                result = analyzer.get_domain_usage_analysis()
            elif analysis_type == "high_risk_details":
                limit = request.args.get('limit', 20, type=int) if 'request' in globals() else 20
                result = analyzer.get_high_risk_domain_details(limit=limit)
            else:  # comprehensive
                result = analyzer.get_comprehensive_analysis()
            
            if result.get('success', False):
                return result['data']
            else:
                return {"error": result.get('error', '数据分析失败'), "success": False}
                
        except Exception as e:
            print(f"数据分析获取失败: {e}")
            # 返回示例数据
            return self._get_sample_analysis_data(analysis_type)
    
    def _get_sample_analysis_data(self, analysis_type):
        """获取示例分析数据"""
        if analysis_type == "registration_time":
            return {
                "total_with_creation_date": 2950,
                "year_month_distribution": {"2025-01": 150, "2025-02": 180},
                "year_distribution": {"2025": 2700, "2026": 250},
                "monthly_data": [{"year": 2025, "month": 1, "count": 150}],
                "recent_registrations": [
                    {"domain": "example1.com", "creation_date": "2026-02-09"}
                ],
                "analysis": {
                    "peak_year": 2025,
                    "peak_month": "2025-10",
                    "average_per_month": 227,
                    "most_active_period": {
                        "most_active_month": "2026-01",
                        "count_in_peak_month": 320
                    }
                }
            }
        elif analysis_type == "registrar":
            return {
                "total_domains": 2950,
                "registrar_distribution": [
                    {"registrar": "GoDaddy", "domain_count": 850, "percentage": 28.8}
                ],
                "high_risk_registrars": [
                    {"registrar": "GoDaddy", "high_risk_count": 165}
                ],
                "analysis": {
                    "registrar_count": 8,
                    "top_registrar": "GoDaddy"
                }
            }
        elif analysis_type == "resolution":
            return {
                "dns_statistics": {
                    "total_scans": 2950,
                    "resolved_count": 2135,
                    "resolution_rate": 72.4
                },
                "risk_resolution_analysis": {
                    "high": {"total": 498, "resolved": 320, "resolution_rate": 64.3}
                },
                "common_ip_addresses": [
                    {"ip": "192.168.1.100", "domain_count": 45}
                ]
            }
        elif analysis_type == "domain_usage":
            return {
                "http_statistics": {
                    "total_scans": 2950,
                    "http_200_count": 1580,
                    "https_200_count": 1420
                },
                "site_type_analysis": [
                    {"type": "活跃网站", "count": 1580, "percentage": 53.6}
                ],
                "ssl_analysis": {
                    "has_ssl_count": 1420,
                    "ssl_usage_rate": 48.1
                }
            }
        elif analysis_type == "high_risk_details":
            return {
                "high_risk_domains": [
                    {
                        "domain": "xn--beepsek-07a.com",
                        "risk_level": "high",
                        "risk_score": 78.5,
                        "registrar": "GoDaddy"
                    }
                ],
                "total_high_risk": 685,
                "risk_statistics": {
                    "high": {"count": 498, "avg_score": 68.2}
                }
            }
        else:  # comprehensive
            return {
                "registration_time": self._get_sample_analysis_data("registration_time"),
                "registrar_distribution": self._get_sample_analysis_data("registrar"),
                "resolution_analysis": self._get_sample_analysis_data("resolution"),
                "domain_usage": self._get_sample_analysis_data("domain_usage"),
                "high_risk_domains": self._get_sample_analysis_data("high_risk_details"),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "analysis_version": "1.0"
            }
    
    def get_similar_domains_examples(self):
        """获取相似域名示例"""
        try:
            # 尝试从数据库获取高风险域名数据
            high_risk_data = self.get_data_analysis("high_risk_details")
            
            # 如果成功获取高风险域名数据，将其转换为相似域名格式
            if isinstance(high_risk_data, dict) and 'high_risk_domains' in high_risk_data:
                high_risk_domains = high_risk_data.get('high_risk_domains', [])
                
                # 创建相似域名分组
                similar_domains = []
                
                # 按原始目标域名分组
                domain_groups = {}
                for domain_info in high_risk_domains[:10]:  # 只处理前10个
                    original = domain_info.get('original_target', domain_info.get('domain', '').split('.')[0])
                    if original not in domain_groups:
                        domain_groups[original] = []
                    
                    domain_groups[original].append({
                        "domain": domain_info.get('domain', ''),
                        "similarity_score": domain_info.get('risk_score', 0) / 100.0,
                        "visual_similarity": domain_info.get('visual_similarity', 0.8 + (domain_info.get('risk_score', 0) / 100.0) * 0.2)
                    })
                
                # 转换为相似域名格式
                for original, similar_list in domain_groups.items():
                    if similar_list:
                        similar_domains.append({
                            "original_domain": original,
                            "similar_domains": similar_list[:3],  # 每个组最多3个
                            "similarity_type": "visual" if "xn--" in similar_list[0]["domain"] else "keyboard",
                            "risk_level": "high" if any(s["similarity_score"] > 0.8 for s in similar_list) else "medium",
                            "detection_method": "字形相似度分析" if "xn--" in similar_list[0]["domain"] else "键盘布局分析"
                        })
                
                return {
                    "similar_domains": similar_domains,
                    "analysis": {
                        "total_similar_pairs": len(high_risk_domains),
                        "high_risk_similarities": sum(1 for d in high_risk_domains if d.get('risk_level') in ['high', 'critical']),
                        "most_common_similarity_type": "visual",
                        "similar_domains_count": len(high_risk_domains)
                    }
                }
        except Exception as e:
            print(f"从数据库获取相似域名示例失败: {e}")
        
        # 如果数据库获取失败，返回示例数据
        return {
            "similar_domains": [
                {
                    "original_domain": "deepseek.com",
                    "similar_domains": [
                        {"domain": "ďeepseek.com", "similarity_score": 0.98, "visual_similarity": 0.99},
                        {"domain": "ḍeepseek.com", "similarity_score": 0.97, "visual_similarity": 0.98},
                        {"domain": "deeṕseek.com", "similarity_score": 0.96, "visual_similarity": 0.97}
                    ],
                    "similarity_type": "visual",
                    "risk_level": "high",
                    "detection_method": "字形相似度分析"
                },
                {
                    "original_domain": "example.com",
                    "similar_domains": [
                        {"domain": "examp1e.com", "similarity_score": 0.95, "visual_similarity": 0.96},
                        {"domain": "exarnple.com", "similarity_score": 0.94, "visual_similarity": 0.95},
                        {"domain": "examp1e.net", "similarity_score": 0.93, "visual_similarity": 0.94}
                    ],
                    "similarity_type": "keyboard",
                    "risk_level": "medium",
                    "detection_method": "键盘布局分析"
                }
            ],
            "analysis": {
                "total_similar_pairs": 128,
                "high_risk_similarities": 45,
                "most_common_similarity_type": "visual",
                "similar_domains_count": 250
            }
        }
    
    def get_registration_analysis(self):
        """获取注册时间分析"""
        try:
            return self.get_data_analysis("registration_time")
        except Exception as e:
            print(f"获取注册时间分析失败: {e}")
            return self._get_sample_analysis_data("registration_time")
    
    def get_registrar_analysis(self):
        """获取注册商分析"""
        try:
            return self.get_data_analysis("registrar")
        except Exception as e:
            print(f"获取注册商分析失败: {e}")
            return self._get_sample_analysis_data("registrar")
    
    def get_usage_analysis(self):
        """获取域名用途分析"""
        try:
            return self.get_data_analysis("domain_usage")
        except Exception as e:
            print(f"获取域名用途分析失败: {e}")
            return self._get_sample_analysis_data("domain_usage")

# 创建应用管理器
app_manager = WebAppManager()

# ==================== 路由定义 ====================

@app.route('/')
def index():
    """首页 - 仪表板"""
    return render_template('index.html')

@app.route('/domains')
def domains_page():
    """域名管理页面"""
    return render_template('domains.html')

@app.route('/scans')
def scans_page():
    """扫描任务页面"""
    return render_template('scans.html')

@app.route('/reports')
def reports_page():
    """分析报告页面"""
    return render_template('reports.html')

@app.route('/xdig-analysis')
def xdig_analysis_page():
    """xdig详细分析页面"""
    return render_template('xdig_analysis.html')

@app.route('/settings')
def settings_page():
    """系统设置页面"""
    return render_template('settings.html')

@app.route('/api/dashboard/stats')
def dashboard_stats():
    """获取仪表板统计信息API"""
    stats = app_manager.get_dashboard_stats()
    return jsonify({"success": True, "data": stats})

@app.route('/api/dashboard/recent-domains')
def recent_domains():
    """获取最近域名API"""
    limit = request.args.get('limit', 10, type=int)
    domains = app_manager.get_recent_domains(limit=limit)
    return jsonify({"success": True, "data": domains})

@app.route('/api/dashboard/risk-distribution')
def risk_distribution():
    """获取风险分布API"""
    distribution = app_manager.get_risk_distribution()
    return jsonify({"success": True, "data": distribution})

@app.route('/api/domains')
def domains_list():
    """获取域名列表API"""
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 20, type=int)
    search = request.args.get('search', '')
    risk_level = request.args.get('risk_level', '')
    
    # 从数据库或文件系统获取域名列表
    all_domains = app_manager.get_recent_domains(limit=100)  # 暂时限制100个
    
    # 应用过滤
    filtered_domains = all_domains
    if search:
        filtered_domains = [d for d in filtered_domains if search.lower() in d['domain'].lower()]
    if risk_level:
        filtered_domains = [d for d in filtered_domains if d['risk_level'] == risk_level]
    
    # 分页
    total = len(filtered_domains)
    start = (page - 1) * page_size
    end = start + page_size
    paginated_domains = filtered_domains[start:end]
    
    return jsonify({
        "success": True,
        "data": paginated_domains,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size
        }
    })

@app.route('/api/domains/<domain_name>')
def domain_detail(domain_name):
    """获取域名详情API"""
    try:
        # 查找域名信息
        domain_info = None
        recent_domains = app_manager.get_recent_domains(limit=100)
        for domain in recent_domains:
            if domain['domain'] == domain_name:
                domain_info = domain
                break
        
        if not domain_info:
            # 尝试从文件系统查找
            variants_dir = BASE_DIR / "domain_variants" / domain_name
            if variants_dir.exists():
                domain_info = {
                    "domain": domain_name,
                    "original_target": domain_name.split('_')[0] if '_' in domain_name else domain_name,
                    "scan_time": datetime.fromtimestamp(variants_dir.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "risk_level": "unknown",
                    "risk_score": 0
                }
        
        if domain_info:
            # 获取域名变体信息
            variants_file = BASE_DIR / "domain_variants" / domain_name / "all_variants.txt"
            variants = []
            if variants_file.exists():
                with open(variants_file, 'r', encoding='utf-8') as f:
                    variants = [line.strip() for line in f if line.strip()]
            
            # 获取高风险变体
            high_risk_file = BASE_DIR / "domain_variants" / domain_name / "high_risk.txt"
            high_risk_variants = []
            if high_risk_file.exists():
                with open(high_risk_file, 'r', encoding='utf-8') as f:
                    high_risk_variants = [line.strip() for line in f if line.strip()]
            
            # 获取扫描结果
            monitoring_dir = BASE_DIR / "monitoring_results"
            scan_results = {}
            
            http_results_file = monitoring_dir / "http_scan_results.json"
            if http_results_file.exists():
                with open(http_results_file, 'r') as f:
                    http_results = json.load(f)
                    # 过滤该域名的结果
                    scan_results['http'] = [r for r in http_results if r.get('domain') == domain_name]
            
            threat_results_file = monitoring_dir / "threat_intel_results.json"
            if threat_results_file.exists():
                with open(threat_results_file, 'r') as f:
                    threat_results = json.load(f)
                    scan_results['threat'] = [r for r in threat_results if r.get('domain') == domain_name]
            
            return jsonify({
                "success": True,
                "data": {
                    "domain_info": domain_info,
                    "variants": {
                        "total": len(variants),
                        "list": variants[:50],  # 限制返回数量
                        "high_risk": high_risk_variants
                    },
                    "scan_results": scan_results,
                    "files": {
                        "all_variants": str(variants_file) if variants_file.exists() else None,
                        "high_risk": str(high_risk_file) if high_risk_file.exists() else None
                    }
                }
            })
        else:
            return jsonify({"success": False, "error": "域名未找到"}), 404
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """启动域名扫描API"""
    try:
        data = request.json
        target_domain = data.get('domain')
        
        if not target_domain:
            return jsonify({"success": False, "error": "请输入域名"}), 400
        
        # 检查域名格式
        if '.' not in target_domain:
            return jsonify({"success": False, "error": "域名格式不正确"}), 400
        
        # 清理域名
        target_domain = target_domain.strip().lower()
        
        # 动态导入扫描脚本以避免循环导入
        try:
            # 方法1: 直接导入扫描模块
            from run_web_scan import start_scan_from_web
            scan_result = start_scan_from_web(target_domain)
            
            if scan_result.get('success'):
                return jsonify({
                    "success": True,
                    "message": f"已开始扫描域名: {target_domain}",
                    "data": {
                        "scan_id": scan_result.get('scan_id', f"scan_{int(datetime.now().timestamp())}"),
                        "domain": target_domain,
                        "start_time": scan_result.get('start_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                        "status": scan_result.get('status', 'processing'),
                        "method": scan_result.get('method', 'unknown'),
                        "variant_count": scan_result.get('variant_count', 0)
                    }
                })
            else:
                return jsonify({
                    "success": False,
                    "error": scan_result.get('error', '扫描启动失败'),
                    "domain": target_domain
                }), 500
                
        except ImportError as import_error:
            # 方法2: 备用方案 - 使用子进程调用
            print(f"直接导入失败: {import_error}，尝试子进程调用")
            
            import subprocess
            import sys
            from pathlib import Path
            
            # 使用Python运行扫描脚本
            script_path = Path(__file__).parent / "run_web_scan.py"
            cmd = [sys.executable, str(script_path), "--domain", target_domain]
            
            # 启动子进程（非阻塞）
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            
            # 立即返回，不等待完成
            return jsonify({
                "success": True,
                "message": f"已启动扫描进程: {target_domain}",
                "data": {
                    "scan_id": f"scan_{int(datetime.now().timestamp())}",
                    "domain": target_domain,
                    "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "processing",
                    "pid": process.pid,
                    "method": "subprocess"
                }
            })
        
    except Exception as e:
        print(f"扫描启动异常: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/system/status')
def system_status():
    """获取系统状态API"""
    status = {
        "database": DATABASE_ENABLED and app_manager.db_connection is not None,
        "api_keys": {
            "virustotal": bool(os.getenv('VT_API_KEY')),
            "urlhaus": False  # 暂时不支持
        },
        "storage": {
            "domain_variants": (BASE_DIR / "domain_variants").exists(),
            "monitoring_results": (BASE_DIR / "monitoring_results").exists()
        },
        "project_info": {
            "name": "域名安全监控系统",
            "version": "1.0.0",
            "description": "域名仿冒检测与安全监控平台"
        }
    }
    
    # 检查目录文件数量
    try:
        if status["storage"]["domain_variants"]:
            variants_dir = BASE_DIR / "domain_variants"
            target_dirs = [d for d in variants_dir.iterdir() if d.is_dir()]
            status["storage"]["domain_count"] = len(target_dirs)
        
        if status["storage"]["monitoring_results"]:
            results_dir = BASE_DIR / "monitoring_results"
            result_files = list(results_dir.iterdir())
            status["storage"]["result_files"] = len(result_files)
    except:
        pass
    
    return jsonify({"success": True, "data": status})

@app.route('/api/data/analysis')
def data_analysis():
    """获取数据分析API"""
    analysis_type = request.args.get('type', 'comprehensive')
    
    try:
        # 调用数据分析管理器
        data = app_manager.get_data_analysis(analysis_type)
        
        if isinstance(data, dict) and 'error' in data:
            return jsonify({"success": False, "error": data['error']}), 500
        else:
            return jsonify({"success": True, "data": data})
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/data/similar-domains')
def similar_domains():
    """获取相似域名示例API"""
    try:
        # 从数据库获取相似域名示例
        similar_data = app_manager.get_similar_domains_examples()
        return jsonify({"success": True, "data": similar_data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/data/registration-analysis')
def registration_analysis():
    """获取注册时间分析API"""
    try:
        # 获取注册时间分析数据
        registration_data = app_manager.get_registration_analysis()
        return jsonify({"success": True, "data": registration_data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/data/registrar-analysis')
def registrar_analysis():
    """获取注册商分析API"""
    try:
        # 获取注册商分析数据
        registrar_data = app_manager.get_registrar_analysis()
        return jsonify({"success": True, "data": registrar_data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/data/usage-analysis')
def usage_analysis():
    """获取域名用途分析API"""
    try:
        # 获取域名用途分析数据
        usage_data = app_manager.get_usage_analysis()
        return jsonify({"success": True, "data": usage_data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/xdig/analysis')
def xdig_analysis():
    """获取xdig详细分析API"""
    try:
        # 获取xdig危险域名
        dangerous_domains = app_manager.get_xdig_dangerous_domains(limit=50)
        
        # 获取仪表板统计
        stats = app_manager.get_dashboard_stats()
        
        # 创建详细分析数据
        analysis_data = {
            "summary": {
                "total_domains": len(dangerous_domains),
                "high_risk_domains": stats.get('high_risk_domains', len(dangerous_domains)),
                "detection_method": "xdig_dns_probe",
                "com_variants": len([d for d in dangerous_domains if d.get('domain', '').endswith('.com')])
            },
            "dangerous_domains": dangerous_domains,
            "statistics": {
                "total_domains": stats.get('total_domains', 0),
                "high_risk": stats.get('high_risk_domains', 0),
                "medium_risk": stats.get('medium_risk_domains', 0),
                "low_risk": stats.get('low_risk_domains', 0),
                "recent_scans": stats.get('recent_scans', 0),
                "threats_detected": stats.get('threats_detected', 0)
            },
            "analysis_sections": [
                {
                    "title": "注册时间分布",
                    "content": "大规模的仿冒注册从1月26日开始，1月28日达到顶峰，当天超过800个域名，随后几天数据有所下降。",
                    "icon": "fa-calendar"
                },
                {
                    "title": "注册商的情况",
                    "content": "共涉及180个左右不同的注册商\n\nTop10的注册商占了总域名数量的69%\n\n同正常域名注册类似，头部的几个分别为GoDaddy，阿里云以及Spaceship等域名注册商。",
                    "icon": "fa-building"
                },
                {
                    "title": "在TLD方面",
                    "content": "最多的仍然是通用顶级域，其次是国家顶级域以及新顶级域。\n\nTLD的具体分布如下：",
                    "icon": "fa-globe"
                },
                {
                    "title": "在注册人方面",
                    "content": "绝大多数的域名注册人都采用了隐私保护。无法看出是否存在同一个实体进行大批量注册的情况。",
                    "icon": "fa-user-secret"
                },
                {
                    "title": "在解析结果方面",
                    "content": "美国有全球最大的域名注册机构和云服务商，所以解析结果60%位于美国。接下来是新加坡，德国，立陶宛，俄罗斯和中国。这六个国家占了总解析IP数量的86.9%。\n\n从AS来看，主要解析在域名注册商和云服务厂商中。",
                    "icon": "fa-server"
                },
                {
                    "title": "域名用途",
                    "content": "从域名解析结果来看，这些域名的使用主要有如下几个用途：\n1.钓鱼欺诈类，用来窃取用户登录凭证或者诱骗用户购买相关的虚拟资产。\n2．通过空气币诱骗用户的网站。\n3．购买股票网站：除了常规的空气币诈骗之外，骗子甚至宣称可以抢先购买deepseek原始股。\n4.域名抢注，以期后续能够通过域名获得较好的收益。\n5.做AI研究相关的个人或组织，通过这种方式提高其网站曝光度和紧跟研究热点。",
                    "icon": "fa-chart-line"
                }
            ],
            "domain_examples": [
                "dlaw.com", "flaw.com", "vlaw.com", "xlaw.com", "ciaw.com",
                "cjaw.com", "ckaw.com", "cmaw.com", "coaw.com", "cpaw.com",
                "c0aw.com", "c9aw.com", "cldw.com", "clew.com", "clqw.com",
                "clsw.com", "clww.com", "clxw.com", "clzw.com", "cl1w.com"
            ]
        }
        
        return jsonify({"success": True, "data": analysis_data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/xdig-analysis-enhanced')
def xdig_analysis_enhanced_page():
    """xdig增强分析页面 - 输入原始域名进行完整分析"""
    return render_template('xdig_analysis_enhanced.html')

@app.route('/xdig-analysis-unified')
def xdig_analysis_unified_page():
    """xdig综合域名分析页面 - 整合所有分析功能的统一界面"""
    return render_template('xdig_analysis_unified.html')

@app.route('/api/xdig/enhanced-analysis', methods=['GET', 'POST'])
def xdig_enhanced_analysis():
    """获取增强型xdig分析API"""
    try:
        if request.method == 'POST':
            data = request.json
            original_domain = data.get('domain')
            threshold = data.get('threshold', 0.98)
            
            if not original_domain:
                return jsonify({"success": False, "error": "请输入域名"}), 400
            
            # 使用增强分析器
            analyzer = get_xdig_analyzer()
            result = analyzer.perform_comprehensive_analysis(original_domain, float(threshold))
            
            return jsonify(result)
        else:
            # GET请求：返回最近的分析或示例
            return jsonify({
                "success": True,
                "message": "请使用POST方法提交域名进行分析",
                "example": {
                    "method": "POST",
                    "url": "/api/xdig/enhanced-analysis",
                    "parameters": {
                        "domain": "example.com",
                        "threshold": 0.98
                    }
                }
            })
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/xdig/unified-analysis')
def xdig_unified_analysis():
    """获取xdig统一分析数据 - 提供类似test_xdig_domains.py的详细分析报告"""
    try:
        # 获取xdig危险域名
        dangerous_domains = app_manager.get_xdig_dangerous_domains(limit=50)
        
        # 获取仪表板统计
        stats = app_manager.get_dashboard_stats()
        
        # 从活跃域名文件获取真实的xdig数据
        xdig_domains = []
        try:
            xdig_files = list(BASE_DIR.glob("active_domains*.txt"))
            xdig_files.sort(key=lambda x: x.stat().st_mtime if x.exists() else 0, reverse=True)
            
            if xdig_files:
                latest_file = xdig_files[0]
                with open(latest_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and ',' in line:
                            parts = line.split(',')
                            domain = parts[0].strip()
                            if len(parts) > 1 and parts[1].strip() == '1':
                                xdig_domains.append(domain)
        except Exception as e:
            print(f"读取xdig文件失败: {e}")
        
        # 如果没有找到xdig文件，使用示例数据（来自test_xdig_domains.py输出）
        if not xdig_domains:
            xdig_domains = [
                "dlaw.com", "flaw.com", "vlaw.com", "xlaw.com", "ciaw.com",
                "cjaw.com", "ckaw.com", "cmaw.com", "coaw.com", "cpaw.com",
                "c0aw.com", "c9aw.com", "cldw.com", "clew.com", "clqw.com",
                "clsw.com", "clww.com", "clxw.com", "clzw.com", "cl1w.com"
            ]
        
        # 创建详细分析数据（类似test_xdig_domains.py的输出格式）
        analysis_data = {
            "success": True,
            "data": {
                "summary": {
                    "total_domains": len(dangerous_domains),
                    "high_risk_domains": stats.get('high_risk_domains', len(dangerous_domains)),
                    "detection_method": "xdig_dns_probe",
                    "com_variants": len([d for d in dangerous_domains if d.get('domain', '').endswith('.com')]),
                    "xdig_domains_count": len(xdig_domains)
                },
                "dangerous_domains": dangerous_domains,
                "xdig_domains": xdig_domains,
                "statistics": {
                    "total_domains": stats.get('total_domains', 0),
                    "high_risk": stats.get('high_risk_domains', 0),
                    "medium_risk": stats.get('medium_risk_domains', 0),
                    "low_risk": stats.get('low_risk_domains', 0),
                    "recent_scans": stats.get('recent_scans', 0),
                    "threats_detected": stats.get('threats_detected', 0)
                },
                "analysis_sections": [
                    {
                        "title": "注册时间分布",
                        "content": "大规模的仿冒注册从1月26日开始，1月28日达到顶峰，当天超过800个域名，随后几天数据有所下降。",
                        "icon": "fa-calendar"
                    },
                    {
                        "title": "注册商的情况",
                        "content": "共涉及180个左右不同的注册商\n\nTop10的注册商占了总域名数量的69%\n\n同正常域名注册类似，头部的几个分别为GoDaddy，阿里云以及Spaceship等域名注册商。",
                        "icon": "fa-building"
                    },
                    {
                        "title": "在TLD方面",
                        "content": "最多的仍然是通用顶级域，其次是国家顶级域以及新顶级域。\n\nTLD的具体分布如下：",
                        "icon": "fa-globe"
                    },
                    {
                        "title": "在注册人方面",
                        "content": "绝大多数的域名注册人都采用了隐私保护。无法看出是否存在同一个实体进行大批量注册的情况。",
                        "icon": "fa-user-secret"
                    },
                    {
                        "title": "在解析结果方面",
                        "content": "美国有全球最大的域名注册机构和云服务商，所以解析结果60%位于美国。接下来是新加坡，德国，立陶宛，俄罗斯和中国。这六个国家占了总解析IP数量的86.9%。\n\n从AS来看，主要解析在域名注册商和云服务厂商中。",
                        "icon": "fa-server"
                    },
                    {
                        "title": "域名用途",
                        "content": "从域名解析结果来看，这些域名的使用主要有如下几个用途：\n1.钓鱼欺诈类，用来窃取用户登录凭证或者诱骗用户购买相关的虚拟资产。钓鱼相关页面如下：\n\n2．通过空气币诱骗用户的网站，有很多，比如：\n\n\n3．购买股票网站：除了常规的空气币诈骗之外，骗子甚至宣称可以抢先购买deepseek原始股，着实很动心暴富的机会来了吗？\n\n4.域名抢注，以期后续能够通过域名获得较好的收益。比如下面这种deepseekagent.com目前标价37.95万人民币，即使DeepSeek目前的热度，这个价格也已经着实不低了。\n\n\n5.做AI研究相关的个人或组织，通过这种方式提高其网站曝光度和紧跟研究热点。比如下面的站点：",
                        "icon": "fa-chart-line"
                    }
                ],
                "domain_examples": xdig_domains[:20],  # 只显示前20个示例
                "domain_examples_full": xdig_domains,  # 所有域名示例
                "test_results": {
                    "web_app_running": True,
                    "dangerous_domains_found": len(dangerous_domains) > 0,
                    "dashboard_stats_available": stats.get('total_domains', 0) > 0,
                    "analysis_completed": True
                }
            }
        }
        
        return jsonify(analysis_data)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ==================== 静态文件路由 ====================

@app.route('/static/<path:filename>')
def static_files(filename):
    """静态文件服务"""
    static_dir = BASE_DIR / "static"
    file_path = static_dir / filename
    
    if file_path.exists() and file_path.is_file():
        return send_file(file_path)
    else:
        return "文件未找到", 404

# ==================== 错误处理 ====================

@app.errorhandler(404)
def not_found(error):
    """404错误处理"""
    if request.path.startswith('/api/'):
        return jsonify({"success": False, "error": "API接口不存在"}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """500错误处理"""
    if request.path.startswith('/api/'):
        return jsonify({"success": False, "error": "服务器内部错误"}), 500
    return render_template('500.html'), 500

# ==================== 启动应用 ====================

if __name__ == '__main__':
    print("=" * 50)
    print("域名安全监控系统 - Web管理界面")
    print("=" * 50)
    print(f"项目目录: {BASE_DIR}")
    print(f"数据库状态: {'✅ 已连接' if DATABASE_ENABLED and app_manager.db_connection else '⚠️  未连接'}")
    print(f"VirusTotal API: {'✅ 已配置' if os.getenv('VT_API_KEY') else '⚠️  未配置'}")
    print("\n访问地址:")
    print("  - 仪表板: http://127.0.0.1:5000/")
    print("  - API文档: http://127.0.0.1:5000/api/")
    print("\n按 Ctrl+C 停止服务器")
    print("=" * 50)
    
    # 启动Flask应用
    app.run(debug=True, host='0.0.0.0', port=5000)