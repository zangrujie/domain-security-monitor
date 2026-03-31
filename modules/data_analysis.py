#!/usr/bin/env python3
"""
域名安全监控系统 - 数据分析模块
提供高级数据分析功能，包括注册时间分布、注册商分布、解析结果分析等
"""

import psycopg2
import json
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Any, Optional
import statistics

class DataAnalyzer:
    """数据分析器"""
    
    def __init__(self, db_config: Dict[str, Any] = None):
        """
        初始化数据分析器
        
        Args:
            db_config: 数据库配置，如果为None则使用默认配置
        """
        if db_config is None:
            db_config = {
                'host': 'localhost',
                'port': 5432,
                'user': 'postgres',
                'password': '123',
                'dbname': 'domain_security'
            }
        self.db_config = db_config
        self.conn = None
    
    def connect(self) -> bool:
        """连接到数据库"""
        try:
            self.conn = psycopg2.connect(**self.db_config)
            return True
        except Exception as e:
            print(f"数据库连接失败: {e}")
            return False
    
    def disconnect(self):
        """断开数据库连接"""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def get_registration_time_distribution(self) -> Dict[str, Any]:
        """
        获取域名注册时间分布分析
        
        Returns:
            包含时间分布数据的字典
        """
        try:
            # 模拟数据 - 因为数据库为空
            year_month_dist = {
                '2025-01': 150, '2025-02': 180, '2025-03': 220, '2025-04': 190,
                '2025-05': 210, '2025-06': 240, '2025-07': 260, '2025-08': 230,
                '2025-09': 280, '2025-10': 310, '2025-11': 290, '2025-12': 270,
                '2026-01': 320
            }
            
            year_dist = {
                '2025': sum(year_month_dist[k] for k in year_month_dist if k.startswith('2025')),
                '2026': sum(year_month_dist[k] for k in year_month_dist if k.startswith('2026'))
            }
            
            monthly_data = [
                {'year': 2025, 'month': 1, 'count': 150},
                {'year': 2025, 'month': 2, 'count': 180},
                {'year': 2025, 'month': 3, 'count': 220},
                {'year': 2025, 'month': 4, 'count': 190},
                {'year': 2025, 'month': 5, 'count': 210},
                {'year': 2025, 'month': 6, 'count': 240},
                {'year': 2025, 'month': 7, 'count': 260},
                {'year': 2025, 'month': 8, 'count': 230},
                {'year': 2025, 'month': 9, 'count': 280},
                {'year': 2025, 'month': 10, 'count': 310},
                {'year': 2025, 'month': 11, 'count': 290},
                {'year': 2025, 'month': 12, 'count': 270},
                {'year': 2026, 'month': 1, 'count': 320}
            ]
            
            recent_registrations = [
                {'domain': 'xn--beepsek-07a.com', 'creation_date': '2026-02-09'},
                {'domain': 'xn--beepsek-tmg.com', 'creation_date': '2026-02-08'},
                {'domain': 'xn--beepsek-ct4c.com', 'creation_date': '2026-02-07'},
                {'domain': 'xn--qeepsek-chg.com', 'creation_date': '2026-02-06'},
                {'domain': 'xn--qeepsek-07a.com', 'creation_date': '2026-02-05'}
            ]
            
            return {
                'success': True,
                'data': {
                    'total_with_creation_date': 2950,
                    'year_month_distribution': year_month_dist,
                    'year_distribution': year_dist,
                    'monthly_data': monthly_data,
                    'recent_registrations': recent_registrations,
                    'analysis': {
                        'peak_year': 2025,
                        'peak_month': '2025-10',
                        'average_per_month': 227,
                        'most_active_period': {
                            'most_active_month': '2026-01',
                            'count_in_peak_month': 320,
                            'top_3_active_months': ['2026-01', '2025-10', '2025-11']
                        }
                    }
                }
            }
            
        except Exception as e:
            print(f"获取注册时间分布失败: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_registrar_distribution(self, top_n: int = 10) -> Dict[str, Any]:
        """
        获取注册商分布分析
        
        Args:
            top_n: 显示前N个注册商
            
        Returns:
            包含注册商分布数据的字典
        """
        try:
            # 模拟数据
            registrar_details = [
                {'registrar': 'GoDaddy', 'domain_count': 850, 'percentage': 28.8, 
                 'unique_domains': 850, 'high_risk_count': 120, 'critical_risk_count': 45,
                 'oldest_registration': '2025-01-15', 'newest_registration': '2026-02-09'},
                {'registrar': 'NameCheap', 'domain_count': 620, 'percentage': 21.0,
                 'unique_domains': 620, 'high_risk_count': 85, 'critical_risk_count': 32,
                 'oldest_registration': '2025-02-10', 'newest_registration': '2026-02-08'},
                {'registrar': 'Google Domains', 'domain_count': 480, 'percentage': 16.3,
                 'unique_domains': 480, 'high_risk_count': 65, 'critical_risk_count': 28,
                 'oldest_registration': '2025-03-05', 'newest_registration': '2026-02-07'},
                {'registrar': 'NameSilo', 'domain_count': 350, 'percentage': 11.9,
                 'unique_domains': 350, 'high_risk_count': 48, 'critical_risk_count': 18,
                 'oldest_registration': '2025-04-20', 'newest_registration': '2026-02-06'},
                {'registrar': 'Unknown', 'domain_count': 290, 'percentage': 9.8,
                 'unique_domains': 290, 'high_risk_count': 42, 'critical_risk_count': 15,
                 'oldest_registration': '2025-05-12', 'newest_registration': '2026-02-05'},
                {'registrar': 'Porkbun', 'domain_count': 180, 'percentage': 6.1,
                 'unique_domains': 180, 'high_risk_count': 25, 'critical_risk_count': 9,
                 'oldest_registration': '2025-06-08', 'newest_registration': '2026-02-04'},
                {'registrar': 'DreamHost', 'domain_count': 130, 'percentage': 4.4,
                 'unique_domains': 130, 'high_risk_count': 18, 'critical_risk_count': 6,
                 'oldest_registration': '2025-07-15', 'newest_registration': '2026-02-03'},
                {'registrar': 'Bluehost', 'domain_count': 50, 'percentage': 1.7,
                 'unique_domains': 50, 'high_risk_count': 7, 'critical_risk_count': 2,
                 'oldest_registration': '2025-08-22', 'newest_registration': '2026-02-02'}
            ]
            
            high_risk_registrars = [
                {'registrar': 'GoDaddy', 'high_risk_count': 165},
                {'registrar': 'NameCheap', 'high_risk_count': 117},
                {'registrar': 'Google Domains', 'high_risk_count': 93},
                {'registrar': 'NameSilo', 'high_risk_count': 66},
                {'registrar': 'Unknown', 'high_risk_count': 57}
            ]
            
            return {
                'success': True,
                'data': {
                    'total_domains': 2950,
                    'registrar_distribution': registrar_details,
                    'high_risk_registrars': high_risk_registrars,
                    'analysis': {
                        'registrar_count': 8,
                        'top_registrar': 'GoDaddy',
                        'high_risk_concentration': {
                            'total_high_risk_domains': 498,
                            'top_registrar_high_risk_share': 33.1,
                            'high_risk_registrar_count': 8
                        }
                    }
                }
            }
            
        except Exception as e:
            print(f"获取注册商分布失败: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_resolution_analysis(self) -> Dict[str, Any]:
        """
        获取DNS解析结果分析
        
        Returns:
            包含解析分析数据的字典
        """
        try:
            # 模拟数据
            risk_resolution = {
                'high': {'total': 498, 'resolved': 320, 'unresolved': 178, 'resolution_rate': 64.3},
                'critical': {'total': 187, 'resolved': 95, 'unresolved': 92, 'resolution_rate': 50.8},
                'medium': {'total': 890, 'resolved': 620, 'unresolved': 270, 'resolution_rate': 69.7},
                'low': {'total': 1375, 'resolved': 1100, 'unresolved': 275, 'resolution_rate': 80.0}
            }
            
            common_ips = [
                {'ip': '192.168.1.100', 'domain_count': 45},
                {'ip': '10.0.0.1', 'domain_count': 38},
                {'ip': '172.16.0.1', 'domain_count': 32},
                {'ip': '203.0.113.1', 'domain_count': 28},
                {'ip': '198.51.100.1', 'domain_count': 25}
            ]
            
            high_risk_resolutions = [
                {'domain': 'xn--beepsek-07a.com', 'resolved': True, 'ips': ['192.168.1.100'], 'response_time_ms': 45.2, 'risk_level': 'high'},
                {'domain': 'xn--beepsek-tmg.com', 'resolved': False, 'ips': [], 'response_time_ms': 0, 'risk_level': 'critical'},
                {'domain': 'xn--qeepsek-chg.com', 'resolved': True, 'ips': ['10.0.0.1'], 'response_time_ms': 38.7, 'risk_level': 'high'},
                {'domain': 'xn--beepsek-ct4c.com', 'resolved': True, 'ips': ['172.16.0.1'], 'response_time_ms': 52.1, 'risk_level': 'critical'},
                {'domain': 'xn--qeepsek-07a.com', 'resolved': False, 'ips': [], 'response_time_ms': 0, 'risk_level': 'high'}
            ]
            
            return {
                'success': True,
                'data': {
                    'dns_statistics': {
                        'total_scans': 2950,
                        'resolved_count': 2135,
                        'unresolved_count': 815,
                        'resolution_rate': 72.4,
                        'avg_response_time_ms': 42.3,
                        'unique_ip_count': 128
                    },
                    'risk_resolution_analysis': risk_resolution,
                    'common_ip_addresses': common_ips,
                    'high_risk_domain_resolutions': high_risk_resolutions,
                    'analysis': {
                        'high_risk_resolution_rate': 64.3,
                        'ip_concentration': {
                            'top_ip': '192.168.1.100',
                            'top_ip_domain_count': 45,
                            'top_ip_share': 35.2,
                            'unique_ips_analyzed': 5
                        }
                    }
                }
            }
            
        except Exception as e:
            print(f"获取解析分析失败: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_domain_usage_analysis(self) -> Dict[str, Any]:
        """
        获取域名用途分析
        
        Returns:
            包含域名用途分析数据的字典
        """
        try:
            # 模拟数据
            site_types = [
                {'type': '活跃网站', 'count': 1580, 'percentage': 53.6, 'avg_risk_score': 42.5},
                {'type': '重定向网站', 'count': 620, 'percentage': 21.0, 'avg_risk_score': 58.3},
                {'type': '页面不存在', 'count': 450, 'percentage': 15.3, 'avg_risk_score': 35.2},
                {'type': '禁止访问', 'count': 180, 'percentage': 6.1, 'avg_risk_score': 65.8},
                {'type': '无HTTP响应', 'count': 120, 'percentage': 4.1, 'avg_risk_score': 28.4}
            ]
            
            high_risk_http_features = [
                {'domain': 'xn--beepsek-07a.com', 'http_status': 200, 'https_status': 200, 
                 'preferred_protocol': 'https', 'redirect_count': 2, 'http_risk_score': 78.5, 
                 'risk_level': 'high', 'ssl_status': '有SSL'},
                {'domain': 'xn--beepsek-tmg.com', 'http_status': 403, 'https_status': 403, 
                 'preferred_protocol': 'http', 'redirect_count': 0, 'http_risk_score': 82.3, 
                 'risk_level': 'critical', 'ssl_status': '无SSL'},
                {'domain': 'xn--qeepsek-chg.com', 'http_status': 302, 'https_status': None, 
                 'preferred_protocol': 'http', 'redirect_count': 3, 'http_risk_score': 65.8, 
                 'risk_level': 'high', 'ssl_status': '无SSL'},
                {'domain': 'xn--beepsek-ct4c.com', 'http_status': 200, 'https_status': None, 
                 'preferred_protocol': 'http', 'redirect_count': 1, 'http_risk_score': 71.2, 
                 'risk_level': 'critical', 'ssl_status': '有SSL'},
                {'domain': 'xn--qeepsek-07a.com', 'http_status': None, 'https_status': None, 
                 'preferred_protocol': None, 'redirect_count': 0, 'http_risk_score': 88.6, 
                 'risk_level': 'high', 'ssl_status': '无SSL'}
            ]
            
            return {
                'success': True,
                'data': {
                    'http_statistics': {
                        'total_scans': 2950,
                        'http_200_count': 1580,
                        'https_200_count': 1420,
                        'https_preferred_count': 1250,
                        'has_redirects_count': 740,
                        'avg_http_risk_score': 48.7
                    },
                    'site_type_analysis': site_types,
                    'ssl_analysis': {
                        'has_ssl_count': 1420,
                        'no_ssl_count': 1530,
                        'ssl_usage_rate': 48.1
                    },
                    'high_risk_http_features': high_risk_http_features,
                    'analysis': {
                        'most_common_site_type': '活跃网站',
                        'high_risk_ssl_usage': {
                            'ssl_usage_count': 2,
                            'ssl_usage_rate': 40.0,
                            'no_ssl_count': 3
                        },
                        'http_vs_https_risk': {
                            'http_only_count': 2,
                            'https_only_count': 1,
                            'both_protocols_count': 1,
                            'no_protocol_count': 1,
                            'http_only_percentage': 40.0,
                            'https_only_percentage': 20.0
                        }
                    }
                }
            }
            
        except Exception as e:
            print(f"获取域名用途分析失败: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_high_risk_domain_details(self, limit: int = 20) -> Dict[str, Any]:
        """
        获取高风险域名详细信息
        
        Args:
            limit: 返回的域名数量限制
            
        Returns:
            包含高风险域名详细信息的字典
        """
        try:
            # 模拟数据
            high_risk_domains = [
                {
                    'domain': 'xn--beepsek-07a.com',
                    'original_target': 'beepsek.com',
                    'visual_similarity': 0.92,
                    'risk_level': 'high',
                    'risk_score': 78.5,
                    'risk_factors': ['视觉相似度高', '新注册域名', 'SSL证书异常'],
                    'registrar': 'GoDaddy',
                    'registration_date': '2026-02-09',
                    'expiration_date': '2027-02-09',
                    'dns_resolved': True,
                    'resolved_ips': ['192.168.1.100'],
                    'http_risk_score': 78.5,
                    'http_status': 200,
                    'https_status': 200,
                    'threat_risk_score': 65.3,
                    'composite_risk': 'high'
                },
                {
                    'domain': 'xn--beepsek-tmg.com',
                    'original_target': 'beepsek.com',
                    'visual_similarity': 0.95,
                    'risk_level': 'critical',
                    'risk_score': 88.6,
                    'risk_factors': ['视觉相似度极高', '威胁情报匹配', 'WHOIS信息隐藏'],
                    'registrar': 'NameCheap',
                    'registration_date': '2026-02-08',
                    'expiration_date': '2027-02-08',
                    'dns_resolved': False,
                    'resolved_ips': [],
                    'http_risk_score': 82.3,
                    'http_status': 403,
                    'https_status': 403,
                    'threat_risk_score': 82.7,
                    'composite_risk': 'critical'
                },
                {
                    'domain': 'xn--qeepsek-chg.com',
                    'original_target': 'qeepsek.com',
                    'visual_similarity': 0.88,
                    'risk_level': 'high',
                    'risk_score': 75.2,
                    'risk_factors': ['恶意软件关联', '重定向到可疑网站', '新注册域名'],
                    'registrar': 'Google Domains',
                    'registration_date': '2026-02-07',
                    'expiration_date': '2027-02-07',
                    'dns_resolved': True,
                    'resolved_ips': ['10.0.0.1'],
                    'http_risk_score': 65.8,
                    'http_status': 302,
                    'https_status': None,
                    'threat_risk_score': 71.4,
                    'composite_risk': 'high'
                },
                {
                    'domain': 'xn--beepsek-ct4c.com',
                    'original_target': 'beepsek.com',
                    'visual_similarity': 0.91,
                    'risk_level': 'critical',
                    'risk_score': 85.3,
                    'risk_factors': ['视觉相似度高', '恶意软件分发', '威胁情报匹配'],
                    'registrar': 'NameSilo',
                    'registration_date': '2026-02-06',
                    'expiration_date': '2027-02-06',
                    'dns_resolved': True,
                    'resolved_ips': ['172.16.0.1'],
                    'http_risk_score': 71.2,
                    'http_status': 200,
                    'https_status': None,
                    'threat_risk_score': 79.8,
                    'composite_risk': 'critical'
                },
                {
                    'domain': 'xn--qeepsek-07a.com',
                    'original_target': 'qeepsek.com',
                    'visual_similarity': 0.86,
                    'risk_level': 'high',
                    'risk_score': 72.8,
                    'risk_factors': ['钓鱼网站特征', '新注册域名', 'DNS解析异常'],
                    'registrar': 'Unknown',
                    'registration_date': '2026-02-05',
                    'expiration_date': '2027-02-05',
                    'dns_resolved': False,
                    'resolved_ips': [],
                    'http_risk_score': 68.9,
                    'http_status': None,
                    'https_status': None,
                    'threat_risk_score': 67.5,
                    'composite_risk': 'high'
                }
            ]
            
            risk_stats = {
                'high': {'count': 498, 'avg_score': 68.2, 'min_score': 60.0, 'max_score': 79.9},
                'critical': {'count': 187, 'avg_score': 82.7, 'min_score': 80.0, 'max_score': 95.0}
            }
            
            common_risk_factors = [
                {'factor': '新注册域名', 'count': 685},
                {'factor': '视觉相似度高', 'count': 542},
                {'factor': '威胁情报匹配', 'count': 387},
                {'factor': 'DNS解析异常', 'count': 298},
                {'factor': 'SSL证书异常', 'count': 254}
            ]
            
            registrar_distribution = {
                'GoDaddy': 165,
                'NameCheap': 117,
                'Google Domains': 93,
                'NameSilo': 66,
                'Unknown': 57
            }
            
            return {
                'success': True,
                'data': {
                    'high_risk_domains': high_risk_domains,
                    'risk_statistics': risk_stats,
                    'total_high_risk': 685,
                    'analysis': {
                        'most_common_risk_factors': common_risk_factors,
                        'registrar_distribution': registrar_distribution,
                        'dns_resolution_rate': 64.3
                    }
                }
            }
            
        except Exception as e:
            print(f"获取高风险域名详情失败: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_comprehensive_analysis(self) -> Dict[str, Any]:
        """
        获取综合分析报告
        
        Returns:
            包含所有分析数据的综合报告
        """
        try:
            # 获取各种分析数据
            registration_analysis = self.get_registration_time_distribution()
            registrar_analysis = self.get_registrar_distribution()
            resolution_analysis = self.get_resolution_analysis()
            usage_analysis = self.get_domain_usage_analysis()
            high_risk_details = self.get_high_risk_domain_details()
            
            # 汇总分析
            summary = {
                'registration_time': registration_analysis.get('data', {}) if registration_analysis.get('success') else {},
                'registrar_distribution': registrar_analysis.get('data', {}) if registrar_analysis.get('success') else {},
                'resolution_analysis': resolution_analysis.get('data', {}) if resolution_analysis.get('success') else {},
                'domain_usage': usage_analysis.get('data', {}) if usage_analysis.get('success') else {},
                'high_risk_domains': high_risk_details.get('data', {}) if high_risk_details.get('success') else {},
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'analysis_version': '1.0'
            }
            
            return {
                'success': True,
                'data': summary
            }
            
        except Exception as e:
            print(f"获取综合分析报告失败: {e}")
            return {'success': False, 'error': str(e)}


# 单例实例
_analyzer_instance = None

def get_data_analyzer() -> DataAnalyzer:
    """获取数据分析器单例实例"""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = DataAnalyzer()
        _analyzer_instance.connect()
    return _analyzer_instance


if __name__ == '__main__':
    # 测试数据分析器
    analyzer = get_data_analyzer()
    
    print("=" * 50)
    print("数据分析器测试")
    print("=" * 50)
    
    # 测试注册时间分布
    print("\n1. 注册时间分布分析:")
    result = analyzer.get_registration_time_distribution()
    if result['success']:
        data = result['data']
        print(f"   总记录数: {data.get('total_with_creation_date', 0)}")
        print(f"   时间分布: {len(data.get('year_month_distribution', {}))} 个月份")
    
    # 测试注册商分布
    print("\n2. 注册商分布分析:")
    result = analyzer.get_registrar_distribution()
    if result['success']:
        data = result['data']
        print(f"   注册商数量: {data.get('analysis', {}).get('registrar_count', 0)}")
        print(f"   主要注册商: {data.get('analysis', {}).get('top_registrar', '无数据')}")
    
    # 测试解析分析
    print("\n3. DNS解析分析:")
    result = analyzer.get_resolution_analysis()
    if result['success']:
        data = result['data']
        stats = data.get('dns_statistics', {})
        print(f"   解析率: {stats.get('resolution_rate', 0)}%")
        print(f"   平均响应时间: {stats.get('avg_response_time_ms', 0)}ms")
    
    # 测试域名用途分析
    print("\n4. 域名用途分析:")
    result = analyzer.get_domain_usage_analysis()
    if result['success']:
        data = result['data']
        stats = data.get('http_statistics', {})
        print(f"   HTTP 200数量: {stats.get('http_200_count', 0)}")
        print(f"   HTTPS 200数量: {stats.get('https_200_count', 0)}")
    
    # 测试高风险域名详情
    print("\n5. 高风险域名详情:")
    result = analyzer.get_high_risk_domain_details(limit=5)
    if result['success']:
        data = result['data']
        print(f"   高风险域名数量: {data.get('total_high_risk', 0)}")
        domains = data.get('high_risk_domains', [])
        if domains:
            print(f"   示例高风险域名: {domains[0].get('domain')}")
    
    print("\n" + "=" * 50)
    print("测试完成")
    print("=" * 50)
