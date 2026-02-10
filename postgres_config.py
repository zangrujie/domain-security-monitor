#!/usr/bin/env python3
"""
PostgreSQL数据库配置脚本
帮助用户设置和测试数据库连接
"""

import os
import sys
import subprocess
from pathlib import Path

def check_postgresql_installation():
    """检查PostgreSQL是否安装"""
    print("检查PostgreSQL安装状态...")
    
    # 常见安装路径
    possible_paths = [
        "C:\\Program Files\\PostgreSQL",
        "C:\\Program Files (x86)\\PostgreSQL",
        "D:\\Program Files\\PostgreSQL",
        os.path.expanduser("~") + "\\AppData\\Local\\Programs\\PostgreSQL",
    ]
    
    for path in possible_paths:
        if Path(path).exists():
            print(f"✅ 找到PostgreSQL安装目录: {path}")
            
            # 查找bin目录
            bin_paths = list(Path(path).glob("*/bin"))
            for bin_path in bin_paths:
                if bin_path.exists():
                    psql_exe = bin_path / "psql.exe"
                    if psql_exe.exists():
                        print(f"   PSQL可执行文件: {psql_exe}")
                        return str(bin_path)
    
    print("❌ 未找到PostgreSQL安装目录")
    return None

def check_service_status():
    """检查PostgreSQL服务状态"""
    print("\n检查PostgreSQL服务状态...")
    
    services = ["postgresql", "postgresql-x64", "pgsql"]
    
    for service in services:
        try:
            result = subprocess.run(
                ["sc", "query", service], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            
            if "RUNNING" in result.stdout:
                print(f"✅ {service} 服务正在运行")
                return service
            elif "STOPPED" in result.stdout:
                print(f"⚠️  {service} 服务已停止")
                return service
                
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue
    
    print("❌ 未找到PostgreSQL服务，可能未安装或服务名称不同")
    return None

def test_connection(host="localhost", port="5432", user="postgres", password=None):
    """测试数据库连接"""
    print(f"\n测试数据库连接...")
    print(f"  主机: {host}")
    print(f"  端口: {port}")
    print(f"  用户: {user}")
    
    import psycopg2
    
    try:
        conn_string = f"host={host} port={port} user={user}"
        if password:
            conn_string += f" password={password}"
        conn_string += " dbname=postgres"
        
        conn = psycopg2.connect(conn_string)
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        
        print(f"✅ 连接成功!")
        print(f"  PostgreSQL版本: {version}")
        
        # 检查是否已创建domain_security数据库
        cursor.execute("SELECT datname FROM pg_database WHERE datname = 'domain_security';")
        if cursor.fetchone():
            print(f"✅ domain_security数据库已存在")
        else:
            print(f"⚠️  domain_security数据库不存在，将自动创建")
        
        cursor.close()
        conn.close()
        return True
        
    except psycopg2.OperationalError as e:
        print(f"❌ 连接失败: {e}")
        return False
    except ImportError as e:
        print(f"❌ 缺少psycopg2模块: {e}")
        print("  请运行: pip install psycopg2-binary")
        return False

def create_env_file():
    """创建环境变量配置文件"""
    print("\n创建环境变量配置文件...")
    
    env_content = """# PostgreSQL数据库连接配置
# 请根据您的实际配置修改以下值

DB_USER=postgres
DB_PASSWORD=your_password_here
DB_HOST=localhost
DB_PORT=5432
DB_NAME=domain_security

# 可选：威胁情报API密钥
# VT_API_KEY=your_virustotal_api_key_here
# URLHAUS_API_KEY=not_required
"""
    
    env_path = Path(".env")
    env_path.write_text(env_content, encoding="utf-8")
    
    print(f"✅ 配置文件已创建: {env_path}")
    print("⚠️  请编辑此文件，将DB_PASSWORD修改为您的实际密码")
    
    return env_path

def create_database_script():
    """创建数据库初始化脚本"""
    print("\n创建数据库初始化脚本...")
    
    script_content = '''#!/usr/bin/env python3

import psycopg2
import sys

def create_database():
    """
    创建domain_security数据库
    """
    # 默认连接参数 - 修改为您实际的参数
    conn_params = {
        'host': 'localhost',
        'port': '5432',
        'user': 'postgres',
        'password': 'your_password_here'
    }
    
    try:
        # 连接到默认数据库
        print(f"连接到PostgreSQL服务器...")
        conn = psycopg2.connect(**conn_params)
        conn.autocommit = True
        cursor = conn.cursor()
        
        # 创建数据库（如果不存在）
        print("检查domain_security数据库...")
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = 'domain_security'")
        if not cursor.fetchone():
            print("创建domain_security数据库...")
            cursor.execute("CREATE DATABASE domain_security")
            print("✅ domain_security数据库创建成功")
        else:
            print("✅ domain_security数据库已存在")
        
        # 连接到新创建的数据库
        conn_params['database'] = 'domain_security'
        conn = psycopg2.connect(**conn_params)
        cursor = conn.cursor()
        
        # 创建表（将由SQLAlchemy自动创建）
        print("✅ 数据库已准备就绪")
        print("运行数据管道时将自动创建表结构")
        
        cursor.close()
        conn.close()
        return True
        
    except psycopg2.OperationalError as e:
        print(f"❌ 连接失败: {e}")
        print("\\n请检查:")
        print("1. PostgreSQL服务是否正在运行")
        print("2. 连接参数是否正确")
        print("3. 密码是否正确")
        return False
    except Exception as e:
        print(f"❌ 错误: {e}")
        return False

if __name__ == "__main__":
    print("PostgreSQL数据库初始化脚本")
    print("=" * 50)
    
    # 提示用户输入密码
    import getpass
    password = getpass.getpass("请输入PostgreSQL密码（用户postgres）: ")
    
    # 更新连接参数
    conn_params = {
        'host': 'localhost',
        'port': '5432',
        'user': 'postgres',
        'password': password
    }
    
    create_database()'''
    
    script_path = Path("init_database.py")
    script_path.write_text(script_content, encoding="utf-8")
    
    print(f"✅ 初始化脚本已创建: {script_path}")
    print("⚠️  运行此脚本前，请确保PostgreSQL服务正在运行")
    
    return script_path

def main():
    print("=" * 60)
    print("PostgreSQL数据库配置助手")
    print("=" * 60)
    
    # 检查安装
    bin_path = check_postgresql_installation()
    
    # 检查服务状态
    service = check_service_status()
    
    # 提示用户
    print("\n📌 下一步操作建议:")
    
    if not service:
        print("1. 启动PostgreSQL安装程序，完成安装")
        print("2. 确保在安装过程中设置好密码")
        print("3. 启动PostgreSQL服务")
    elif "STOPPED" in str(service):
        print("1. 启动PostgreSQL服务:")
        print("   net start postgresql")
        print("   或使用服务管理器启动")
    else:
        print("✅ PostgreSQL服务正在运行")
    
    # 创建配置文件
    env_file = create_env_file()
    
    # 创建初始化脚本
    script_file = create_database_script()
    
    # 测试连接
    print("\n🔧 测试连接:")
    print("1. 首先编辑 .env 文件，设置正确的密码")
    print("2. 然后运行: python init_database.py")
    print("3. 或直接运行数据管道: python -m modules.data_pipeline -d example.com")
    
    print("\n" + "=" * 60)
    print("完成配置后，运行以下命令测试:")
    print("  python -m modules.data_pipeline -d test.com")
    print("=" * 60)

if __name__ == "__main__":
    main()