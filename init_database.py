#!/usr/bin/env python3

import psycopg2
import sys

def create_database(conn_params: dict) -> bool:
    """
    创建domain_security数据库
    """
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
        # 使用 repr 避免内部字节解码错误导致的显示异常
        print(f"❌ 连接失败: {repr(e)}")
        print("\n请检查:")
        print("1. PostgreSQL服务是否正在运行")
        print("2. 连接参数是否正确")
        print("3. 密码是否正确")
        return False
    except Exception as e:
        print(f"❌ 错误: {repr(e)}")
        return False

if __name__ == "__main__":
    print("PostgreSQL数据库初始化脚本")
    print("=" * 50)
    
    # 提示用户输入密码
    import getpass
    password = getpass.getpass("请输入PostgreSQL密码（用户postgres）: ")

    # 更新连接参数并调用创建函数
    conn_params = {
        'host': 'localhost',
        'port': '5432',
        'user': 'postgres',
        'password': password
    }

    success = create_database(conn_params)
    if success:
        sys.exit(0)
    else:
        sys.exit(1)