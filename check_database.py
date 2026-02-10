#!/usr/bin/env python3
"""
检查数据库状态脚本
"""

import psycopg2
import sys

def check_database():
    """检查数据库状态"""
    
    print("=" * 50)
    print("数据库状态检查")
    print("=" * 50)
    
    # 首先检查PostgreSQL服务是否可用
    try:
        # 连接到默认的postgres数据库
        conn = psycopg2.connect(
            host='localhost',
            port=5432,
            user='postgres',
            password='123',
            dbname='postgres'
        )
        print("✅ PostgreSQL服务运行正常")
        
        # 检查domain_security数据库是否存在
        cursor = conn.cursor()
        cursor.execute("SELECT datname FROM pg_database WHERE datname = 'domain_security'")
        result = cursor.fetchone()
        
        if result:
            print("✅ domain_security数据库存在")
            
            # 连接到domain_security数据库
            try:
                conn2 = psycopg2.connect(
                    host='localhost',
                    port=5432,
                    user='postgres',
                    password='123',
                    dbname='domain_security'
                )
                cursor2 = conn2.cursor()
                
                # 检查表数量
                cursor2.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'")
                table_count = cursor2.fetchone()[0]
                print(f"📊 domain_security数据库中有 {table_count} 张表")
                
                # 列出所有表
                cursor2.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name")
                tables = cursor2.fetchall()
                
                print("\n📋 表列表:")
                for table in tables:
                    table_name = table[0]
                    # 获取每个表的记录数
                    cursor2.execute(f"SELECT COUNT(*) FROM {table_name}")
                    count = cursor2.fetchone()[0]
                    print(f"  - {table_name}: {count} 条记录")
                
                cursor2.close()
                conn2.close()
                
            except Exception as e:
                print(f"❌ 连接到domain_security数据库失败: {e}")
                print("  可能数据库存在但表结构未初始化")
                
        else:
            print("❌ domain_security数据库不存在")
            print("  需要运行 init_database.py 来创建数据库和表")
            
        cursor.close()
        conn.close()
        
    except psycopg2.OperationalError as e:
        print(f"❌ 无法连接到PostgreSQL服务: {e}")
        print("  请检查:")
        print("  1. PostgreSQL服务是否运行 (services.msc)")
        print("  2. 连接参数是否正确 (host, port, user, password)")
        print("  3. 防火墙是否允许连接")
        return False
    except Exception as e:
        print(f"❌ 未知错误: {e}")
        return False
    
    print("\n" + "=" * 50)
    print("检查完成")
    print("=" * 50)
    return True

if __name__ == "__main__":
    check_database()