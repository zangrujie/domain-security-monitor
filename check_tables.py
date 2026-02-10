#!/usr/bin/env python3
"""
检查数据库表状态
"""

import psycopg2
import sys

def check_tables():
    """检查当前数据库表"""
    try:
        conn = psycopg2.connect(
            host='localhost',
            port='5432',
            user='postgres',
            password='123',
            database='domain_security'
        )
        cursor = conn.cursor()
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
        tables = cursor.fetchall()
        
        print("当前数据库表:")
        if tables:
            for table in tables:
                print(f"  - {table[0]}")
        else:
            print("  ⚠️ 没有表存在")
            
        # 检查表结构
        print("\n检查关键表是否存在:")
        key_tables = ['domains', 'risk_assessments', 'dns_scans', 'http_scans', 'whois_records', 'threat_intelligence']
        for table in key_tables:
            cursor.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema='public' AND table_name=%s)", (table,))
            exists = cursor.fetchone()[0]
            status = "✅ 存在" if exists else "❌ 不存在"
            print(f"  - {table}: {status}")
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ 错误: {e}")
        return False

def create_tables_with_sqlalchemy():
    """使用SQLAlchemy创建表"""
    print("\n使用SQLAlchemy创建表...")
    try:
        from modules.database.connection import DatabaseConnection
        db = DatabaseConnection()
        if db.connect():
            print("✅ 数据库连接成功")
            db.create_tables()
            print("✅ 表创建完成")
            return True
        else:
            print("❌ 数据库连接失败")
            return False
    except Exception as e:
        print(f"❌ 创建表失败: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("检查数据库表状态")
    print("=" * 50)
    
    # 检查当前表
    if check_tables():
        print("\n尝试创建缺失的表...")
        create_tables_with_sqlalchemy()
        
        # 再次检查
        print("\n" + "=" * 50)
        print("创建后检查表状态:")
        check_tables()