#!/usr/bin/env python3
"""
尝试找出PostgreSQL密码
"""

import subprocess
import sys
import time

def test_password(password):
    """测试密码是否正确"""
    try:
        # 使用psql命令测试密码
        cmd = f'psql -U postgres -h localhost -c "SELECT 1;" -w -t'
        env = {'PGPASSWORD': password}
        
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True,
            env=env,
            timeout=5
        )
        
        if result.returncode == 0 and '1' in result.stdout:
            return True
        return False
        
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def test_password_python(password):
    """使用Python的psycopg2测试密码"""
    try:
        import psycopg2
        
        conn_params = {
            'host': 'localhost',
            'port': '5432',
            'user': 'postgres',
            'password': password,
            'dbname': 'postgres'
        }
        
        conn = psycopg2.connect(**conn_params)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        return True
        
    except Exception:
        return False

def main():
    print("PostgreSQL密码测试工具")
    print("=" * 50)
    
    # 常见PostgreSQL默认密码
    common_passwords = [
        'postgres123',      # 常见默认
        'password',         # 通用默认
        '123456',           # 简单密码
        'postgres',         # 用户名作为密码
        'admin',            # 管理员密码
        'root',             # root密码
        '',                 # 空密码
        'postgresql',       # 服务名作为密码
        'admin123',         # 常见组合
        'postgres2023',     # 带年份
        'postgres2024',
        'postgres2025',
        'postgres2026',
        'P@ssw0rd',         # 复杂密码
        'Password1!',       # 带特殊字符
        '12345678',         # 数字
        'qwerty',           # 键盘序列
        '123456789',
        '123123',
        '111111',
        'abc123',
        'password123',
    ]
    
    print(f"尝试 {len(common_passwords)} 个常见密码...")
    print()
    
    found_password = None
    
    for i, password in enumerate(common_passwords):
        print(f"测试密码 {i+1}/{len(common_passwords)}: {password}", end='')
        
        if test_password_python(password):
            print(" ✅ 正确!")
            found_password = password
            break
        else:
            print(" ❌ 错误")
    
    if found_password:
        print(f"\n✅ 找到密码: {found_password}")
        print("\n请更新.env文件:")
        print(f"  DB_PASSWORD={found_password}")
        
        # 更新.env文件
        try:
            with open('.env', 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 替换密码
            lines = content.split('\n')
            new_lines = []
            for line in lines:
                if line.startswith('DB_PASSWORD='):
                    new_lines.append(f'DB_PASSWORD={found_password}')
                else:
                    new_lines.append(line)
            
            with open('.env', 'w', encoding='utf-8') as f:
                f.write('\n'.join(new_lines))
            
            print("✅ .env文件已更新")
            
        except Exception as e:
            print(f"❌ 更新.env文件失败: {e}")
            print("请手动编辑.env文件，将DB_PASSWORD设置为上述密码")
        
        print("\n下一步:")
        print("1. 运行数据库初始化: python init_database_fixed.py")
        print("2. 测试数据库: python test_db_simple.py")
        print("3. 运行数据管道: python -m modules.data_pipeline -d test.com")
        
    else:
        print("\n❌ 未找到正确的密码")
        print("\n建议:")
        print("1. 回忆安装PostgreSQL时设置的密码")
        print("2. 尝试以下方法重置密码:")
        print("   a. 停止服务: net stop postgresql-x64-16")
        print("   b. 编辑 pg_hba.conf 文件:")
        print("      C:\\Program Files\\PostgreSQL\\16\\data\\pg_hba.conf")
        print("   c. 将 'md5' 改为 'trust'")
        print("   d. 启动服务: net start postgresql-x64-16")
        print("   e. 连接: psql -U postgres")
        print("   f. 重置密码: ALTER USER postgres WITH PASSWORD '新密码';")
        print("   g. 恢复pg_hba.conf设置")
        print("3. 或者使用简单的密码重新安装PostgreSQL")
    
    return 0 if found_password else 1

if __name__ == "__main__":
    # 检查psycopg2是否安装
    try:
        import psycopg2
    except ImportError:
        print("❌ psycopg2未安装")
        print("运行: pip install psycopg2-binary")
        sys.exit(1)
    
    sys.exit(main())