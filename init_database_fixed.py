#!/usr/bin/env python3
"""
修复版的数据库初始化脚本
解决编码问题
"""

import sys
import os

def get_password_from_user():
    """从用户获取密码，处理编码问题"""
    print("请输入PostgreSQL密码（用户postgres）: ", end='', flush=True)
    
    try:
        # Windows上尝试使用msvcrt
        if sys.platform == 'win32':
            import msvcrt
            password_chars = []
            while True:
                ch = msvcrt.getch()
                if ch in (b'\r', b'\n'):  # 回车键
                    print()
                    break
                elif ch == b'\x08':  # 退格键
                    if password_chars:
                        password_chars.pop()
                        # 回退光标、清除字符、再回退
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                else:
                    password_chars.append(ch)
                    sys.stdout.write('*')
                    sys.stdout.flush()
            
            # 将字节解码为字符串
            password_bytes = b''.join(password_chars)
            try:
                return password_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # 尝试其他编码
                try:
                    return password_bytes.decode('gbk')
                except UnicodeDecodeError:
                    return password_bytes.decode('latin-1')
        else:
            # Unix/Linux/Mac
            import termios
            import tty
            
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                password_chars = []
                while True:
                    ch = sys.stdin.read(1)
                    if ch in ('\r', '\n'):
                        print()
                        break
                    elif ch == '\x08' or ch == '\x7f':  # 退格/删除
                        if password_chars:
                            password_chars.pop()
                            sys.stdout.write('\b \b')
                            sys.stdout.flush()
                    else:
                        password_chars.append(ch)
                        sys.stdout.write('*')
                        sys.stdout.flush()
                
                return ''.join(password_chars)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                
    except ImportError:
        # 备用方案：使用getpass但处理异常
        import getpass
        try:
            return getpass.getpass("请输入PostgreSQL密码（用户postgres）: ")
        except (UnicodeDecodeError, UnicodeEncodeError):
            print("警告: 检测到编码问题，请使用ASCII字符密码")
            return get_password_simple()

def get_password_simple():
    """简单的密码获取，不使用getpass"""
    print("请输入PostgreSQL密码（仅限ASCII字符）: ", end='', flush=True)
    try:
        # 使用二进制输入避免编码问题
        if hasattr(sys.stdin, 'buffer'):
            password_bytes = b''
            while True:
                ch = sys.stdin.buffer.read(1)
                if ch in (b'\r', b'\n'):
                    print()
                    break
                elif ch == b'\x08':  # 退格
                    if password_bytes:
                        password_bytes = password_bytes[:-1]
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                else:
                    password_bytes += ch
                    sys.stdout.write('*')
                    sys.stdout.flush()
            
            try:
                return password_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return password_bytes.decode('latin-1')
        else:
            return input()
    except Exception:
        return input()

def get_password():
    """获取密码，优先从.env文件读取"""
    # 首先尝试从.env文件读取
    env_file = '.env'
    if os.path.exists(env_file):
        try:
            # 尝试多种编码读取.env文件
            encodings = ['utf-8', 'gbk', 'latin-1', 'utf-8-sig']
            for encoding in encodings:
                try:
                    with open(env_file, 'r', encoding=encoding) as f:
                        content = f.read()
                        for line in content.split('\n'):
                            line = line.strip()
                            if line.startswith('DB_PASSWORD='):
                                password = line.split('=', 1)[1].strip()
                                # 移除可能的引号
                                if (password.startswith('"') and password.endswith('"')) or \
                                   (password.startswith("'") and password.endswith("'")):
                                    password = password[1:-1]
                                
                                if password and password != 'your_password_here':
                                    print(f"从.env文件读取密码: {password[:4]}...")
                                    return password
                except UnicodeDecodeError:
                    continue
        except Exception as e:
            print(f"读取.env文件失败: {e}")
    
    # 从命令行参数获取
    if len(sys.argv) > 1:
        password = sys.argv[1]
        if password and password != 'your_password_here':
            print(f"使用命令行参数密码: {password[:4]}...")
            return password
    
    # 交互式输入
    return get_password_from_user()

def create_database(password):
    """
    创建domain_security数据库
    """
    import psycopg2
    
    conn_params = {
        'host': 'localhost',
        'port': '5432',
        'user': 'postgres',
        'password': password
    }
    
    try:
        # 连接到默认数据库
        print("连接到PostgreSQL服务器...")
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
        print("\n请检查:")
        print("1. PostgreSQL服务是否正在运行")
        print("2. 连接参数是否正确")
        print("3. 密码是否正确")
        return False
    except Exception as e:
        print(f"❌ 错误: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_password(password):
    """测试密码是否正确"""
    import psycopg2
    
    conn_params = {
        'host': 'localhost',
        'port': '5432',
        'user': 'postgres',
        'password': password,
        'dbname': 'postgres'
    }
    
    try:
        conn = psycopg2.connect(**conn_params)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        return True
    except psycopg2.OperationalError:
        return False
    except Exception:
        return False

def main():
    print("PostgreSQL数据库初始化脚本（修复版）")
    print("=" * 50)
    
    # 获取密码
    password = get_password()
    
    if not password or password == 'your_password_here':
        print("❌ 无效的密码")
        print("\n请在.env文件中设置DB_PASSWORD，格式:")
        print("  DB_PASSWORD=your_actual_password")
        print("\n或直接运行:")
        print("  python init_database_fixed.py your_password")
        return 1
    
    # 测试密码
    print(f"测试密码...")
    if test_password(password):
        print("✅ 密码正确")
    else:
        print("❌ 密码错误")
        print("\n常见PostgreSQL默认密码:")
        print("  - postgres123")
        print("  - password")
        print("  - 123456")
        print("  - （安装时设置的密码）")
        print("\n如果忘记密码，需要重置PostgreSQL密码:")
        print("1. 停止PostgreSQL服务: net stop postgresql-x64-16")
        print("2. 编辑C:\\Program Files\\PostgreSQL\\16\\data\\pg_hba.conf")
        print("3. 将所有'md5'改为'trust'")
        print("4. 启动服务: net start postgresql-x64-16")
        print("5. 连接并重置密码:")
        print("   psql -U postgres")
        print("   ALTER USER postgres WITH PASSWORD 'new_password';")
        print("6. 恢复pg_hba.conf设置")
        return 1
    
    # 创建数据库
    return 0 if create_database(password) else 1

if __name__ == "__main__":
    sys.exit(main())