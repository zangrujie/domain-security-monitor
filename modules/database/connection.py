#!/usr/bin/env python3
"""
数据库连接管理 - 提供统一的数据库连接和会话管理
"""

import os
import logging
from typing import Optional
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session, scoped_session
from sqlalchemy.exc import SQLAlchemyError

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseConnection:
    """数据库连接管理器"""
    
    def __init__(self, connection_string: Optional[str] = None):
        """
        初始化数据库连接
        
        Args:
            connection_string: PostgreSQL连接字符串
                格式: postgresql://user:password@host:port/database
                如果为None，则从环境变量读取
        """
        self.connection_string = connection_string or self._get_connection_string()
        self.engine = None
        self.session_factory = None
        self.Session = None
        
    def _get_connection_string(self) -> str:
        """从环境变量获取连接字符串"""
        # 尝试从环境变量读取
        db_user = os.getenv('DB_USER', 'postgres')
        db_password = os.getenv('DB_PASSWORD', 'password')
        db_host = os.getenv('DB_HOST', 'localhost')
        db_port = os.getenv('DB_PORT', '5432')
        db_name = os.getenv('DB_NAME', 'domain_security')
        
        connection_string = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
        logger.info(f"使用数据库连接: {db_user}@{db_host}:{db_port}/{db_name}")
        
        return connection_string
    
    def connect(self, echo: bool = False) -> bool:
        """
        连接到数据库
        
        Args:
            echo: 是否输出SQL语句（调试用）
            
        Returns:
            bool: 连接是否成功
        """
        try:
            # 添加编码参数解决中文环境下的编码问题
            self.engine = create_engine(
                self.connection_string,
                echo=echo,
                connect_args={
                    'client_encoding': 'utf8'
                },
                pool_pre_ping=True
            )
            
            # 创建会话工厂
            self.session_factory = sessionmaker(bind=self.engine)
            self.Session = scoped_session(self.session_factory)
            
            logger.info("数据库连接成功")
            return True
            
        except Exception as e:
            logger.error(f"数据库连接失败: {e}")
            return False
    
    def get_session(self) -> Session:
        """
        获取数据库会话
        
        Returns:
            Session: SQLAlchemy会话对象
            
        Raises:
            RuntimeError: 如果未先调用connect()
        """
        if self.Session is None:
            raise RuntimeError("必须先调用connect()方法建立数据库连接")
        
        return self.Session()
    
    def close(self):
        """关闭数据库连接"""
        try:
            if self.engine:
                self.engine.dispose()
                logger.info("数据库连接已关闭")
        except Exception as e:
            logger.error(f"关闭数据库连接时出错: {e}")
    
    def test_connection(self) -> bool:
        """测试数据库连接"""
        try:
            if not self.engine:
                self.connect()
            
            with self.engine.connect() as conn:
                conn.execute("SELECT 1")
            logger.info("数据库连接测试成功")
            return True
            
        except Exception as e:
            logger.error(f"数据库连接测试失败: {e}")
            return False
    
    def create_tables(self):
        """创建所有数据库表"""
        try:
            from .models import create_tables
            create_tables(self.engine)
            logger.info("数据库表创建成功")
        except Exception as e:
            logger.error(f"创建数据库表失败: {e}")
            raise
    
    def drop_tables(self):
        """删除所有数据库表（仅用于开发和测试）"""
        try:
            from .models import drop_tables
            drop_tables(self.engine)
            logger.warning("数据库表已删除")
        except Exception as e:
            logger.error(f"删除数据库表失败: {e}")
            raise

# 全局数据库连接实例
_db_connection: Optional[DatabaseConnection] = None

def init_database(connection_string: Optional[str] = None, echo: bool = False) -> DatabaseConnection:
    """
    初始化全局数据库连接
    
    Args:
        connection_string: PostgreSQL连接字符串
        echo: 是否输出SQL语句
        
    Returns:
        DatabaseConnection: 数据库连接实例
    """
    global _db_connection
    
    if _db_connection is None:
        _db_connection = DatabaseConnection(connection_string)
        if not _db_connection.connect(echo):
            raise RuntimeError("无法连接到数据库")
    
    return _db_connection

def get_db() -> DatabaseConnection:
    """
    获取全局数据库连接
    
    Returns:
        DatabaseConnection: 数据库连接实例
        
    Raises:
        RuntimeError: 如果未先调用init_database()
    """
    if _db_connection is None:
        raise RuntimeError("必须先调用init_database()初始化数据库连接")
    
    return _db_connection

# 删除有问题的create_engine函数，因为它与SQLAlchemy的create_engine冲突
# 使用SQLAlchemy的create_engine代替
def get_session() -> Session:
    """获取数据库会话（工具函数）"""
    return get_db().get_session()

# 上下文管理器，用于自动管理会话
class DatabaseSession:
    """数据库会话上下文管理器"""
    
    def __init__(self, connection: Optional[DatabaseConnection] = None):
        self.connection = connection or get_db()
        self.session = None
    
    def __enter__(self) -> Session:
        self.session = self.connection.get_session()
        return self.session
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is not None:
                self.session.rollback()
                logger.error(f"数据库操作异常: {exc_val}")
            else:
                self.session.commit()
        except SQLAlchemyError as e:
            self.session.rollback()
            logger.error(f"数据库会话提交失败: {e}")
            raise
        finally:
            self.session.close()

if __name__ == "__main__":
    # 测试数据库连接
    db = DatabaseConnection()
    if db.connect():
        print("✅ 数据库连接测试成功")
        
        # 测试创建表
        try:
            db.create_tables()
            print("✅ 数据库表创建成功")
        except Exception as e:
            print(f"❌ 创建表失败: {e}")
        
        db.close()
    else:
        print("❌ 数据库连接测试失败")