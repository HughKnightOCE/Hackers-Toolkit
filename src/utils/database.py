"""Database handler for storing results"""
import sqlite3
import os
from .logger import Logger

class Database:
    """SQLite database handler for toolkit results"""
    
    def __init__(self, db_path="data/toolkit.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize database and create tables"""
        os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Scan results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    result TEXT,
                    status TEXT
                )
            ''')
            
            # Host table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    hostname TEXT,
                    country TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Ports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    port_number INTEGER,
                    service TEXT,
                    state TEXT,
                    FOREIGN KEY (host_id) REFERENCES hosts(id)
                )
            ''')
            
            # Vulnerabilities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    cve_id TEXT,
                    title TEXT,
                    severity TEXT,
                    description TEXT,
                    found_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES hosts(id)
                )
            ''')
            
            conn.commit()
            conn.close()
            Logger.info("Database initialized successfully")
        except sqlite3.Error as e:
            Logger.error(f"Database initialization error: {str(e)}")
    
    def execute_query(self, query, params=None):
        """Execute a database query"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            Logger.error(f"Database query error: {str(e)}")
            return False
    
    def fetch_data(self, query, params=None):
        """Fetch data from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            results = cursor.fetchall()
            conn.close()
            return results
        except sqlite3.Error as e:
            Logger.error(f"Database fetch error: {str(e)}")
            return None
