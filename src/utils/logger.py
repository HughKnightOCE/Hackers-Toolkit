"""Logging utility for the toolkit"""
import logging
import os
from datetime import datetime

class Logger:
    """Centralized logging for all toolkit operations"""
    
    _logger = None
    
    @classmethod
    def get_logger(cls, name="HackersToolkit"):
        """Get or create logger instance"""
        if cls._logger is None:
            log_dir = "logs"
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            log_file = os.path.join(log_dir, f"toolkit_{datetime.now().strftime('%Y%m%d')}.log")
            
            cls._logger = logging.getLogger(name)
            cls._logger.setLevel(logging.DEBUG)
            
            # File handler
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            
            # Console handler
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            
            # Formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            fh.setFormatter(formatter)
            ch.setFormatter(formatter)
            
            cls._logger.addHandler(fh)
            cls._logger.addHandler(ch)
        
        return cls._logger
    
    @staticmethod
    def info(message):
        """Log info message"""
        Logger.get_logger().info(message)
    
    @staticmethod
    def error(message):
        """Log error message"""
        Logger.get_logger().error(message)
    
    @staticmethod
    def warning(message):
        """Log warning message"""
        Logger.get_logger().warning(message)
    
    @staticmethod
    def debug(message):
        """Log debug message"""
        Logger.get_logger().debug(message)
