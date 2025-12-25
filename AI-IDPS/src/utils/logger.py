"""
src/utils/logger.py
Advanced Logging System với màu sắc đa dạng và icon
Hỗ trợ nhiều loại thông báo khác nhau
"""

import logging
import colorlog
from datetime import datetime


class CustomLogger:
    """
    Custom Logger với nhiều màu sắc và format đẹp mắt
    Hỗ trợ các loại thông báo: DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL, SECURITY, NETWORK
    """
    
    def __init__(self, name="AI-IDPS", level=logging.INFO):
        """
        Khởi tạo logger
        Args:
            name: Tên logger
            level: Mức độ log mặc định (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.handlers.clear()  # Xóa handlers cũ
        
        # Tạo custom levels cho các loại thông báo đặc biệt
        logging.SUCCESS = 25  # Giữa INFO (20) và WARNING (30)
        logging.SECURITY = 35  # Giữa WARNING (30) và ERROR (40)
        logging.NETWORK = 15  # Giữa DEBUG (10) và INFO (20)
        
        logging.addLevelName(logging.SUCCESS, "SUCCESS")
        logging.addLevelName(logging.SECURITY, "SECURITY")
        logging.addLevelName(logging.NETWORK, "NETWORK")
        
        # Thêm các method mới vào logger
        self.logger.success = lambda msg, *args, **kwargs: self.logger.log(logging.SUCCESS, msg, *args, **kwargs)
        self.logger.security = lambda msg, *args, **kwargs: self.logger.log(logging.SECURITY, msg, *args, **kwargs)
        self.logger.network = lambda msg, *args, **kwargs: self.logger.log(logging.NETWORK, msg, *args, **kwargs)
        
        self._setup_handlers()
    
    def _setup_handlers(self):
        """Thiết lập các handler với format màu sắc"""
        
        # ==================== Console Handler với màu sắc ====================
        console_handler = colorlog.StreamHandler()
        console_formatter = colorlog.ColoredFormatter(
            fmt="%(log_color)s%(icon)s %(asctime)s | %(levelname)-8s | %(name)s | %(message)s%(reset)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            log_colors={
                'DEBUG':    'cyan',
                'NETWORK':  'blue',
                'INFO':     'green',
                'SUCCESS':  'bold_green',
                'WARNING':  'yellow',
                'SECURITY': 'bold_yellow',
                'ERROR':    'red',
                'CRITICAL': 'bold_red,bg_white',
            },
            secondary_log_colors={},
            style='%'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # ==================== File Handler (không màu) ====================
        try:
            file_handler = logging.FileHandler('logs/system.log', encoding='utf-8')
            file_formatter = logging.Formatter(
                fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
        except Exception as e:
            print(f"Không thể tạo file log: {e}")
    
    def get_logger(self):
        """Trả về logger instance"""
        return self.logger


# ==================== CUSTOM FILTER ĐỂ THÊM ICON ====================
class IconFilter(logging.Filter):
    """Filter để thêm icon vào mỗi level"""
    
    ICONS = {
        'DEBUG':    '🐛',
        'NETWORK':  '🌐',
        'INFO':     'ℹ️ ',
        'SUCCESS':  '✅',
        'WARNING':  '⚠️ ',
        'SECURITY': '🔒',
        'ERROR':    '❌',
        'CRITICAL': '🔥',
    }
    
    def filter(self, record):
        """Thêm icon vào record"""
        record.icon = self.ICONS.get(record.levelname, '📝')
        return True


# ==================== SETUP FUNCTION CHÍNH ====================
def setup_advanced_logger(name="AI-IDPS", level=logging.INFO, add_icons=True):
    """
    Hàm setup logger nâng cao với đầy đủ tính năng
    
    Args:
        name: Tên của logger
        level: Mức độ log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        add_icons: Có thêm icon vào log không
    
    Returns:
        logger instance
    """
    
    # Tạo logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()
    
    # Tạo custom levels
    logging.SUCCESS = 25
    logging.SECURITY = 35
    logging.NETWORK = 15
    
    logging.addLevelName(logging.SUCCESS, "SUCCESS")
    logging.addLevelName(logging.SECURITY, "SECURITY")
    logging.addLevelName(logging.NETWORK, "NETWORK")
    
    # Thêm methods mới
    logger.success = lambda msg, *args, **kwargs: logger.log(logging.SUCCESS, msg, *args, **kwargs)
    logger.security = lambda msg, *args, **kwargs: logger.log(logging.SECURITY, msg, *args, **kwargs)
    logger.network = lambda msg, *args, **kwargs: logger.log(logging.NETWORK, msg, *args, **kwargs)
    
    # Console handler
    console_handler = colorlog.StreamHandler()
    console_formatter = colorlog.ColoredFormatter(
        fmt="%(log_color)s%(icon)s %(asctime)s | %(levelname)-8s | %(message)s%(reset)s",
        datefmt="%H:%M:%S",
        log_colors={
            'DEBUG':    'cyan',
            'NETWORK':  'blue',
            'INFO':     'green',
            'SUCCESS':  'bold_green',
            'WARNING':  'yellow',
            'SECURITY': 'bold_yellow',
            'ERROR':    'red',
            'CRITICAL': 'bold_red,bg_white',
        },
        style='%'
    )
    console_handler.setFormatter(console_formatter)
    
    # Thêm icon filter nếu được yêu cầu
    if add_icons:
        console_handler.addFilter(IconFilter())
    
    logger.addHandler(console_handler)
    
    return logger


# ==================== LOGGER CHO TỪNG MODULE ====================
def get_module_logger(module_name):
    """
    Tạo logger riêng cho từng module
    
    Args:
        module_name: Tên module (vd: 'DataProcessor', 'AlertManager')
    
    Returns:
        logger instance
    """
    return setup_advanced_logger(name=module_name, level=logging.INFO, add_icons=True)


# ==================== RUN DEMO ====================
if __name__ == '__main__':
    demo_logger()
