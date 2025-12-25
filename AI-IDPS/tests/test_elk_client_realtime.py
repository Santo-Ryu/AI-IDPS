"""
scripts/test_elk_client_realtime.py
Test script để kiểm tra ELK Client realtime với đầy đủ metrics
- Kiểm tra khả năng fetch logs mới liên tục
- Đo latency từ lúc log vào ELK đến lúc fetch được
- Thống kê performance và throughput
- Kiểm tra tính ổn định của PIT + search_after
"""

import sys
import time
import signal
from pathlib import Path
from datetime import datetime, timedelta
from collections import deque
import statistics

sys.path.append(str(Path(__file__).parent.parent))

from src.utils.logger import get_module_logger
from src.integrations.elk_client import fetch_logs_realtime, check_connection

logger = get_module_logger("ELKTest")


class RealtimeELKTester:


def main():
    """Main function"""
    print("\n" + "="*80)
    print("🧪 ELK CLIENT REALTIME TEST")
    print("="*80 + "\n")
    
    # Check connection first
    logger.info("🔌 Kiểm tra kết nối Elasticsearch...")
    if not check_connection():
        logger.error("❌ Không thể kết nối tới Elasticsearch")
        logger.error("💡 Kiểm tra lại ES_HOST và ES_PORT trong .env")
        sys.exit(1)
    
    print()
    
    # Ask for test duration
    try:
        duration = input("⏱️  Nhập thời gian test (phút) [mặc định: 5]: ").strip()
        duration = int(duration) if duration else 5
        
        if duration <= 0:
            logger.error("❌ Thời gian test phải > 0")
            sys.exit(1)
        
        print()
        
    except ValueError:
        logger.error("❌ Thời gian test không hợp lệ")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n")
        logger.warning("⚠️  Đã hủy test")
        sys.exit(0)
    
    # Run test
    tester = RealtimeELKTester(test_duration_minutes=duration)
    tester.run_test()


if __name__ == '__main__':
    main()