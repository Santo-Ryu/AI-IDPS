"""
tests/test_elk_client.py
Test ELK Client - Fetch pfSense firewall logs và lưu vào file JSONL

Chức năng:
- --once: Fetch 1000 logs mới nhất một lần → hiển thị thống kê + lưu file
- --stream: Realtime streaming → mỗi batch mới nhận được sẽ append vào file
- File lưu: data/raw/elk_logs.jsonl (JSON Lines format)
- Có __main__ để chạy trực tiếp
"""

import argparse
import json
import os
import sys
from datetime import datetime

import yaml

from src.integrations.elk_client import check_connection, fetch_logs_realtime
from src.utils.logger import get_module_logger

logger = get_module_logger("TestELKClient")

# =================== LOAD CONFIG ĐỂ LẤY ĐƯỜNG DẪN LƯU FILE ===================
CONFIG_PATH = "config/config.yaml"

def load_log_file_path() -> str:
    if not os.path.exists(CONFIG_PATH):
        logger.error(f"❌ Không tìm thấy file config: {CONFIG_PATH}")
        sys.exit(1)

    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    log_path = config.get('data', {}).get('elk_logs')
    if not log_path:
        logger.error("❌ Không tìm thấy 'data.elk_logs' trong config.yaml")
        sys.exit(1)

    # Đảm bảo phần mở rộng là .jsonl
    if not log_path.endswith('.jsonl'):
        log_path = log_path.rstrip('/') + '.jsonl'

    # Tạo thư mục nếu chưa tồn tại
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    return log_path

ELK_LOGS_PATH = load_log_file_path()


def append_logs_to_file(logs: list[dict]):
    """Append batch logs vào file JSONL (mỗi log một dòng)"""
    if not logs:
        return

    try:
        with open(ELK_LOGS_PATH, 'a', encoding='utf-8') as f:
            for log in logs:
                json.dump(log, f, ensure_ascii=False)
                f.write('\n')
        logger.info(f"💾 Đã append {len(logs)} logs vào {ELK_LOGS_PATH}")
    except Exception as e:
        logger.error(f"❌ Lỗi ghi file logs: {e}")


def test_once():
    """Test fetch một lần duy nhất - lấy 1000 logs mới nhất và lưu file"""
    logger.info("🧪 Chế độ TEST ONCE - Fetch 1000 logs mới nhất")

    if not check_connection():
        sys.exit(1)

    # Tạo generator với batch_size lớn hơn để lấy initial batch 1000 logs
    stream_gen = fetch_logs_realtime(batch_size=500, interval=10)

    try:
        # Lần next đầu tiên sẽ trả về batch initial 1000 logs mới nhất
        batch_logs = next(stream_gen)
        logger.success(f"✅ Fetch thành công {len(batch_logs)} logs mới nhất")

        # Lưu vào file JSONL
        append_logs_to_file(batch_logs)

        print("\n" + "═" * 100)
        print("                  📊 1000 LOGS FIREWALL MỚI NHẤT (đã lưu file)")
        print("═" * 100)
        print(f"   📁 File lưu: {ELK_LOGS_PATH}")
        print("═" * 100 + "\n")

    except StopIteration:
        logger.warning("⚠️ Không có logs nào để fetch")
    except Exception as e:
        logger.error(f"❌ Lỗi khi fetch: {e}")
        sys.exit(1)


def test_stream(batch_size: int = 500, interval: int = 20):
    """Test realtime streaming - liên tục fetch và append vào file"""
    logger.success("🚀 Chế độ REALTIME STREAMING - Theo dõi + lưu logs liên tục")
    logger.info(f"   Batch size (sau initial): {batch_size}")
    logger.info(f"   Interval: {interval}s")
    logger.info(f"   Initial batch: 1000 logs mới nhất")
    logger.info(f"   Logs sẽ được append vào: {ELK_LOGS_PATH}")
    logger.info("   Nhấn Ctrl+C để dừng\n")

    if not check_connection():
        sys.exit(1)

    try:
        for batch_logs in fetch_logs_realtime(batch_size=batch_size, interval=interval):
            if batch_logs:
                # Lưu vào file ngay khi nhận batch mới
                append_logs_to_file(batch_logs)

    except KeyboardInterrupt:
        logger.warning("\n⚠️ Dừng streaming bởi người dùng (Ctrl+C)")
        logger.info("👋 Hoàn tất! Logs đã được lưu liên tục.")
    except Exception as e:
        logger.error(f"❌ Lỗi nghiêm trọng trong streaming: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="🔍 Test ELK Client - Fetch & lưu pfSense firewall logs từ Elasticsearch"
    )

    parser.add_argument(
        "-n", "--number",
        type=int,
        default=500,
        help="Batch size cho các lần fetch sau initial batch. Mặc định: 500"
    )

    parser.add_argument(
        "-i", "--interval",
        type=int,
        default=20,
        help="Khoảng thời gian giữa các lần fetch (giây) khi stream. Mặc định: 20"
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--once",
        action="store_true",
        help="Chỉ fetch một lần (1000 logs mới nhất) và lưu file"
    )
    group.add_argument(
        "--stream",
        action="store_true",
        help="Chạy realtime streaming và liên tục append logs vào file"
    )

    args = parser.parse_args()

    print(f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 80)
    logger.info("🧪 BẮT ĐẦU TEST ELK CLIENT")
    print("═" * 80 + "\n")

    if args.stream:
        test_stream(batch_size=args.number, interval=args.interval)
    else:
        # Nếu có --once hoặc không có option nào → chạy chế độ once
        if args.once:
            test_once()
        else:
            # Mặc định vẫn là once để tương thích hành vi cũ
            test_once()


if __name__ == "__main__":
    main()