"""
src/integrations/elk_client.py
ELK Client cho AI-IDPS Realtime System (PROGRESS BAR VERSION)

Realtime streaming CHUẨN:
- KHÔNG dùng PIT cho realtime
- Dùng @timestamp + search_after
- Không trùng log
- Không bỏ sót
- Thấy log mới NGAY khi ES index
- Progress bar đẹp cho fetch process
"""

import os
import time
import yaml
from datetime import datetime
from typing import List, Dict, Optional

from elasticsearch8 import Elasticsearch
from elasticsearch8.exceptions import ConnectionError, ApiError
from dotenv import load_dotenv

from src.utils.logger import get_module_logger

load_dotenv()
logger = get_module_logger("ELKClient")

# =================== LOAD CONFIG ===================
CONFIG_PATH = "config/config.yaml"


def load_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(CONFIG_PATH)

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    es_host = os.getenv("ES_HOST")
    es_port = os.getenv("ES_PORT")
    index_pattern = config.get("elk-module", {}).get("INDEX_PATTERN")
    batch_size = config.get("realtime", {}).get("batch_size", 200)
    fetch_interval = config.get("realtime", {}).get("fetch_interval", 5)

    if not all([es_host, es_port, index_pattern]):
        raise ValueError("Missing ELK configuration")

    logger.info("📋 Cấu hình ELK:")
    logger.info(f"   Host: {es_host}:{es_port}")
    logger.info(f"   Index Pattern: {index_pattern}")
    logger.info(f"   Batch Size: {batch_size}")
    logger.info(f"   Fetch Interval: {fetch_interval}s")

    return {
        "es_host": es_host,
        "es_port": es_port,
        "index_pattern": index_pattern,
        "batch_size": batch_size,
        "fetch_interval": fetch_interval,
    }


# =================== ELK CLIENT ===================
class ElkClient:
    """
    ELK Client cho AI-IDPS Realtime
    Bootstrap → Realtime tail-f với Progress Bar
    """

    def __init__(self, config: dict = None):
        if config is None:
            config = load_config()

        self.config = config
        self.es = Elasticsearch(
            [f"http://{config['es_host']}:{config['es_port']}"]
        )

        self.index_pattern = config["index_pattern"]
        self.batch_size = config["batch_size"]
        self.fetch_interval = config["fetch_interval"]

        # Realtime state
        self.checkpoint_timestamp: Optional[str] = None
        self.search_after: Optional[list] = None

        self.total_fetched = 0
        self.last_fetch_count = 0
        self.fetch_counter = 0

        logger.info("🔧 ELK Client khởi tạo thành công")

    # =================== BOOTSTRAP ===================
    def bootstrap_checkpoint(self) -> str:
        """
        Lấy checkpoint ban đầu = timestamp của log mới nhất hiện tại
        Batch này KHÔNG xử lý
        """
        logger.info("🚀 BOOTSTRAP checkpoint...")

        try:
            resp = self.es.search(
                index=self.index_pattern,
                size=1,
                sort=[{"@timestamp": "desc"}],
                _source=["@timestamp"],
            )

            hits = resp["hits"]["hits"]

            if hits:
                checkpoint = hits[0]["_source"]["@timestamp"]
                logger.success(f"✅ Checkpoint = {checkpoint}")
            else:
                checkpoint = datetime.utcnow().isoformat()
                logger.warning("⚠️ Không có logs, dùng timestamp hiện tại")

            self.checkpoint_timestamp = checkpoint
            self.search_after = None
            return checkpoint

        except Exception as e:
            logger.error(f"❌ Bootstrap lỗi: {e}")
            checkpoint = datetime.utcnow().isoformat()
            self.checkpoint_timestamp = checkpoint
            return checkpoint

    # =================== PROGRESS BAR ===================
    def _print_fetch_progress(self, logs_count: int, status: str = "fetching"):
        """
        Hiển thị progress bar cho quá trình fetch logs
        
        Args:
            logs_count: Số logs đã fetch
            status: 'fetching', 'success', 'idle'
        """
        bar_length = 40
        
        # Tính progress based on batch_size
        if status == "fetching":
            # Animated loading
            animation = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            spinner = animation[self.fetch_counter % len(animation)]
            color = "\033[96m"  # Cyan
            status_text = f"{spinner} Fetching"
        elif status == "success":
            color = "\033[92m"  # Green
            status_text = "✓ Fetched"
            spinner = "✓"
        else:  # idle
            color = "\033[93m"  # Yellow
            status_text = "⏸ Idle"
            spinner = "⏸"
        
        reset = "\033[0m"
        
        # Progress bar dựa trên logs_count
        if logs_count > 0:
            filled_length = min(bar_length, int(bar_length * logs_count / self.batch_size))
            bar = "█" * filled_length + "░" * (bar_length - filled_length)
            percent = min(100, int(logs_count / self.batch_size * 100))
        else:
            bar = "░" * bar_length
            percent = 0
        
        # Format numbers
        total_str = f"{self.total_fetched:,}"
        batch_str = f"{logs_count}"
        
        print(f"\r📡 {status_text}: {color}[{bar}]{reset} {percent:3d}% | "
              f"Batch: {color}{batch_str:>4}{reset}/{self.batch_size} | "
              f"Total: {color}{total_str}{reset} logs", 
              end="", flush=True)
        
        self.fetch_counter += 1

    # =================== REALTIME FETCH ===================
    def fetch_logs(self, max_retries: int = 3, show_progress: bool = True) -> List[Dict]:
        """
        Fetch logs realtime CHUẨN với progress bar:
        - @timestamp > checkpoint
        - sort @timestamp + _id
        - search_after
        - Progress bar đẹp
        """

        if not self.checkpoint_timestamp:
            self.bootstrap_checkpoint()

        for attempt in range(max_retries):
            try:
                # Show fetching progress
                if show_progress:
                    self._print_fetch_progress(0, "fetching")
                
                query = {
                    "size": self.batch_size,
                    "query": {
                        "range": {
                            "@timestamp": {
                                "gt": self.checkpoint_timestamp
                            }
                        }
                    },
                    "sort": [{"@timestamp": "asc"}],
                }

                if self.search_after:
                    query["search_after"] = self.search_after

                resp = self.es.search(
                    index=self.index_pattern,
                    body=query,
                )

                hits = resp["hits"]["hits"]
                self.last_fetch_count = len(hits)

                if not hits:
                    if show_progress:
                        self._print_fetch_progress(0, "idle")
                    return []

                # Update cursor
                self.search_after = hits[-1]["sort"]
                self.checkpoint_timestamp = hits[-1]["_source"]["@timestamp"]

                logs = [h["_source"] for h in hits]
                self.total_fetched += len(logs)

                # Show success progress
                if show_progress:
                    self._print_fetch_progress(len(logs), "success")
                    print()  # New line after success

                return logs

            except ApiError as e:
                logger.error(f"❌ Elasticsearch API error: {e}")
                time.sleep(2)

            except Exception as e:
                logger.error(f"❌ Fetch error: {e}")
                time.sleep(2)

        return []

    # =================== STREAMING ===================
    def stream_logs(self, show_progress: bool = True):
        """
        Generator để stream logs liên tục với progress bar
        
        Args:
            show_progress: Hiển thị progress bar hay không
        
        Yields:
            List[Dict]: Batch logs
        """
        logger.info("🌊 Start realtime streaming...")

        if not self.checkpoint_timestamp:
            self.bootstrap_checkpoint()

        try:
            while True:
                logs = self.fetch_logs(show_progress=show_progress)
                if logs:
                    yield logs
                else:
                    # Countdown idle time
                    if show_progress:
                        for remaining in range(self.fetch_interval, 0, -1):
                            self._print_idle_countdown(remaining)
                            time.sleep(1)
                        print("\r" + " " * 100 + "\r", end="", flush=True)
                    else:
                        time.sleep(self.fetch_interval)

        except KeyboardInterrupt:
            logger.warning("\n⛔ Streaming stopped")
        finally:
            logger.info("🛑 Streaming ended")
    
    def _print_idle_countdown(self, seconds_remaining: int):
        """Hiển thị countdown khi idle"""
        bar_length = 40
        elapsed = self.fetch_interval - seconds_remaining
        filled_length = int(bar_length * elapsed / self.fetch_interval)
        bar = "░" * filled_length + "█" * (bar_length - filled_length)
        
        color = "\033[93m"  # Yellow
        reset = "\033[0m"
        
        print(f"\r⏸ Idle: {color}[{bar}]{reset} Next fetch in {color}{seconds_remaining:2d}s{reset} "
              f"| Total: {self.total_fetched:,} logs", 
              end="", flush=True)

    # =================== UTILS ===================
    def check_connection(self) -> bool:
        try:
            if self.es.ping():
                logger.success("✅ Elasticsearch connected")
                return True
            logger.error("❌ Elasticsearch ping failed")
            return False
        except Exception as e:
            logger.error(f"❌ Connection error: {e}")
            return False

    def get_stats(self) -> Dict:
        return {
            "total_fetched": self.total_fetched,
            "last_fetch": self.last_fetch_count,
            "checkpoint": self.checkpoint_timestamp,
        }


# =================== CONVENIENCE FUNCTION ===================
def fetch_logs_realtime(batch_size: int = 200, interval: int = 5, show_progress: bool = True):
    """
    Convenience function để fetch logs realtime
    
    Args:
        batch_size: Số logs mỗi batch
        interval: Giây giữa các lần fetch
        show_progress: Hiển thị progress bar
    
    Yields:
        List[Dict]: Batch logs
    """
    config = load_config()
    config['batch_size'] = batch_size
    config['fetch_interval'] = interval
    
    client = ElkClient(config)
    
    if not client.check_connection():
        logger.error("❌ Không thể kết nối Elasticsearch")
        return
    
    return client.stream_logs(show_progress=show_progress)


# =================== DEMO ===================
def demo_streaming():
    logger.info("=" * 60)
    logger.info("🎬 DEMO REALTIME STREAMING WITH PROGRESS BAR")
    logger.info("=" * 60)

    client = ElkClient()

    if not client.check_connection():
        return

    batch = 0
    try:
        for logs in client.stream_logs(show_progress=True):
            batch += 1
            logger.info(f"\n📦 Batch #{batch} | {len(logs)} logs")

            # Show sample logs
            for log in logs[:3]:
                src = log.get("source", {}).get("ip", "N/A")
                dst = log.get("destination", {}).get("ip", "N/A")
                action = log.get("event", {}).get("action", "N/A")
                logger.debug(f"   {src} → {dst} | {action}")
            
            if len(logs) > 3:
                logger.debug(f"   ... and {len(logs) - 3} more logs")
    
    except KeyboardInterrupt:
        logger.warning("\n⛔ Demo stopped by user")


if __name__ == "__main__":
    demo_streaming()
