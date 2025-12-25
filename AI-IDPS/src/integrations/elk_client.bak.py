"""
src/integrations/elk_client.py
ELK Client cho AI-IDPS Realtime System (FIXED VERSION)

Realtime streaming CHUẨN:
- KHÔNG dùng PIT cho realtime
- Dùng @timestamp + search_after
- Không trùng log
- Không bỏ sót
- Thấy log mới NGAY khi ES index
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
    Bootstrap → Realtime tail-f
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

    # =================== REALTIME FETCH ===================
    def fetch_logs(self, max_retries: int = 3) -> List[Dict]:
        """
        Fetch logs realtime CHUẨN:
        - @timestamp > checkpoint
        - sort @timestamp + _id
        - search_after
        """

        if not self.checkpoint_timestamp:
            self.bootstrap_checkpoint()

        logger.info("📡 Fetching realtime logs...")

        for attempt in range(max_retries):
            try:
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
                    logger.debug("📭 Không có logs mới")
                    return []
                
                # 👉 CHECK TIMESTAMP LOGS CUỐI CÙNG CỦA TỪNG BATCH LOGS
                # last_log_ts = hits[-1]["_source"].get("@timestamp")
                # logger.info(
                #     f"🕒 Last log timestamp (batch tail): {last_log_ts}"
                # )

                # Update cursor
                self.search_after = hits[-1]["sort"]
                self.checkpoint_timestamp = hits[-1]["_source"]["@timestamp"]

                logs = [h["_source"] for h in hits]
                self.total_fetched += len(logs)

                logger.success(
                    f"📦 Fetched {len(logs)} logs | Total {self.total_fetched}"
                )

                return logs

            except ApiError as e:
                logger.error(f"❌ Elasticsearch API error: {e}")
                time.sleep(2)

            except Exception as e:
                logger.error(f"❌ Fetch error: {e}")
                time.sleep(2)

        return []

    # =================== STREAMING ===================
    def stream_logs(self):
        logger.info("🌊 Start realtime streaming...")

        if not self.checkpoint_timestamp:
            self.bootstrap_checkpoint()

        try:
            while True:
                logs = self.fetch_logs()
                if logs:
                    yield logs
                else:
                    time.sleep(self.fetch_interval)

        except KeyboardInterrupt:
            logger.warning("⛔ Streaming stopped")
        finally:
            logger.info("🛑 Streaming ended")

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


# =================== DEMO ===================
def demo_streaming():
    logger.info("=" * 60)
    logger.info("🎬 DEMO REALTIME STREAMING")
    logger.info("=" * 60)

    client = ElkClient()

    if not client.check_connection():
        return

    batch = 0
    for logs in client.stream_logs():
        batch += 1
        logger.info(f"📦 Batch #{batch} | {len(logs)} logs")

        for log in logs[:3]:
            src = log.get("source", {}).get("ip", "N/A")
            dst = log.get("destination", {}).get("ip", "N/A")
            action = log.get("event", {}).get("action", "N/A")
            logger.debug(f"   {src} → {dst} | {action}")


if __name__ == "__main__":
    demo_streaming()
