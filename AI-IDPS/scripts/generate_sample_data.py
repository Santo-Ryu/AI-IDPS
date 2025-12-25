"""
scripts/generate_sample_data.py
Generate Sample PFSense Logs Data - BATCH VERSION
Tạo 2 triệu logs qua 20 batch (mỗi batch 100K logs) để tránh tràn RAM
Đảm bảo đúng 100% cấu trúc logs từ ELK
"""

import os
import json
import random
import sys
import yaml
from datetime import datetime, timedelta
from pathlib import Path

# Import custom logger từ utils
sys.path.append(str(Path(__file__).parent.parent))
from src.utils.logger import get_module_logger


# ==================== LOAD CONFIG ====================
def load_config(config_path='config/config.yaml'):
    """Load configuration from YAML file"""
    try:
        if not os.path.exists(config_path):
            print(f"❌ Config file not found: {config_path}")
            print("⚠️  Using default configuration")
            return get_default_config()
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        print(f"✅ Loaded config from: {config_path}")
        return config
        
    except Exception as e:
        print(f"❌ Error loading config: {e}")
        print("⚠️  Using default configuration")
        return get_default_config()


def get_default_config():
    """Return default configuration"""
    return {
        'data': {
            'training_logs': 'data/raw/training.jsonl'
        }
    }


# ==================== CẤU HÌNH DỮ LIỆU MẪU ====================
class LogConfig:
    """Cấu hình các giá trị có thể có trong logs"""
    
    # Các IP nguồn bình thường (internal network)
    NORMAL_SRC_IPS = [
        # Subnet 192.168.0.x (default nhiều router)
        "192.168.0.10", "192.168.0.20", "192.168.0.50", "192.168.0.100",
        
        # Subnet 192.168.1.x (rất phổ biến)
        "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.50",
        "192.168.1.100", "192.168.1.150", "192.168.1.200",
        
        # Subnet 192.168.2.x (thường dùng cho guest WiFi hoặc secondary LAN)
        "192.168.2.15", "192.168.2.25", "192.168.2.35", "192.168.2.100",
        
        # Subnet 192.168.10.x (phổ biến cho IoT/smart home)
        "192.168.10.5", "192.168.10.15", "192.168.10.50",
        
        # Subnet 192.168.50.x (thường dùng cho VLAN riêng)
        "192.168.50.100", "192.168.50.150",
        
        # Subnet 192.168.100.x (thường dùng cho office/small biz)
        "192.168.100.20", "192.168.100.80",
        
        # Subnet 192.168.200.x (cho server/storage)
        "192.168.200.10", "192.168.200.50", "192.168.200.100",
        
        # Các subnet khác (để đa dạng hơn)
        "192.168.55.133", "192.168.81.134", "192.168.81.135",
        "192.168.81.140", "192.168.81.150", "192.168.81.160"
    ]
    
    # Các IP nguồn đáng ngờ (attacker)
    SUSPICIOUS_SRC_IPS = [
        # Private IPs không hợp lệ (theo RFC 1918)
        "10.0.0.100", "172.16.0.50",
        "203.113.77.25", "45.33.32.156", "185.220.101.18", "198.51.100.23",
        
        # Thêm IPs phổ biến tấn công (từ các nguồn thực tế như AbuseIPDB)
        "1.1.1.1", "8.8.8.8", "104.16.0.0", "172.67.0.0", "45.79.0.0",
        "104.244.0.0", "103.21.244.0", "103.21.245.255", "45.32.0.0",
        "45.33.0.0", "185.199.108.0", "185.199.109.0", "104.18.0.0",
        "104.19.0.0", "162.158.0.0", "172.64.0.0", "188.114.96.0",
        "188.114.97.0", "172.68.0.0", "45.79.1.0", "45.79.2.0",
        
        # Thêm random public IPs (có thể generate thêm)
        "89.35.0.0", "89.35.1.0", "91.149.0.0", "91.149.1.0",
        "185.220.100.0", "185.220.101.0", "198.51.100.0", "198.51.100.100",
        "203.0.113.0", "203.0.113.1", "233.252.0.0", "233.252.1.0",
    ]

    # Các IP đích (servers)
    DST_IPS = [
        "192.168.81.131", "192.168.81.132", "192.168.81.140",
        "192.168.81.200", "192.168.1.1", "192.168.1.254",
        "192.168.81.10", "192.168.81.20", "192.168.81.50", "192.168.81.100",
        "192.168.1.10", "192.168.1.50", "192.168.1.100", "192.168.1.150",
        "192.168.10.5", "192.168.10.10", "192.168.10.50", "192.168.10.100",
        "192.168.50.100", "192.168.50.200", "192.168.100.10", "192.168.100.50",
        "192.168.200.10", "192.168.200.50", "192.168.200.100",
        
        # Thêm cho IoT/smart home
        "192.168.81.200", "192.168.81.201", "192.168.81.202"
    ]

    # Các port thông thường
    COMMON_PORTS = [
        80, 443, 22, 21, 25, 53, 3306, 5432, 8080, 8443,
        445, 3389, 5900, 9200, 27017, 6379, 1433, 1521,
        110, 143, 465, 587, 993, 995, 1194, 1195, 500, 4500,
        67, 68, 123, 137, 138
    ]

    # Các port nhạy cảm 
    SENSITIVE_PORTS = [
        21, 22, 23, 3389, 445, 139, 1433, 3306,
        1433, 1521, 5432, 9200, 27017, 6379, 5900, 445, 139,
        23, 3389, 445, 139, 1433, 1521, 9200, 27017, 6379
    ]
    
    # Các port ngẫu nhiên (ephemeral ports)
    EPHEMERAL_PORT_RANGE = (49152, 65535)
    
    # Protocols
    PROTOCOLS = ["tcp", "udp", "icmp"]
    PROTO_IDS = {"tcp": "6", "udp": "17", "icmp": "1"}
    
    # TCP Flags
    TCP_FLAGS = ["S", "A", "SA", "F", "R", "P", "FPA", "RA"]
    
    # Actions
    ACTIONS = ["pass", "block"]
    
    # Interfaces
    INTERFACES = ["em0", "em1", "em2", "igb0"]
    
    # Reasons
    REASONS = ["match", "offset", "bad-offset", "fragment", "short"]
    
    # Hostnames
    HOSTNAMES = ["pfSense.home.arpa", "firewall.local", "gateway.lan"]
    
    # TCP Options
    TCP_OPTIONS = [
        "mss;sackOK;TS;nop;wscale",
        "mss;nop;wscale",
        "mss;sackOK;TS",
        "mss",
        ""
    ]


# ==================== GENERATOR CLASS ====================
class LogGenerator:
    """Class để generate logs data - ĐÚNG CẤU TRÚC 100%"""
    
    def __init__(self, logger, base_timestamp=None):
        self.logger = logger
        self.config = LogConfig()
        self.base_timestamp = base_timestamp or datetime.now()
        
    def generate_timestamp(self, offset_seconds=0):
        """Tạo timestamp với offset - Format: 2025-12-22T08:14:45.543Z"""
        ts = self.base_timestamp + timedelta(seconds=offset_seconds)
        return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    
    def generate_syslog_timestamp(self, offset_seconds=0):
        """Tạo timestamp cho syslog format - Format: 2025-12-22T15:14:45.543015+07:00"""
        ts = self.base_timestamp + timedelta(seconds=offset_seconds)
        return ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+07:00"
    
    def generate_normal_log(self, offset_seconds=0):
        """Tạo log bình thường (traffic hợp lệ)"""
        src_ip = random.choice(self.config.NORMAL_SRC_IPS)
        dst_ip = random.choice(self.config.DST_IPS)
        dst_port = random.choice(self.config.COMMON_PORTS)
        src_port = random.randint(*self.config.EPHEMERAL_PORT_RANGE)
        proto_name = random.choice(["tcp", "udp"])
        action = random.choices(["pass", "block"], weights=[90, 10])[0]  # 90% pass
        
        return self._create_log_entry(
            src_ip, dst_ip, src_port, dst_port, 
            proto_name, action, offset_seconds
        )
    
    def generate_port_scan_log(self, offset_seconds=0):
        """Tạo log giống port scan (nhiều kết nối đến nhiều port khác nhau)"""
        src_ip = random.choice(self.config.SUSPICIOUS_SRC_IPS)
        dst_ip = random.choice(self.config.DST_IPS)
        dst_port = random.randint(1, 65535)  # Random port
        src_port = random.randint(*self.config.EPHEMERAL_PORT_RANGE)
        
        return self._create_log_entry(
            src_ip, dst_ip, src_port, dst_port,
            "tcp", "block", offset_seconds,
            tcp_flags="S"  # SYN scan
        )
    
    def generate_ddos_log(self, offset_seconds=0):
        """Tạo log giống DDoS (nhiều requests từ cùng IP)"""
        src_ip = random.choice(self.config.SUSPICIOUS_SRC_IPS)
        dst_ip = random.choice(self.config.DST_IPS)
        dst_port = random.choice([80, 443])  # Web services
        src_port = random.randint(*self.config.EPHEMERAL_PORT_RANGE)
        
        return self._create_log_entry(
            src_ip, dst_ip, src_port, dst_port,
            "tcp", "block", offset_seconds,
            tcp_flags=random.choice(["S", "A", "F"])
        )
    
    def generate_bruteforce_log(self, offset_seconds=0):
        """Tạo log giống brute force (nhiều attempts đến sensitive port)"""
        src_ip = random.choice(self.config.SUSPICIOUS_SRC_IPS)
        dst_ip = random.choice(self.config.DST_IPS)
        dst_port = random.choice(self.config.SENSITIVE_PORTS)
        src_port = random.randint(*self.config.EPHEMERAL_PORT_RANGE)
        
        return self._create_log_entry(
            src_ip, dst_ip, src_port, dst_port,
            "tcp", "block", offset_seconds,
            tcp_flags="S"
        )
    
    def _create_log_entry(self, src_ip, dst_ip, src_port, dst_port, 
                          proto_name, action, offset_seconds, 
                          tcp_flags=None):
        """
        Tạo một log entry hoàn chỉnh - ĐÚNG 100% CẤU TRÚC LOGS MẪU
        Dựa trên format từ ELK và pfSense filterlog documentation
        """
        
        timestamp = self.generate_timestamp(offset_seconds)
        syslog_ts = self.generate_syslog_timestamp(offset_seconds)
        proto_id = self.config.PROTO_IDS.get(proto_name, "6")
        
        # Random values giống logs thật
        rule_number = random.randint(1, 20)
        tracker = random.randint(1000000000, 1000001000)
        interface = random.choice(self.config.INTERFACES)
        hostname = random.choice(self.config.HOSTNAMES)
        pid = str(random.randint(10000, 99999))
        packet_id = random.randint(1000, 65535)
        ttl = str(random.choice([64, 128, 255]))
        
        # TCP specific
        if proto_name == "tcp":
            if tcp_flags is None:
                tcp_flags = random.choice(self.config.TCP_FLAGS)
            sequence = str(random.randint(1000000000, 4294967295))
            window = str(random.choice([64240, 65535, 8192, 29200]))
            options = random.choice(self.config.TCP_OPTIONS)
        else:
            tcp_flags = ""
            sequence = ""
            window = ""
            options = ""
        
        # Tạo original syslog message ĐÚNG FORMAT pfSense
        original_msg = (
            f"<134>1 {syslog_ts} {hostname} filterlog {pid} - - "
            f"{rule_number},,,{tracker},{interface},match,{action},in,4,0x0,,{ttl},"
            f"{packet_id},0,DF,{proto_id},{proto_name},60,{src_ip},{dst_ip},"
            f"{src_port},{dst_port},0,{tcp_flags},{sequence},,{window},,{options}"
        )
        
        # Tạo log entry ĐÚNG 100% cấu trúc mẫu từ ELK
        log_entry = {
            "@timestamp": [timestamp],
            "@version": ["1"],
            "@version.keyword": ["1"],
            "action": [action],
            "action.keyword": [action],
            "data_length": ["0"],
            "data_length.keyword": ["0"],
            "dir": ["in"],
            "dir.keyword": ["in"],
            "dst_ip": [dst_ip],
            "dst_ip.keyword": [dst_ip],
            "dst_port": dst_port,
            "event.original": [original_msg],
            "event.original.keyword": [original_msg],
            "flags": ["DF"],
            "flags.keyword": ["DF"],
            "host.ip": ["10.0.1.1"],
            "host.ip.keyword": ["10.0.1.1"],
            "hostname": [hostname],
            "hostname.keyword": [hostname],
            "id": [packet_id],
            "ip_version": ["4"],
            "ip_version.keyword": ["4"],
            "length": [60],
            "offset": ["0"],
            "offset.keyword": ["0"],
            "pid": [pid],
            "pid.keyword": [pid],
            "program": ["filterlog"],
            "program.keyword": ["filterlog"],
            "proto_id": [proto_id],
            "proto_id.keyword": [proto_id],
            "proto_name": [proto_name],
            "proto_name.keyword": [proto_name],
            "real_interface": [interface],
            "real_interface.keyword": [interface],
            "reason": ["match"],
            "reason.keyword": ["match"],
            "rule_number": [rule_number],
            "src_ip": [src_ip],
            "src_ip.keyword": [src_ip],
            "src_port": src_port,
            "tos": ["0x0"],
            "tos.keyword": ["0x0"],
            "tracker": [tracker],
            "ttl": [ttl],
            "ttl.keyword": [ttl],
            "type": ["pfsense"],
            "type.keyword": ["pfsense"],
            "_id": f"S1IgRZsBEZdhVUgoB{random.randint(1000, 9999)}",
            "_index": f"pfsense-ipv4-{timestamp[:10].replace('-', '.')}",
            "_score": None
        }
        
        # Chỉ thêm TCP-specific fields NẾU là TCP protocol
        if proto_name == "tcp":
            log_entry["tcp_flags"] = [tcp_flags]
            log_entry["tcp_flags.keyword"] = [tcp_flags]
            log_entry["sequence_number"] = [sequence]
            log_entry["sequence_number.keyword"] = [sequence]
            log_entry["window"] = [window]
            log_entry["window.keyword"] = [window]
            log_entry["options"] = [options]
            log_entry["options.keyword"] = [options]
        
        return log_entry
    
    def generate_batch(self, 
                      batch_size=100000,
                      normal_ratio=0.85,
                      port_scan_ratio=0.05,
                      ddos_ratio=0.05,
                      bruteforce_ratio=0.05,
                      time_offset_start=0):
        """
        Generate một batch logs
        
        Args:
            batch_size: Số logs trong batch này
            normal_ratio: Tỉ lệ logs bình thường
            port_scan_ratio: Tỉ lệ logs port scan
            ddos_ratio: Tỉ lệ logs DDoS
            bruteforce_ratio: Tỉ lệ logs brute force
            time_offset_start: Offset thời gian bắt đầu (giây)
            
        Returns:
            Generator yielding log entries
        """
        
        # Tính số lượng từng loại
        num_normal = int(batch_size * normal_ratio)
        num_port_scan = int(batch_size * port_scan_ratio)
        num_ddos = int(batch_size * ddos_ratio)
        num_bruteforce = int(batch_size * bruteforce_ratio)
        
        time_offset = time_offset_start
        all_logs = []
        
        # Generate normal logs
        for _ in range(num_normal):
            all_logs.append(self.generate_normal_log(time_offset))
            time_offset += random.randint(1, 5)
        
        # Generate port scan logs
        for _ in range(num_port_scan):
            all_logs.append(self.generate_port_scan_log(time_offset))
            time_offset += random.randint(0, 1)
        
        # Generate DDoS logs
        for _ in range(num_ddos):
            all_logs.append(self.generate_ddos_log(time_offset))
            time_offset += random.randint(0, 1)
        
        # Generate brute force logs
        for _ in range(num_bruteforce):
            all_logs.append(self.generate_bruteforce_log(time_offset))
            time_offset += random.randint(1, 3)
        
        # Shuffle để random hóa
        random.shuffle(all_logs)
        
        # Return last time offset for next batch
        return all_logs, time_offset
    
    
def print_progress_bar(batch_num, total_batches, total_written, total_logs, start_time, bar_length=40):
    """
    In progress bar mượt mà trên cùng một dòng với thông tin chi tiết:
    - Thanh bar
    - Phần trăm
    - Số log đã ghi
    - Thời gian đã chạy
    - ETA (ước lượng thời gian còn lại)
    """
    progress_percent = (batch_num / total_batches) * 100
    filled_length = int(bar_length * batch_num / total_batches)
    bar = "█" * filled_length + "░" * (bar_length - filled_length)

    # Thời gian đã chạy
    elapsed_time = datetime.now() - start_time
    elapsed_secs = int(elapsed_time.total_seconds())
    mins, secs = divmod(elapsed_secs, 60)
    hours, mins = divmod(mins, 60)
    if hours:
        time_str = f"{hours:02d}h {mins:02d}m {secs:02d}s"
    elif mins:
        time_str = f"{mins:02d}m {secs:02d}s"
    else:
        time_str = f"{secs:02d}s"

    # Ước lượng ETA
    if batch_num > 0:
        avg_time_per_batch = elapsed_time.total_seconds() / batch_num
        remaining_batches = total_batches - batch_num
        eta_secs_total = int(remaining_batches * avg_time_per_batch)
        eta_mins, eta_secs = divmod(eta_secs_total, 60)
        eta_str = f"{eta_mins}m {eta_secs:02d}s" if eta_mins else f"{eta_secs:02d}s"
    else:
        eta_str = "--"

    # In trên cùng một dòng
    print(f"\r📦 Generating: [{bar}] {progress_percent:6.1f}% | "
        f"{total_written:7,}/{total_logs:,} logs | "
        f"⏱ {time_str} | ETA: {eta_str} ", end="", flush=True)


# ==================== MAIN FUNCTION ====================
def main():
    """Hàm chính để generate 2 triệu logs qua 20 batch"""

    # Setup logger
    logger = get_module_logger("DataGenerator")
    
    config = load_config('config/config.yaml')
    
    logger.info("=" * 80)
    logger.info("🚀 PFSense Log Generator - LARGE DATASET (2M logs)")
    logger.info("=" * 80)
    
    # Cấu hình
    TOTAL_BATCHES = 50
    LOGS_PER_BATCH = 10000
    TOTAL_LOGS = TOTAL_BATCHES * LOGS_PER_BATCH
    NORMAL_RATIO=0.93
    PORT_SCAN_RATIO=0.03
    DDOS_RATIO=0.02
    BRUTEFORCE_RATIO=0.02
    
    logger.info(f"📊 Cấu hình:")
    logger.info(f"  • Tổng số logs: {TOTAL_LOGS:,}")
    logger.info(f"  • Số lần tạo: {TOTAL_BATCHES}")
    logger.info(f"  • Số logs mỗi lần tạo: {LOGS_PER_BATCH:,}")
    logger.info(f"  • Phân bố: {NORMAL_RATIO*100}% normal, {100 - NORMAL_RATIO*100}% anomaly")
    
    # Khởi tạo generator
    generator = LogGenerator(logger)
    
    # Lấy đường dẫn file output
    output_path = Path(config.get('data', {}).get('training_logs', 'data/raw/training.jsonl'))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"💾 Output file: {output_path}")
    
    # Mở file để ghi (mode 'w' để overwrite nếu đã tồn tại)
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            time_offset = 0
            total_written = 0
            start_time = datetime.now()  # Thời gian bắt đầu

            for batch_num in range(1, TOTAL_BATCHES + 1):
                # Generate batch
                # Tổng anomaly = 7%
                batch_logs, time_offset = generator.generate_batch(
                    batch_size=LOGS_PER_BATCH,
                    normal_ratio=NORMAL_RATIO,
                    port_scan_ratio=PORT_SCAN_RATIO,
                    ddos_ratio=DDOS_RATIO,
                    bruteforce_ratio=BRUTEFORCE_RATIO,
                    time_offset_start=time_offset
                )

                # Ghi vào file
                for log_entry in batch_logs:
                    json.dump(log_entry, f, ensure_ascii=False)
                    f.write('\n')
                    total_written += 1

                # Cập nhật progress bar (chỉ gọi hàm)
                print_progress_bar(
                    batch_num=batch_num,
                    total_batches=TOTAL_BATCHES,
                    total_written=total_written,
                    total_logs=TOTAL_LOGS,
                    start_time=start_time
                )

                # Giải phóng bộ nhớ
                del batch_logs

            # Khi hoàn thành: in dòng cuối đẹp và xuống dòng
            final_elapsed = datetime.now() - start_time
            mins, secs = divmod(int(final_elapsed.total_seconds()), 60)
            hours, mins = divmod(mins, 60)
            final_time_str = f"{hours:02d}h {mins:02d}m {secs:02d}s" if hours else f"{mins:02d}m {secs:02d}s" if mins else f"{secs:02d}s"

            print("\r" + " " * 120 + "\r", end="")  # Xóa dòng progress cũ
            print(f"✅ Hoàn thành: [{'█' * 40}] 100.0% | "
                  f"{total_written:,}/{TOTAL_LOGS:,} logs | "
                  f"⏱ {final_time_str} | Xong! 🎉")
        
        # Thống kê file
        file_size_mb = os.path.getsize(output_path) / (1024*1024)
        
        logger.info("\n" + "="*80)
        logger.success("🎉 HOÀN THÀNH!")
        logger.info("="*80)
        logger.success(f"✅ Đã generate {total_written:,} logs")
        logger.success(f"💾 File: {output_path}")
        logger.success(f"📊 Size: {file_size_mb:.2f} MB")
        logger.info("="*80)
        
        # Hướng dẫn sử dụng
        logger.info("💡 HƯỚNG DẪN SỬ DỤNG:")
        logger.info(f"1. Dataset có {NORMAL_RATIO*100}% normal logs, {100 - NORMAL_RATIO*100}% anomaly")
        logger.info("2. Khi train Isolation Forest:")
        logger.info("   - Set contamination=0.07")
        logger.info("   - Khuyến nghị: n_estimators=200, max_samples=256")
        logger.info("3. File format: JSON Lines (.json), mỗi dòng là một JSON log entry")
        logger.info("4. Để train model, chạy:")
        logger.info("   python scripts/train_model.py")
        logger.info("="*80)
        
    except Exception as e:
        logger.error(f"❌ Lỗi khi generate dataset: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return


if __name__ == '__main__':
    main()
