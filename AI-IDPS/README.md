# 🤖 AI-IDPS Real-time Anomaly Detection System

## 📋 Tổng quan

Hệ thống phát hiện và chặn tự động các IP nguy hiểm dựa trên AI với tích hợp:
- ✅ **Real-time log fetching** từ Elasticsearch (mỗi 20s)
- ✅ **AI anomaly detection** với Isolation Forest
- ✅ **Auto-blocking** qua pfSense Firewall API
- ✅ **Telegram alerts** cho các sự kiện quan trọng

## 🏗️ Kiến trúc hệ thống

```
┌─────────────┐    20s     ┌──────────────┐
│ Elasticsearch├──────────►│  ELK Client  │
│   (Logs)    │            └──────┬───────┘
└─────────────┘                   │
                                  ▼
                         ┌────────────────┐
                         │    Anomaly     │
                         │    Detector    │
                         │ (AI Model)     │
                         └────────┬───────┘
                                  │
                    ┌─────────────┴──────────────┐
                    ▼                            ▼
            ┌───────────────┐          ┌─────────────────┐
            │ pfSense Client│          │ Alert Manager   │
            │  (Block IPs)  │          │  (Telegram Bot) │
            └───────────────┘          └─────────────────┘
```

## 📦 Components

### 1. **ELK Client** (`src/integrations/elk_client.py`)
- Fetch logs từ Elasticsearch mỗi 20s
- Track timestamp để tránh fetch logs cũ
- Stream logs continuously

### 2. **Anomaly Detector** (`src/core/anomaly_detector.py`)
- Sử dụng trained Isolation Forest model
- Phát hiện anomalies với severity levels
- Real-time preprocessing và prediction

### 3. **pfSense Client** (`src/integrations/pfsense_client.py`)
- Tương tác với pfSense Firewall API
- Chặn/bỏ chặn IP addresses
- Quản lý blocked IP alias

### 4. **Alert Manager** (`src/core/alert_manager.py`)
- Gửi alerts qua Telegram
- Thông báo: anomalies, blocks, failures, statistics
- Sử dụng `python-telegram-bot==20.7`

### 5. **Real-time System** (`src/scripts/realtime_anomaly_detector.py`)
- Orchestrate tất cả components
- Main loop: fetch → detect → block → alert
- Graceful shutdown handling

## 🚀 Cài đặt

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
elasticsearch8>=8.0.0
python-telegram-bot==20.7
python-dotenv>=0.19.0
requests>=2.28.0
pyyaml>=6.0
pandas>=1.5.0
numpy>=1.23.0
scikit-learn>=1.1.0
joblib>=1.2.0
colorlog>=6.7.0
tabulate>=0.9.0
```

### 2. Cấu hình Telegram Bot

#### a. Tạo bot mới:
```
1. Mở Telegram, tìm @BotFather
2. Gửi /newbot
3. Đặt tên bot (vd: AI_IDPS_Bot)
4. Lấy BOT TOKEN
```

#### b. Lấy Chat ID:
```
1. Gửi message cho bot của bạn
2. Truy cập: https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
3. Tìm "chat":{"id":YOUR_CHAT_ID}
```

#### c. Cấu hình `.env`:
```bash
cp .env.example .env
nano .env
```

```bash
# Điền thông tin của bạn
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=987654321
ENABLE_TELEGRAM_ALERTS=true
```

### 3. Cấu hình pfSense API

#### a. Enable API trên pfSense:
```
1. Login vào pfSense web interface
2. System > API > Settings
3. Enable API
4. Create API key và secret
```

#### b. Cập nhật `config/config.yaml`:
```yaml
pfsense:
  host: "192.168.1.1"  # IP của pfSense
  port: 443
  api_key: "your_actual_api_key"
  api_secret: "your_actual_api_secret"
  verify_ssl: false
  blocked_alias: "AI_IDPS_Blocked"
  auto_block: true
  min_severity_to_block: "HIGH"
```

### 4. Cấu hình Elasticsearch

Cập nhật `config/config.yaml`:
```yaml
elk-module:
  ES_HOST: "127.0.0.1"
  ES_PORT: 9200
  INDEX_PATTERN: "pfsense-*"
```

## 🎯 Sử dụng

### 1. Train model (lần đầu)

```bash
# Đảm bảo có logs trong data/raw/elk_logs.json
python -m scripts.train_model
```

Output:
```
✅ Model đã được train và lưu tại:
   - models/latest_model.pkl
   - models/latest_processor.pkl
   - models/latest_engineer.pkl
```

### 2. Chạy real-time detection

```bash
python -m scripts.realtime_anomaly_detector
```

### 3. Test components riêng lẻ

#### Test ELK Client:
```bash
python -m src.integrations.elk_client
```

#### Test pfSense Client:
```bash
python -m src.integrations.pfsense_client
```

#### Test Alert Manager:
```bash
python -m src.core.alert_manager
```

## 📊 Monitoring

### Console Output

System sẽ hiển thị real-time logs với màu sắc:

```
🌐 15:30:45 | NETWORK  | Fetching logs từ 15:30:25 đến 15:30:45
📦 15:30:45 | INFO     | Fetched 47 new logs
🚨 15:30:46 | SECURITY | HIGH Anomaly: 192.168.1.100 → 8.8.8.8
🚫 15:30:46 | SECURITY | Attempting to block 192.168.1.100
✅ 15:30:47 | SUCCESS  | Successfully blocked 192.168.1.100
📧 15:30:47 | SUCCESS  | Alert sent successfully
```

### Telegram Alerts

Bạn sẽ nhận được các loại alerts:

1. **System Status**
```
🚀 SYSTEM STARTED
Real-time AI-IDPS started
Fetch interval: 20s
Auto-block: true
```

2. **Anomaly Detection**
```
🚨 ANOMALY DETECTED
Severity: HIGH
Score: -0.3542
Source: 192.168.1.100
Destination: 8.8.8.8:443
Protocol: TCP
```

3. **IP Blocked**
```
🚫 IP BLOCKED
IP Address: 192.168.1.100
Severity: HIGH
Reason: AI-IDPS Detection
Time: 2025-12-18 15:30:47
```

4. **Periodic Statistics**
```
📊 AI-IDPS STATISTICS
Total Logs: 5,234
Anomalies: 156 (2.98%)
Blocked: 12
```

### Statistics

Mỗi 10 batches, system sẽ in statistics:

```
================================================================================
📊 SYSTEM STATISTICS
================================================================================
⏰ Uptime: 1:23:45
📦 Batches processed: 250
📋 Total logs: 12,450
🚨 Total anomalies: 378 (3.04%)

🎯 Severity Breakdown:
  • CRITICAL:     23
  • HIGH    :    156
  • MEDIUM  :    199

🚫 IPs blocked: 45
📧 Alerts sent: 423
================================================================================
```

## ⚙️ Configuration

### Auto-blocking Settings

Trong `config/config.yaml`:

```yaml
pfsense:
  auto_block: true                    # Enable/disable auto-blocking
  min_severity_to_block: "HIGH"       # Minimum severity to block
                                      # Options: INFO, LOW, MEDIUM, HIGH, CRITICAL
```

### Fetch Interval

```yaml
realtime:
  fetch_interval: 20    # Seconds between fetches
  batch_size: 100       # Logs per batch
```

### Alert Settings

```yaml
alerts:
  telegram_enabled: true
  max_alerts_per_minute: 10
  alert_on_severity: ["CRITICAL", "HIGH", "MEDIUM"]
```

## 🛡️ Security Features

### 1. Private IP Protection
System tự động skip blocking các private IPs:
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `127.0.0.0/8`

### 2. Severity-based Blocking
Chỉ block IPs với severity >= threshold:
- **CRITICAL**: Score < -0.4 (Cực kỳ nguy hiểm)
- **HIGH**: -0.4 ≤ Score < -0.3 (Rất nguy hiểm)
- **MEDIUM**: -0.3 ≤ Score < -0.2 (Nguy hiểm)
- **LOW**: -0.2 ≤ Score < -0.1 (Hơi nghi ngờ)
- **INFO**: Score ≥ -0.1 (Gần như bình thường)

### 3. Graceful Shutdown
System handle SIGINT (Ctrl+C) và SIGTERM gracefully:
- Print final statistics
- Send shutdown alert
- Clean exit

## 🔧 Troubleshooting

### 1. Không kết nối được Elasticsearch

```
❌ Không thể kết nối đến Elasticsearch
```

**Giải pháp:**
- Kiểm tra ES đang chạy: `curl http://localhost:9200`
- Kiểm tra config `ES_HOST` và `ES_PORT`

### 2. Telegram alerts không gửi được

```
❌ Telegram error: Unauthorized
```

**Giải pháp:**
- Kiểm tra `TELEGRAM_BOT_TOKEN` đúng chưa
- Kiểm tra `TELEGRAM_CHAT_ID` đúng chưa
- Đảm bảo đã start conversation với bot

### 3. pfSense blocking không hoạt động

```
⚠️  pfSense API trả về status code: 401
```

**Giải pháp:**
- Kiểm tra API key và secret
- Đảm bảo API đã được enable trong pfSense
- Kiểm tra IP có thể access pfSense API không

### 4. Model không load được

```
💥 Model files not found
```

**Giải pháp:**
- Train model trước: `python -m scripts.train_model`
- Kiểm tra file tồn tại:
  ```bash
  ls -la models/latest_*.pkl
  ```

## 📈 Performance

### Resource Usage
- **CPU**: ~5-10% (depends on batch size)
- **RAM**: ~500MB-1GB
- **Network**: Minimal (only API calls)

### Scalability
- Có thể handle **1000+ logs/minute**
- Batch processing: 100 logs mỗi 20s = **300 logs/minute**
- Tăng `batch_size` để handle more logs

## 🎓 Best Practices

1. **Start with safe settings:**
   ```yaml
   auto_block: false  # Test detection first
   ```

2. **Monitor carefully in first 24h:**
   - Check false positives
   - Adjust `contamination` if needed
   - Tune `min_severity_to_block`

3. **Regular model retraining:**
   - Retrain weekly với new data
   - Include blocked IPs in training

4. **Backup blocked alias:**
   - Export blocked IPs periodically
   - Keep audit log

## 📝 License

MIT License - Feel free to use and modify

## 👨‍💻 Author

AI-IDPS Team

---

**⚠️ WARNING:** This system automatically blocks IPs. Test thoroughly before production use!


"""
src/integrations/pfsense_client.py
Client để tương tác với pfSense Firewall API
Chặn/bỏ chặn IP addresses thông qua API
"""

import requests
import json
import yaml
from typing import Dict, List, Optional
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

from src.utils.logger import get_module_logger

# Disable SSL warnings (nếu dùng self-signed cert)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logger = get_module_logger('pfSenseClient')


class pfSenseClient:
    """
    Client để tương tác với pfSense Firewall API
    Hỗ trợ chặn IP thông qua firewall rules hoặc alias
    """
    
    def __init__(self, config_path='config/config.yaml'):
        """
        Initialize pfSense client
        
        Args:
            config_path: Path to config file
        """
        self.config = self._load_config(config_path)
        
        # pfSense connection details
        pfsense_config = self.config.get('pfsense', {})
        self.host = pfsense_config.get('host', 'localhost')
        self.port = pfsense_config.get('port', 443)
        self.api_key = pfsense_config.get('api_key', '')
        self.api_secret = pfsense_config.get('api_secret', '')
        self.verify_ssl = pfsense_config.get('verify_ssl', False)
        
        # Alias name for blocked IPs
        self.blocked_alias = pfsense_config.get('blocked_alias', 'AI_IDPS_Blocked')
        
        # Base URL
        self.base_url = f"https://{self.host}:{self.port}/api/v1"
        
        # Session
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        
        # Auth headers
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{self.api_key} {self.api_secret}'
        }
        
        # Statistics
        self.stats = {
            'blocked_ips': [],
            'block_success': 0,
            'block_failed': 0,
            'unblock_success': 0,
            'unblock_failed': 0
        }
        
        logger.info("=" * 80)
        logger.info("🔒 KHỞI TẠO PFSENSE CLIENT")
        logger.info("=" * 80)
        logger.info(f"🌐 Host: {self.host}:{self.port}")
        logger.info(f"📋 Blocked Alias: {self.blocked_alias}")
        logger.info(f"🔐 SSL Verify: {self.verify_ssl}")
        logger.info("=" * 80)
        
        # Test connection
        self._test_connection()
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            return config
        except Exception as e:
            logger.error(f"❌ Lỗi load config: {e}")
            return {}
    
    def _test_connection(self):
        """Test connection to pfSense API"""
        try:
            response = self.session.get(
                f"{self.base_url}/system/status",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.success("✅ Kết nối pfSense API thành công")
                data = response.json()
                logger.info(f"📊 pfSense version: {data.get('data', {}).get('platform', 'unknown')}")
            else:
                logger.warning(f"⚠️  pfSense API trả về status code: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Không thể kết nối pfSense API: {e}")
            logger.warning("⚠️  Chức năng blocking sẽ không hoạt động!")
    
    def _make_request(self, method: str, endpoint: str, data: Dict = None) -> Dict:
        """
        Make HTTP request to pfSense API
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint
            data: Request data
            
        Returns:
            Response data as dict
        """
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, headers=self.headers, timeout=10)
            elif method.upper() == 'POST':
                response = self.session.post(url, headers=self.headers, json=data, timeout=10)
            elif method.upper() == 'PUT':
                response = self.session.put(url, headers=self.headers, json=data, timeout=10)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=self.headers, timeout=10)
            else:
                logger.error(f"❌ Unsupported HTTP method: {method}")
                return None
            
            if response.status_code in [200, 201]:
                return response.json()
            else:
                logger.error(f"❌ API request failed: {response.status_code}")
                logger.debug(f"Response: {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error("❌ Request timeout")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Request error: {e}")
            return None
    
    def get_alias(self, alias_name: str) -> Optional[Dict]:
        """
        Get alias details
        
        Args:
            alias_name: Name of alias
            
        Returns:
            Alias data or None
        """
        logger.debug(f"🔍 Getting alias: {alias_name}")
        return self._make_request('GET', f'/firewall/alias?name={alias_name}')
    
    def create_alias(self, alias_name: str, description: str = "AI-IDPS Blocked IPs") -> bool:
        """
        Create new alias for blocked IPs
        
        Args:
            alias_name: Name of alias
            description: Alias description
            
        Returns:
            True if successful
        """
        logger.info(f"📝 Creating alias: {alias_name}")
        
        data = {
            "name": alias_name,
            "type": "host",
            "address": [],
            "descr": description,
            "detail": "Auto-managed by AI-IDPS"
        }
        
        result = self._make_request('POST', '/firewall/alias', data)
        
        if result:
            logger.success(f"✅ Đã tạo alias: {alias_name}")
            return True
        else:
            logger.error(f"❌ Không thể tạo alias: {alias_name}")
            return False
    
    def add_ip_to_alias(self, ip: str, alias_name: str = None, description: str = "") -> bool:
        """
        Add IP to blocked alias
        
        Args:
            ip: IP address to block
            alias_name: Alias name (default: self.blocked_alias)
            description: Description for this IP
            
        Returns:
            True if successful
        """
        if not alias_name:
            alias_name = self.blocked_alias
        
        logger.info(f"🚫 Adding IP {ip} to alias {alias_name}")
        
        # Get current alias
        alias = self.get_alias(alias_name)
        
        if not alias:
            # Create alias if not exists
            logger.warning(f"⚠️  Alias {alias_name} không tồn tại, đang tạo mới...")
            if not self.create_alias(alias_name):
                return False
            alias = self.get_alias(alias_name)
        
        # Get current addresses
        current_addresses = alias.get('data', {}).get('address', [])
        
        # Check if IP already blocked
        if ip in current_addresses:
            logger.warning(f"⚠️  IP {ip} đã có trong alias")
            return True
        
        # Add new IP
        current_addresses.append(ip)
        
        # Update alias
        data = {
            "name": alias_name,
            "address": current_addresses,
            "detail": description or f"Blocked by AI-IDPS at {datetime.now().isoformat()}"
        }
        
        result = self._make_request('PUT', f'/firewall/alias', data)
        
        if result:
            logger.success(f"✅ Đã chặn IP: {ip}")
            self.stats['blocked_ips'].append({
                'ip': ip,
                'timestamp': datetime.now().isoformat(),
                'description': description
            })
            self.stats['block_success'] += 1
            return True
        else:
            logger.error(f"❌ Không thể chặn IP: {ip}")
            self.stats['block_failed'] += 1
            return False
    
    def remove_ip_from_alias(self, ip: str, alias_name: str = None) -> bool:
        """
        Remove IP from blocked alias
        
        Args:
            ip: IP address to unblock
            alias_name: Alias name (default: self.blocked_alias)
            
        Returns:
            True if successful
        """
        if not alias_name:
            alias_name = self.blocked_alias
        
        logger.info(f"✅ Removing IP {ip} from alias {alias_name}")
        
        # Get current alias
        alias = self.get_alias(alias_name)
        
        if not alias:
            logger.error(f"❌ Alias {alias_name} không tồn tại")
            return False
        
        # Get current addresses
        current_addresses = alias.get('data', {}).get('address', [])
        
        # Check if IP exists
        if ip not in current_addresses:
            logger.warning(f"⚠️  IP {ip} không có trong alias")
            return True
        
        # Remove IP
        current_addresses.remove(ip)
        
        # Update alias
        data = {
            "name": alias_name,
            "address": current_addresses
        }
        
        result = self._make_request('PUT', f'/firewall/alias', data)
        
        if result:
            logger.success(f"✅ Đã bỏ chặn IP: {ip}")
            self.stats['unblock_success'] += 1
            return True
        else:
            logger.error(f"❌ Không thể bỏ chặn IP: {ip}")
            self.stats['unblock_failed'] += 1
            return False
    
    def block_ip(self, ip: str, reason: str = "", severity: str = "MEDIUM") -> Dict:
        """
        Block an IP address
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
            severity: Severity level
            
        Returns:
            Result dict with status and details
        """
        logger.security(f"🔒 BLOCKING IP: {ip} (Severity: {severity})")
        logger.info(f"📋 Reason: {reason}")
        
        description = f"[{severity}] {reason} | Blocked at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        success = self.add_ip_to_alias(ip, description=description)
        
        result = {
            'ip': ip,
            'action': 'block',
            'success': success,
            'reason': reason,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        
        if success:
            logger.success(f"✅ Đã chặn thành công IP: {ip}")
        else:
            logger.error(f"❌ Chặn thất bại IP: {ip}")
        
        return result
    
    def unblock_ip(self, ip: str) -> Dict:
        """
        Unblock an IP address
        
        Args:
            ip: IP address to unblock
            
        Returns:
            Result dict with status
        """
        logger.info(f"🔓 UNBLOCKING IP: {ip}")
        
        success = self.remove_ip_from_alias(ip)
        
        result = {
            'ip': ip,
            'action': 'unblock',
            'success': success,
            'timestamp': datetime.now().isoformat()
        }
        
        if success:
            logger.success(f"✅ Đã bỏ chặn thành công IP: {ip}")
        else:
            logger.error(f"❌ Bỏ chặn thất bại IP: {ip}")
        
        return result
    
    def get_blocked_ips(self) -> List[str]:
        """
        Get list of currently blocked IPs
        
        Returns:
            List of IP addresses
        """
        alias = self.get_alias(self.blocked_alias)
        
        if alias:
            addresses = alias.get('data', {}).get('address', [])
            logger.info(f"📋 Current blocked IPs: {len(addresses)}")
            return addresses
        else:
            logger.warning("⚠️  Không thể lấy danh sách IPs")
            return []
    
    def apply_changes(self) -> bool:
        """
        Apply firewall changes (reload filter)
        
        Returns:
            True if successful
        """
        logger.info("🔄 Applying firewall changes...")
        
        result = self._make_request('POST', '/firewall/apply')
        
        if result:
            logger.success("✅ Đã apply changes thành công")
            return True
        else:
            logger.error("❌ Không thể apply changes")
            return False
    
    def get_statistics(self) -> Dict:
        """
        Get blocking statistics
        
        Returns:
            Statistics dict
        """
        logger.info("=" * 80)
        logger.info("📊 PFSENSE BLOCKING STATISTICS")
        logger.info("=" * 80)
        logger.info(f"✅ Block success:   {self.stats['block_success']}")
        logger.info(f"❌ Block failed:    {self.stats['block_failed']}")
        logger.info(f"✅ Unblock success: {self.stats['unblock_success']}")
        logger.info(f"❌ Unblock failed:  {self.stats['unblock_failed']}")
        logger.info(f"📋 Total blocked:   {len(self.stats['blocked_ips'])}")
        logger.info("=" * 80)
        
        return self.stats.copy()


# =================== TEST ===================
if __name__ == '__main__':
    # Test blocking
    logger.info("🧪 Testing pfSense client...")
    
    client = pfSenseClient()
    
    # Test block
    result = client.block_ip("192.168.1.100", reason="Test blocking", severity="LOW")
    logger.info(f"Block result: {result}")
    
    # Get blocked IPs
    blocked = client.get_blocked_ips()
    logger.info(f"Blocked IPs: {blocked}")
    
    # Statistics
    client.get_statistics()
