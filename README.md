# AI-IDPS pfSense

🛡️ **AI-based Intrusion Detection and Prevention System** integrated with pfSense Firewall and ELK Stack

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📋 Mục Lục

- [Giới Thiệu](#giới-thiệu)
- [Tính Năng](#tính-năng)
- [Kiến Trúc Hệ Thống](#kiến-trúc-hệ-thống)
- [Yêu Cầu](#yêu-cầu)
- [Cài Đặt](#cài-đặt)
- [Cấu Hình](#cấu-hình)
- [Sử Dụng](#sử-dụng)
- [Cấu Trúc Dự Án](#cấu-trúc-dự-án)
- [Demo Mode](#demo-mode)
- [Tài Liệu](#tài-liệu)

## 🎯 Giới Thiệu

**AI-IDPS pfSense** là hệ thống phát hiện và ngăn chặn xâm nhập mạng sử dụng trí tuệ nhân tạo (AI), được tích hợp với pfSense Firewall và ELK Stack. Hệ thống sử dụng thuật toán **Isolation Forest** để phát hiện các hành vi bất thường trong log mạng và tự động chặn các IP độc hại.

### Đặc điểm nổi bật:
- ✅ Phát hiện bất thường theo thời gian thực
- ✅ Tự động chặn IP độc hại qua pfSense API
- ✅ Tích hợp cảnh báo qua Telegram
- ✅ Hỗ trợ nhiều loại tấn công: DDoS, Port Scan, Brute Force
- ✅ Dashboard trực quan với Kibana (ELK Stack)

## 🚀 Tính Năng

### 1. Thu thập và xử lý log
- Đọc log từ file JSON (giả lập từ ELK)
- Làm sạch và chuẩn hóa dữ liệu
- Xử lý các trường: IP, port, protocol, timestamp

### 2. Feature Engineering
- Tần suất kết nối (Connection Frequency)
- Đa dạng cổng (Port Diversity)
- Tỉ lệ block/pass (Action Ratios)
- Thống kê packet size
- Đặc trưng thời gian (Temporal Features)

### 3. Phát hiện bất thường với AI
- Mô hình: **Isolation Forest**
- Phát hiện: DDoS, Port Scan, Brute Force
- Đánh giá mức độ rủi ro: Critical, High, Medium, Low
- Anomaly score cho từng sự kiện

### 4. Tự động phản ứng
- Chặn IP qua pfSense API
- Whitelist để bảo vệ IP nội bộ
- Rate limiting để tránh quá tải
- Retry mechanism

### 5. Hệ thống cảnh báo
- Telegram Bot notifications
- Cảnh báo theo mức độ nghiêm trọng
- Summary reports định kỳ

## 🏗️ Kiến Trúc Hệ Thống

```
┌─────────────────┐
│   pfSense       │
│   Firewall      │
└────────┬────────┘
         │ syslog
         ▼
┌──────────────────┐
│   ELK Stack      │
│ ┌──────────────┐ │
│ │ Logstash     │ │──► Parse & Filter
│ │ Elasticsearch│ │──► Store & Index
│ │ Kibana       │ │──► Visualize
│ └──────────────┘ │
└────────┬─────────┘
         │ JSON Export
         ▼
┌─────────────────────────────────┐
│   AI-IDPS Python Module         │
│ ┌─────────────────────────────┐ │
│ │ Data Processor              │ │
│ │ Feature Engineer            │ │
│ │ Anomaly Detector (IF)       │ │
│ └─────────────────────────────┘ │
└────────┬───────────────┬────────┘
         │               │
         │ Block IP      │ Alert
         ▼               ▼
┌─────────────────┐ ┌──────────────┐
│   pfSense API   │ │  Telegram    │
└─────────────────┘ └──────────────┘
```

## 📋 Yêu Cầu

### Phần mềm
- Python 3.8+
- pfSense 2.5+ (với API package)
- ELK Stack 7.x+ (optional cho production)

### Thư viện Python
```
pandas>=2.0.3
numpy>=1.24.3
scikit-learn>=1.3.0
pyyaml>=6.0.1
python-dotenv>=1.0.0
requests>=2.31.0
python-telegram-bot>=20.4  # optional
colorlog>=6.7.0
```

## 🔧 Cài Đặt

### 1. Clone repository

```bash
git clone https://github.com/your-repo/ai-idps-pfsense.git
cd ai-idps-pfsense
```

### 2. Tạo virtual environment

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# hoặc
venv\Scripts\activate     # Windows
```

### 3. Cài đặt dependencies

```bash
pip install -r requirements.txt
```

### 4. Tạo cấu trúc thư mục

```bash
mkdir -p data/{raw,processed,sample}
mkdir -p models
mkdir -p logs
```

## ⚙️ Cấu Hình

### 1. Cấu hình môi trường (.env)

```bash
cp .env.example .env
```

Chỉnh sửa file `.env`:

```env
# pfSense API
PFSENSE_URL=https://192.168.1.1
PFSENSE_API_KEY=your_api_key_here
PFSENSE_API_SECRET=your_api_secret_here

# Telegram (Optional)
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Model Parameters
CONTAMINATION_RATE=0.1
ANOMALY_THRESHOLD=-0.5
```

### 2. Cấu hình chính (config/config.yaml)

Chỉnh sửa các tham số theo nhu cầu:
- Model parameters
- Feature engineering settings
- Blocking rules
- Alert configuration

### 3. Cấu hình pfSense API (config/pfsense_config.yaml)

Thiết lập endpoints và interface:
```yaml
pfsense:
  base_url: "https://your-pfsense-ip"
  rule:
    interface: "wan"
```

## 🎮 Sử Dụng

### Bước 1: Tạo dữ liệu mẫu

```bash
python scripts/generate_sample_data.py
```

Output: `data/sample/sample_logs.json` (1000+ log entries)

### Bước 2: Huấn luyện model

```bash
python scripts/train_model.py
```

Output:
- `models/isolation_forest.pkl`
- `models/scaler.pkl`
- `data/processed/features.csv`

### Bước 3: Chạy detection

```bash
python main.py
```

Hệ thống sẽ:
1. Load model đã train
2. Xử lý log mới
3. Phát hiện bất thường
4. Chặn IP độc hại (nếu bật auto-block)
5. Gửi cảnh báo

### Output mẫu:

```
🚨 TOP DETECTED THREATS
======================================================================

1. IP Address: 185.220.101.50
   Avg Anomaly Score: -0.8234
   Risk Level: Critical
   Anomaly Count: 150
   
✅ Successfully blocked: 185.220.101.50

📊 DETECTION SUMMARY
======================================================================
Total events: 1000
Anomalies detected: 215 (21.50%)
IPs blocked: 3
```

## 📁 Cấu Trúc Dự Án

```
ai-idps-pfsense/
├── data/
│   ├── raw/              # Log JSON từ ELK
│   ├── processed/        # Dữ liệu đã xử lý
│   └── sample/           # Dữ liệu mẫu
├── models/               # Model đã train
├── src/                  # Source code
│   ├── data_processor.py
│   ├── feature_engineer.py
│   ├── anomaly_detector.py
│   ├── pfsense_api.py
│   └── alert_manager.py
├── config/               # Cấu hình
├── scripts/              # Tiện ích
├── logs/                 # Log chương trình
├── main.py              # Entry point
└── requirements.txt
```

## 🧪 Demo Mode

Nếu không có pfSense hoặc Telegram, hệ thống tự động chạy **DEMO MODE**:

- ✅ Phát hiện bất thường vẫn hoạt động bình thường
- ✅ API calls được giả lập và log ra console
- ✅ Không cần API key/secret
- ✅ Phù hợp để test và học tập

## 📊 Metrics và Đánh Giá

Model được đánh giá dựa trên:
- **Anomaly Detection Rate**: Tỉ lệ phát hiện bất thường
- **False Positive Rate**: Tỉ lệ cảnh báo nhầm
- **Response Time**: Thời gian phản hồi
- **Blocking Success Rate**: Tỉ lệ chặn thành công

## 🔍 Troubleshooting

### Lỗi thường gặp:

**1. Model not found**
```bash
python scripts/train_model.py
```

**2. Data file not found**
```bash
python scripts/generate_sample_data.py
```

**3. pfSense API connection failed**
- Kiểm tra URL và API credentials trong `.env`
- Verify SSL certificate
- Kiểm tra firewall rules

## 📖 Tài Liệu Tham Khảo

- [pfSense Documentation](https://docs.netgate.com/pfsense)
- [Isolation Forest Paper](https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf)
- [ELK Stack Guide](https://www.elastic.co/guide/index.html)
- [Scikit-learn IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)

## 👥 Tác Giả

- **Đoàn Thanh Lâm** - 23NS052
- **Lê Thành Lợi** - 23NS058

**Giảng viên hướng dẫn:** ThS. Trần Thu Thủy

**Trường:** Đại học Công nghệ Thông tin và Truyền thông Việt - Hàn

## 📄 License

MIT License - xem file [LICENSE](LICENSE) để biết thêm chi tiết.

## 🙏 Cảm Ơn

Cảm ơn đã sử dụng AI-IDPS pfSense! Nếu có bất kỳ câu hỏi hoặc góp ý, vui lòng tạo issue trên GitHub.

---

**⭐ Nếu dự án này hữu ích, hãy cho chúng tôi một star trên GitHub!**
