from src.utils.logger import setup_advanced_logger
import logging


def main():
    """Hàm chính để demo các loại log"""
    
    # Khởi tạo logger
    logger = setup_advanced_logger(
        name="DEMO",
        level=logging.DEBUG,  # DEBUG để hiển thị tất cả các level
        add_icons=True
    )
    
    print("\n" + "=" * 80)
    print("DEMO HỆ THỐNG LOGGING ĐA MÀU SẮC")
    print("=" * 80 + "\n")

    # Test các level khác nhau
    logger.debug("Thông tin debug - dùng để phát triển và kiểm tra lỗi chi tiết")
    logger.network("Đang kết nối đến server 192.168.1.100:8080")
    logger.info("Hệ thống khởi động thành công")
    logger.success("Đã tải model AI thành công với accuracy 98.5%")
    logger.warning("Phát hiện 3 lần đăng nhập thất bại từ IP 10.0.0.5")
    logger.security("Phát hiện hoạt động đáng ngờ - Port scanning từ IP 172.16.0.100")
    logger.error("Không thể kết nối đến database - Connection timeout")
    logger.critical("HỆ THỐNG BỊ TẤN CÔNG DDoS - 10,000+ requests/second")

    print("\n" + "=" * 80)
    logger.info("Demo hoàn tất! Kiểm tra file logs/system.log để xem log không màu")
    print("=" * 80 + "\n")


def test_multiple_loggers():
    """Test nhiều logger cho các module khác nhau"""
    
    print("\n" + "=" * 80)
    print("TEST NHIỀU LOGGER CHO CÁC MODULE")
    print("=" * 80 + "\n")
    
    # Tạo logger cho từng module
    data_logger = setup_advanced_logger(name="DataProcessor", level=logging.INFO)
    alert_logger = setup_advanced_logger(name="AlertManager", level=logging.INFO)
    detector_logger = setup_advanced_logger(name="AnomalyDetector", level=logging.INFO)
    
    # Test
    data_logger.info("Đang xử lý 1,234 bản ghi log...")
    data_logger.success("Xử lý dữ liệu hoàn tất")
    
    alert_logger.warning("Phát hiện 5 IP bất thường")
    alert_logger.security("Đã gửi cảnh báo qua Telegram")
    
    detector_logger.info("Đang chạy model detection...")
    detector_logger.success("Phân tích hoàn tất - Độ chính xác: 99.2%")
    detector_logger.error("Không tìm thấy model file")
    
    print("\n" + "=" * 80 + "\n")


def test_logging_scenarios():
    """Test các tình huống thực tế"""
    
    logger = setup_advanced_logger(name="AI-IDPS", level=logging.DEBUG, add_icons=True)
    
    print("\n" + "=" * 80)
    print("TEST CÁC TÌNH HUỐNG THỰC TẾ")
    print("=" * 80 + "\n")
    
    # Scenario 1: Khởi động hệ thống
    logger.info("=" * 70)
    logger.info("BẮT ĐẦU KHỞI ĐỘNG HỆ THỐNG AI-IDPS")
    logger.info("=" * 70)
    logger.network("Đang kết nối đến pfSense router...")
    logger.success("Kết nối thành công")
    logger.info("Đang tải model ML...")
    logger.success("Đã tải model isolation_forest.pkl")
    
    # Scenario 2: Phát hiện bất thường
    logger.warning("=" * 70)
    logger.warning("PHÁT HIỆN HOẠT ĐỘNG BẤT THƯỜNG")
    logger.warning("=" * 70)
    logger.security("IP 192.168.1.100 - Tốc độ request cao bất thường (500 req/s)")
    logger.security("IP 10.0.0.50 - Scan nhiều port liên tục")
    logger.warning("Tổng 2 IP đáng ngờ được phát hiện")
    
    # Scenario 3: Lỗi nghiêm trọng
    logger.error("=" * 70)
    logger.critical("CẢNH BÁO NGHIÊM TRỌNG!")
    logger.critical("Phát hiện DDoS attack từ 50+ IP khác nhau")
    logger.critical("Hệ thống đang quá tải - CPU: 98%, RAM: 95%")
    logger.error("=" * 70)
    
    print("\n")


if __name__ == "__main__":
    # Chạy các test
    main()
    test_multiple_loggers()
    test_logging_scenarios()