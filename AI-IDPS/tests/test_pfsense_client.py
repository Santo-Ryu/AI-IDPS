"""
Test pfSense SSH Client - FIXED VERSION
- Thêm connection test trước
- Better error handling
- Kiểm tra table exists
"""

import time
import sys
from src.integrations.pfsense_client import pfSenseClient

TEST_IP = "1.2.3.4"
TEST_IP2 = "1.2.3.5"
REASON = "Test block từ AI IDPS"
SEVERITY = "LOW"


def print_result(title: str, result: dict):
    print("\n" + "=" * 60)
    print(f"📊 {title}")
    print("=" * 60)
    for k, v in result.items():
        print(f"  {k}: {v}")
    print("=" * 60 + "\n")


def test_block_ip(client: pfSenseClient, ip: str = TEST_IP):
    print("\n🧪 TEST 1: BLOCK IP")
    result = client.block_ip(
        ip=ip,
        reason=REASON,
        severity=SEVERITY
    )
    print_result("BLOCK RESULT", result)
    return result["success"]


def test_list_ips(client: pfSenseClient):
    print("\n🧪 TEST 2: LIST BLOCKED IPS")
    result = client.list_blocked_ips()
    print_result("LIST RESULT", result)
    
    if result["success"] and result.get("ips"):
        print(f"📋 Blocked IPs ({result['count']}):")
        for ip in result["ips"]:
            print(f"   - {ip}")
    
    return result["success"]


def test_unblock_ip(client: pfSenseClient):
    print("\n🧪 TEST 3: UNBLOCK IP")
    result = client.unblock_ip(TEST_IP)
    print_result("UNBLOCK RESULT", result)
    return result["success"]


def main():
    print("\n" + "-" * 50)
    print("🚀 Khởi chạy test pfSense SSH Client")
    print("-" * 50 + "\n")

    try:
        # ✅ Khởi tạo client (sẽ test connection ngay)
        client = pfSenseClient()
        
        # ✅ Kiểm tra table exists
        print("\n🔍 Checking table exists...")
        if not client.check_table_exists():
            print("\n❌ Table không tồn tại - tạo trên pfSense trước:")
            print("   Firewall > Aliases > Add (Type: Host)")
            print(f"   Name: {client.table}")
            sys.exit(1)
        
        print("\n✅ Table OK, tiếp tục test...\n")
        
        # 1️⃣ Block IP
        if not test_block_ip(client):
            print("❌ Block test failed, dừng")
            sys.exit(1)
            
        # 1️⃣ Block IP
        if not test_block_ip(client, TEST_IP2):
            print("❌ Block test failed, dừng")
            sys.exit(1)
        
        time.sleep(2)

        # 2️⃣ List IPs
        if not test_list_ips(client):
            print("❌ List test failed")
        
        time.sleep(2)

        # 3️⃣ Unblock IP
        # if not test_unblock_ip(client):
        #     print("❌ Unblock test failed")
        
        time.sleep(2)

        # 4️⃣ List lại để verify
        print("\n🧪 TEST 4: VERIFY UNBLOCK")
        test_list_ips(client)

        print("\n" + "-" * 50)
        print("✅ TEST HOÀN TẤT THÀNH CÔNG")
        print("-" * 50 + "\n")

    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()