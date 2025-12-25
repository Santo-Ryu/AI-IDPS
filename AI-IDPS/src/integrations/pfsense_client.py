"""
pfSense SSH Client - FIXED VERSION
- Thêm connection test
- Tăng timeout
- Better error handling
- Debug logging
"""

import subprocess
from typing import Dict
from src.utils.logger import get_module_logger

logger = get_module_logger("pfSenseSSH")


class pfSenseClient:
    def __init__(
        self,
        host="10.0.1.1",
        user="admin",
        ssh_key="/home/santo/.ssh/pfsense_ai_idps",
        table="AI_IDPS_Blocked",
        timeout=30  # ⬆️ Tăng timeout lên 30s
    ):
        self.host = host
        self.user = user
        self.ssh_key = ssh_key
        self.table = table
        self.timeout = timeout

        logger.info("🔐 pfSense SSH client khởi tạo thành công")
        logger.info(f"🌐 Host: {host}")
        logger.info(f"🌐 User: {user}")
        logger.info(f"📛 Alias table: {table}")
        
        # ✅ Test connection ngay khi init
        self._test_connection()

    def _test_connection(self) -> bool:
        """
        Test SSH connection trước khi sử dụng
        """
        logger.info("🔍 Testing SSH connection...")
        try:
            result = self._ssh_exec("echo 'SSH_OK'", timeout=5)
            
            if result.returncode == 0 and "SSH_OK" in result.stdout:
                logger.success("✅ SSH connection OK")
                return True
            
            logger.error(f"❌ SSH test failed: {result.stderr}")
            return False
            
        except subprocess.TimeoutExpired:
            logger.error("❌ SSH connection timeout - pfSense có thể đang ở menu mode")
            logger.error("💡 Kiểm tra: System > Advanced > Admin Access")
            logger.error("💡 Đảm bảo SSH shell = 'Command shell' (KHÔNG phải menu)")
            return False
        except Exception as e:
            logger.error(f"❌ SSH connection error: {e}")
            return False

    def _ssh_exec(
        self, 
        command: str, 
        timeout: int = None
    ) -> subprocess.CompletedProcess:
        """
        Thực thi lệnh SSH tới pfSense
        """
        if timeout is None:
            timeout = self.timeout
            
        ssh_cmd = [
            "ssh",
            "-i", self.ssh_key,
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=5",  # ⬆️ Thêm connection timeout
            f"{self.user}@{self.host}",
            command
        ]

        logger.debug(f"🔧 SSH CMD: {command}")
        logger.debug(f"⏱️  Timeout: {timeout}s")

        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # ⬆️ Log output để debug
            if result.stdout:
                logger.debug(f"📤 STDOUT: {result.stdout.strip()}")
            if result.stderr:
                logger.debug(f"📤 STDERR: {result.stderr.strip()}")
            
            return result
            
        except subprocess.TimeoutExpired as e:
            logger.error(f"⏱️  Command timeout sau {timeout}s")
            logger.error(f"💡 Command: {command}")
            raise

    def block_ip(self, ip: str, reason: str = "", severity: str = "HIGH") -> Dict:
        """
        Block IP bằng pfctl table
        """
        logger.info(f"🚫 Đang block IP: {ip}")
        
        try:
            # ⬆️ Thêm -n flag để không flush, tránh prompt
            cmd = f"pfctl -t {self.table} -T add {ip}"
            result = self._ssh_exec(cmd)

            if result.returncode == 0:
                logger.security(f"🚫 BLOCK IP thành công: {ip}")
                logger.info(f"   Lý do: {reason}")
                return {
                    "success": True,
                    "ip": ip,
                    "severity": severity,
                    "message": result.stdout.strip() if result.stdout else "OK"
                }

            logger.error(f"❌ BLOCK IP thất bại: {ip}")
            logger.error(result.stderr.strip())

            return {
                "success": False,
                "ip": ip,
                "error": result.stderr.strip()
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"⏱️  BLOCK IP timeout: {ip}")
            return {
                "success": False,
                "ip": ip,
                "error": "SSH command timeout"
            }

    def unblock_ip(self, ip: str) -> Dict:
        """
        Gỡ block IP
        """
        logger.info(f"✅ Đang unblock IP: {ip}")
        
        try:
            cmd = f"pfctl -t {self.table} -T delete {ip}"
            result = self._ssh_exec(cmd)

            if result.returncode == 0:
                logger.success(f"✅ UNBLOCK IP thành công: {ip}")
                return {
                    "success": True, 
                    "ip": ip,
                    "message": result.stdout.strip() if result.stdout else "OK"
                }

            return {
                "success": False,
                "ip": ip,
                "error": result.stderr.strip()
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "ip": ip,
                "error": "SSH command timeout"
            }

    def list_blocked_ips(self) -> Dict:
        """
        Danh sách IP đang bị block
        """
        logger.info("📋 Đang list blocked IPs...")
        
        try:
            cmd = f"pfctl -t {self.table} -T show"
            result = self._ssh_exec(cmd, timeout=15)

            if result.returncode != 0:
                return {
                    "success": False, 
                    "error": result.stderr.strip()
                }

            ips = [ip.strip() for ip in result.stdout.strip().splitlines() if ip.strip()]
            logger.info(f"📊 Tìm thấy {len(ips)} IPs")
            
            return {
                "success": True, 
                "ips": ips,
                "count": len(ips)
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "SSH command timeout"
            }

    def check_table_exists(self) -> bool:
        """
        Kiểm tra table có tồn tại không
        """
        logger.info(f"🔍 Checking table: {self.table}")
        
        try:
            result = self._ssh_exec(f"pfctl -t {self.table} -T show", timeout=10)
            exists = result.returncode == 0
            
            if exists:
                logger.success(f"✅ Table {self.table} exists")
            else:
                logger.error(f"❌ Table {self.table} NOT found")
                logger.error("💡 Tạo table trên pfSense: Firewall > Aliases")
                
            return exists
            
        except subprocess.TimeoutExpired:
            logger.error("⏱️  Table check timeout")
            return False
