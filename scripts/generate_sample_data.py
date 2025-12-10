"""
Generate Sample Data Script
Creates realistic pfSense log data for testing
"""

import json
import random
from datetime import datetime, timedelta
import os


def generate_normal_traffic(count: int, start_time: datetime) -> list:
    """Generate normal network traffic logs"""
    logs = []
    protocols = ['tcp', 'udp', 'icmp']
    common_ports = [80, 443, 22, 53, 25, 110, 143]
    local_ips = [f"192.168.1.{i}" for i in range(10, 50)]
    external_ips = [f"8.8.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(20)]
    
    for i in range(count):
        timestamp = start_time + timedelta(seconds=i*random.uniform(0.1, 2))
        
        log = {
            'timestamp': timestamp.isoformat(),
            'src_ip': random.choice(local_ips),
            'dest_ip': random.choice(external_ips),
            'src_port': random.randint(1024, 65535),
            'dest_port': random.choice(common_ports),
            'protocol': random.choice(protocols),
            'action': 'pass',
            'packet_size': random.randint(64, 1500),
            'interface': 'wan'
        }
        logs.append(log)
    
    return logs


def generate_ddos_attack(count: int, start_time: datetime, attacker_ip: str) -> list:
    """Generate DDoS attack pattern"""
    logs = []
    target_ip = "192.168.1.100"
    
    for i in range(count):
        timestamp = start_time + timedelta(milliseconds=i*10)  # Very frequent
        
        log = {
            'timestamp': timestamp.isoformat(),
            'src_ip': attacker_ip,
            'dest_ip': target_ip,
            'src_port': random.randint(1024, 65535),
            'dest_port': 80,
            'protocol': 'tcp',
            'action': 'block',
            'packet_size': random.randint(32, 128),
            'interface': 'wan'
        }
        logs.append(log)
    
    return logs


def generate_port_scan(start_time: datetime, scanner_ip: str) -> list:
    """Generate port scanning pattern"""
    logs = []
    target_ip = "192.168.1.50"
    
    # Scan common ports
    for port in range(1, 1024, 10):
        timestamp = start_time + timedelta(milliseconds=port*5)
        
        log = {
            'timestamp': timestamp.isoformat(),
            'src_ip': scanner_ip,
            'dest_ip': target_ip,
            'src_port': random.randint(1024, 65535),
            'dest_port': port,
            'protocol': 'tcp',
            'action': 'block',
            'packet_size': 64,
            'interface': 'wan'
        }
        logs.append(log)
    
    return logs


def generate_brute_force(count: int, start_time: datetime, attacker_ip: str) -> list:
    """Generate brute force login attempt pattern"""
    logs = []
    target_ip = "192.168.1.10"
    ssh_port = 22
    
    for i in range(count):
        timestamp = start_time + timedelta(seconds=i*2)
        
        log = {
            'timestamp': timestamp.isoformat(),
            'src_ip': attacker_ip,
            'dest_ip': target_ip,
            'src_port': random.randint(1024, 65535),
            'dest_port': ssh_port,
            'protocol': 'tcp',
            'action': 'pass',  # SSH allows connection but login fails
            'packet_size': random.randint(100, 300),
            'interface': 'wan'
        }
        logs.append(log)
    
    return logs


def main():
    """Generate comprehensive sample dataset"""
    print("Generating sample pfSense logs...")
    
    start_time = datetime.now() - timedelta(hours=1)
    all_logs = []
    
    # Generate normal traffic (70%)
    print("Generating normal traffic...")
    normal_logs = generate_normal_traffic(700, start_time)
    all_logs.extend(normal_logs)
    
    # Generate DDoS attack (15%)
    print("Generating DDoS attack logs...")
    ddos_attacker = "185.220.101.50"
    ddos_logs = generate_ddos_attack(150, start_time + timedelta(minutes=20), ddos_attacker)
    all_logs.extend(ddos_logs)
    
    # Generate port scan (10%)
    print("Generating port scan logs...")
    port_scanner = "203.0.113.45"
    scan_logs = generate_port_scan(start_time + timedelta(minutes=35), port_scanner)
    all_logs.extend(scan_logs)
    
    # Generate brute force (5%)
    print("Generating brute force logs...")
    brute_forcer = "198.51.100.88"
    brute_logs = generate_brute_force(50, start_time + timedelta(minutes=45), brute_forcer)
    all_logs.extend(brute_logs)
    
    # Sort by timestamp
    all_logs.sort(key=lambda x: x['timestamp'])
    
    # Save to file
    output_dir = 'data/sample'
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, 'sample_logs.json')
    
    with open(output_file, 'w') as f:
        json.dump({'logs': all_logs}, f, indent=2)
    
    print(f"\n✅ Generated {len(all_logs)} log entries")
    print(f"   - Normal traffic: {len(normal_logs)}")
    print(f"   - DDoS attack: {len(ddos_logs)}")
    print(f"   - Port scan: {len(scan_logs)}")
    print(f"   - Brute force: {len(brute_logs)}")
    print(f"\n📁 Saved to: {output_file}")
    
    # Also create a smaller test file
    test_logs = all_logs[:100]
    test_file = os.path.join(output_dir, 'test_logs.json')
    with open(test_file, 'w') as f:
        json.dump({'logs': test_logs}, f, indent=2)
    
    print(f"📁 Test file saved to: {test_file}")


if __name__ == '__main__':
    main()
