"""
src/utils/debug_logger.py
Debug Logger chuyên nghiệp với pretty print và màu sắc
Dùng để debug logs, DataFrames, và data structures phức tạp
"""

import json
import pandas as pd
import numpy as np
from typing import Any, Dict, List, Union
from pprint import pformat
from datetime import datetime


class DebugLogger:
    """
    Debug Logger với pretty print và màu sắc
    Dùng để debug logs structure, DataFrames, và behaviors
    """
    
    # ANSI Colors
    COLORS = {
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'MAGENTA': '\033[95m',
        'CYAN': '\033[96m',
        'WHITE': '\033[97m',
        'GRAY': '\033[90m',
        'BG_RED': '\033[101m',
        'BG_GREEN': '\033[102m',
        'BG_YELLOW': '\033[103m',
    }
    
    def __init__(self, logger, enabled: bool = True):
        """
        Args:
            logger: Logger instance từ get_module_logger
            enabled: Bật/tắt debug mode
        """
        self.logger = logger
        self.enabled = enabled
        self.debug_counter = 0
    
    def _colorize(self, text: str, color: str) -> str:
        """Thêm màu vào text"""
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['RESET']}"
    
    def _get_type_color(self, type_name: str) -> str:
        """Lấy màu cho kiểu dữ liệu"""
        type_colors = {
            'int': 'CYAN',
            'float': 'CYAN',
            'str': 'GREEN',
            'list': 'YELLOW',
            'dict': 'MAGENTA',
            'NoneType': 'GRAY',
            'bool': 'BLUE',
        }
        return type_colors.get(type_name, 'WHITE')
    
    def print_separator(self, title: str = "", char: str = "=", length: int = 80, color: str = "CYAN"):
        """In separator line với title"""
        if not self.enabled:
            return
        
        if title:
            title_str = f" {title} "
            padding = (length - len(title_str)) // 2
            line = char * padding + title_str + char * padding
            if len(line) < length:
                line += char
        else:
            line = char * length
        
        print(self._colorize(line, color))
    
    def print_header(self, title: str, emoji: str = "🔍"):
        """In header lớn"""
        if not self.enabled:
            return
        
        self.debug_counter += 1
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        print()
        self.print_separator("", "═", 80, "CYAN")
        header = f"{emoji} DEBUG #{self.debug_counter}: {title}"
        print(self._colorize(header, "BOLD"))
        print(self._colorize(f"⏰ Time: {timestamp}", "GRAY"))
        self.print_separator("", "═", 80, "CYAN")
    
    def print_log_structure(self, log: Dict, title: str = "LOG STRUCTURE", max_logs: int = 3):
        """
        In cấu trúc chi tiết của log với type và value
        
        Args:
            log: Log dict hoặc list of logs
            title: Tiêu đề
            max_logs: Số logs tối đa hiển thị (nếu là list)
        """
        if not self.enabled:
            return
        
        self.print_header(title, "📋")
        
        # Xử lý list of logs
        if isinstance(log, list):
            print(self._colorize(f"📦 Total logs: {len(log)}", "YELLOW"))
            logs_to_show = log[:max_logs]
            if len(log) > max_logs:
                print(self._colorize(f"   (showing first {max_logs} logs only)", "GRAY"))
            print()
            
            for idx, single_log in enumerate(logs_to_show, 1):
                print(self._colorize(f"--- Log #{idx} ---", "BLUE"))
                self._print_single_log(single_log)
                print()
        else:
            self._print_single_log(log)
        
        self.print_separator()
    
    def _print_single_log(self, log: Dict):
        """In 1 log duy nhất"""
        for key, value in sorted(log.items()):
            # Xác định type
            value_type = type(value).__name__
            type_color = self._get_type_color(value_type)
            
            # Format value theo type
            if isinstance(value, list):
                if len(value) == 0:
                    display_value = "[]"
                    warning = self._colorize(" ⚠️  EMPTY LIST", "YELLOW")
                elif len(value) == 1:
                    display_value = f"[{repr(value[0])}]"
                    warning = self._colorize(" ℹ️  Single item list", "BLUE")
                elif len(value) <= 3:
                    display_value = f"[{', '.join(repr(v) for v in value)}]"
                    warning = ""
                else:
                    display_value = f"[{repr(value[0])}, ..., {repr(value[-1])}]"
                    warning = self._colorize(f" 📊 {len(value)} items", "MAGENTA")
                display_value += warning
                
            elif isinstance(value, str):
                if len(value) > 100:
                    display_value = f"'{value[:40]}...{value[-20:]}'"
                    display_value += self._colorize(f" 🔴 {len(value)} chars! (TOO LONG?)", "RED")
                elif len(value) > 50:
                    display_value = f"'{value[:30]}...{value[-15:]}'"
                    display_value += self._colorize(f" ({len(value)} chars)", "YELLOW")
                else:
                    display_value = repr(value)
                    
            elif isinstance(value, (int, float)):
                display_value = str(value)
                # Highlight số bất thường
                if isinstance(value, int) and value > 65535:
                    display_value += self._colorize(" ⚠️  Suspiciously large", "YELLOW")
                    
            elif value is None:
                display_value = self._colorize("None", "GRAY")
                
            else:
                display_value = repr(value)
            
            # In ra
            key_str = self._colorize(f"{key:.<35}", "WHITE")
            type_str = self._colorize(f"{value_type:.<15}", type_color)
            print(f"  {key_str} {type_str} {display_value}")
    
    def print_dataframe_info(self, df: pd.DataFrame, title: str = "DATAFRAME INFO", 
                            show_sample: bool = True, sample_rows: int = 3):
        """
        In thông tin chi tiết về DataFrame
        
        Args:
            df: DataFrame cần debug
            title: Tiêu đề
            show_sample: Có hiển thị sample rows không
            sample_rows: Số rows sample
        """
        if not self.enabled:
            return
        
        self.print_header(title, "📊")
        
        # Basic info
        print(self._colorize(f"📐 Shape: {df.shape[0]:,} rows × {df.shape[1]} columns", "CYAN"))
        
        memory_mb = df.memory_usage(deep=True).sum() / 1024 / 1024
        memory_str = f"{memory_mb:.2f} MB" if memory_mb > 1 else f"{memory_mb*1024:.2f} KB"
        print(self._colorize(f"💾 Memory: {memory_str}", "CYAN"))
        print()
        
        # Column details
        self.print_separator("COLUMN DETAILS", "─", 80, "BLUE")
        
        print(f"{'Column':<25} {'Type':<12} {'Nulls':<10} {'Unique':<10} {'Sample Values'}")
        print("─" * 80)
        
        for col in df.columns:
            dtype = str(df[col].dtype)
            null_count = df[col].isnull().sum()
            null_pct = null_count / len(df) * 100
            unique_count = df[col].nunique()
            
            # Color coding
            if null_count > 0:
                null_str = self._colorize(f"{null_count} ({null_pct:.1f}%)", "YELLOW")
            else:
                null_str = "0"
            
            # Sample values
            if dtype == 'object':
                sample = df[col].dropna().head(2).tolist()
                if sample:
                    sample_str = ', '.join(str(s)[:15] for s in sample)
                    if len(sample_str) > 30:
                        sample_str = sample_str[:30] + "..."
                else:
                    sample_str = "N/A"
            else:
                try:
                    sample_vals = df[col].dropna().head(2).tolist()
                    sample_str = ', '.join(str(round(s, 2) if isinstance(s, float) else s) for s in sample_vals)
                except:
                    sample_str = "N/A"
            
            print(f"{col:<25} {dtype:<12} {null_str:<15} {unique_count:<10} {sample_str}")
        
        # Warnings
        warnings = []
        for col in df.columns:
            # Check for list columns
            if df[col].apply(lambda x: isinstance(x, list)).any():
                warnings.append(f"⚠️  '{col}' contains lists!")
            
            # Check for very long strings
            if df[col].dtype == 'object':
                max_len = df[col].astype(str).str.len().max()
                if max_len > 100:
                    warnings.append(f"⚠️  '{col}' has strings up to {max_len} chars!")
        
        if warnings:
            print()
            self.print_separator("WARNINGS", "─", 80, "YELLOW")
            for w in warnings:
                print(self._colorize(w, "YELLOW"))
        
        # Sample data
        if show_sample and len(df) > 0:
            print()
            self.print_separator(f"SAMPLE DATA (first {sample_rows} rows)", "─", 80, "GREEN")
            print(df.head(sample_rows).to_string(index=True))
        
        self.print_separator()
    
    def print_dict_tree(self, data: Dict, title: str = "DICTIONARY TREE", max_depth: int = 3):
        """
        In dictionary dưới dạng tree structure
        
        Args:
            data: Dictionary cần hiển thị
            title: Tiêu đề
            max_depth: Độ sâu tối đa
        """
        if not self.enabled:
            return
        
        self.print_header(title, "🌳")
        self._print_tree_recursive(data, depth=0, max_depth=max_depth)
        self.print_separator()
    
    def _print_tree_recursive(self, data: Any, depth: int = 0, max_depth: int = 3, prefix: str = ""):
        """Recursive function để in tree"""
        if depth > max_depth:
            print(f"{prefix}...")
            return
        
        indent = "  " * depth
        
        if isinstance(data, dict):
            for idx, (key, value) in enumerate(data.items()):
                is_last = (idx == len(data) - 1)
                connector = "└─" if is_last else "├─"
                
                value_type = type(value).__name__
                type_color = self._get_type_color(value_type)
                
                key_str = self._colorize(str(key), "CYAN")
                type_str = self._colorize(f"[{value_type}]", type_color)
                
                if isinstance(value, (dict, list)):
                    size = len(value)
                    size_str = self._colorize(f" ({size} items)", "GRAY")
                    print(f"{indent}{connector} {key_str} {type_str}{size_str}")
                    
                    next_prefix = indent + ("   " if is_last else "│  ")
                    self._print_tree_recursive(value, depth + 1, max_depth, next_prefix)
                else:
                    # Leaf node
                    value_str = str(value)
                    if len(value_str) > 50:
                        value_str = value_str[:47] + "..."
                    print(f"{indent}{connector} {key_str} {type_str}: {value_str}")
                    
        elif isinstance(data, list):
            for idx, item in enumerate(data[:5]):  # Show first 5 items
                is_last = (idx == len(data) - 1) or (idx == 4)
                connector = "└─" if is_last else "├─"
                
                value_type = type(item).__name__
                type_color = self._get_type_color(value_type)
                type_str = self._colorize(f"[{value_type}]", type_color)
                
                if isinstance(item, (dict, list)):
                    size = len(item)
                    size_str = self._colorize(f" ({size} items)", "GRAY")
                    print(f"{indent}{connector} [{idx}] {type_str}{size_str}")
                    
                    next_prefix = indent + ("   " if is_last else "│  ")
                    self._print_tree_recursive(item, depth + 1, max_depth, next_prefix)
                else:
                    value_str = str(item)
                    if len(value_str) > 50:
                        value_str = value_str[:47] + "..."
                    print(f"{indent}{connector} [{idx}] {type_str}: {value_str}")
            
            if len(data) > 5:
                print(f"{indent}... ({len(data) - 5} more items)")
    
    def print_behavior_analysis(self, behavior_df: pd.DataFrame, ip: str, logs_count: int):
        """
        In phân tích behavior với highlight
        
        Args:
            behavior_df: DataFrame chứa behavior features
            ip: IP address
            logs_count: Số logs
        """
        if not self.enabled:
            return
        
        self.print_header(f"BEHAVIOR ANALYSIS: {ip}", "🔬")
        
        print(self._colorize(f"📦 Logs analyzed: {logs_count}", "CYAN"))
        print()
        
        b = behavior_df.iloc[0]
        
        # Connection patterns
        self.print_separator("CONNECTION PATTERNS", "─", 80, "BLUE")
        print(f"{'Total connections:':<30} {int(b['total_connections']):>10,}")
        print(f"{'Connection rate:':<30} {b['connection_rate']:>10.2f} conn/s")
        print(f"{'Unique dst IPs:':<30} {int(b['unique_dst_ips']):>10}")
        print(f"{'Unique dst ports:':<30} {int(b['unique_dst_ports']):>10}")
        
        # Port diversity check
        if b['unique_dst_ports'] > 50:
            print(self._colorize("   ⚠️  HIGH PORT DIVERSITY - Possible port scan!", "YELLOW"))
        
        # Action patterns
        print()
        self.print_separator("ACTION PATTERNS", "─", 80, "BLUE")
        print(f"{'Block ratio:':<30} {b['block_ratio']:>10.1%}")
        print(f"{'Pass ratio:':<30} {b['pass_ratio']:>10.1%}")
        
        if b['block_ratio'] > 0.7:
            print(self._colorize("   🔴 HIGH BLOCK RATE - Suspicious activity!", "RED"))
        
        # Port analysis
        print()
        self.print_separator("PORT ANALYSIS", "─", 80, "BLUE")
        print(f"{'Avg src port:':<30} {b['avg_src_port']:>10.1f}")
        print(f"{'Avg dst port:':<30} {b['avg_dst_port']:>10.1f}")
        print(f"{'Port diversity (std):':<30} {b['dst_port_diversity']:>10.1f}")
        print(f"{'High risk port ratio:':<30} {b['high_risk_port_ratio']:>10.1%}")
        
        if b['high_risk_port_ratio'] > 0.5:
            print(self._colorize("   🔴 TARGETING HIGH-RISK SERVICES!", "RED"))
        
        # Protocol distribution
        print()
        self.print_separator("PROTOCOL DISTRIBUTION", "─", 80, "BLUE")
        print(f"{'TCP ratio:':<30} {b['tcp_ratio']:>10.1%}")
        print(f"{'UDP ratio:':<30} {b['udp_ratio']:>10.1%}")
        print(f"{'ICMP ratio:':<30} {b['icmp_ratio']:>10.1%}")
        
        # Packet analysis
        print()
        self.print_separator("PACKET ANALYSIS", "─", 80, "BLUE")
        print(f"{'Avg packet length:':<30} {b['avg_packet_length']:>10.1f} bytes")
        print(f"{'Packet length std:':<30} {b['packet_length_std']:>10.1f}")
        print(f"{'Avg TTL:':<30} {b['avg_ttl']:>10.1f}")
        
        # Behavioral flags
        print()
        self.print_separator("BEHAVIORAL FLAGS", "─", 80, "YELLOW")
        
        flags = []
        if b['unique_dst_ports'] > 50:
            flags.append("🚨 PORT SCANNING")
        if b['connection_rate'] > 5:
            flags.append("🚨 BURST TRAFFIC")
        if b['block_ratio'] > 0.7:
            flags.append("🚨 HIGH DROP RATE")
        if b['high_risk_port_ratio'] > 0.5:
            flags.append("🚨 TARGETING HIGH-RISK SERVICES")
        
        if flags:
            for flag in flags:
                print(self._colorize(f"  {flag}", "RED"))
        else:
            print(self._colorize("  ✅ No suspicious behavioral flags", "GREEN"))
        
        self.print_separator()
    
    def print_comparison(self, data1: Any, data2: Any, label1: str = "Before", label2: str = "After"):
        """So sánh 2 data structures"""
        if not self.enabled:
            return
        
        self.print_header(f"COMPARISON: {label1} vs {label2}", "⚖️")
        
        print(self._colorize(f"📌 {label1}:", "CYAN"))
        print(json.dumps(data1, indent=2, default=str)[:500])
        
        print()
        print(self._colorize(f"📌 {label2}:", "MAGENTA"))
        print(json.dumps(data2, indent=2, default=str)[:500])
        
        self.print_separator()


# ==================== CÁCH SỬ DỤNG ====================
if __name__ == '__main__':
    from src.utils.logger import get_module_logger
    
    logger = get_module_logger("Test")
    debug = DebugLogger(logger, enabled=True)
    
    # Test log structure
    sample_log = {
        '@timestamp': '2024-01-15T10:30:00Z',
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': [50123, 50124, 50125],  # List!
        'dst_port': 443,
        'proto_name': 'tcp',
        'action': 'pass',
        'length': 1500,
        'very_long_string': 'a' * 150
    }
    
    debug.print_log_structure(sample_log, "TEST LOG WITH ISSUES")
    
    # Test DataFrame
    df = pd.DataFrame({
        'src_port': [50123, 50124, 50125],
        'dst_port': [443, 80, 22],
        'action': ['pass', 'block', 'pass']
    })
    
    debug.print_dataframe_info(df, "TEST DATAFRAME")