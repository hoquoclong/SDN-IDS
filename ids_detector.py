#!/usr/bin/env python3
"""
ids_detector.py - Module thu thập và phân tích luồng dữ liệu SDN
"""

import time
import requests
from datetime import datetime

# ============================================================================
# CẤU HÌNH HỆ THỐNG
# ============================================================================

DPID = "1"
RYU_API_URL = f"http://127.0.0.1:8080/stats/flow/{DPID}"
POLL_INTERVAL = 5
TIMEOUT = 10

# ============================================================================
# HÀM TIỆN ÍCH
# ============================================================================

def get_time():
    """Trả về chuỗi thời gian hiện tại."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(message, is_error=False):
    """In thông báo ra console kèm dấu thời gian."""
    prefix = "LỖI:" if is_error else "ℹ INFO:"
    print(f"[{get_time()}] {prefix} {message}")

# ============================================================================
# LOGIC CỐT LÕI
# ============================================================================

def fetch_flows():
    """Gửi request tới Ryu API và trả về danh sách flow thô."""
    try:
        res = requests.get(RYU_API_URL, timeout=TIMEOUT)
        res.raise_for_status()
        return res.json().get(DPID, [])
    except requests.exceptions.RequestException as e:
        log(f"Lỗi kết nối Ryu Controller ({RYU_API_URL}) - Chi tiết: {e}", is_error=True)
        return []

def parse_flows(raw_flows):
    """Lọc flow rác và trích xuất lưu lượng IPv4."""
    parsed = []
    
    for flow in raw_flows:
        match = flow.get("match", {})
        src = match.get("ipv4_src")
        dst = match.get("ipv4_dst")

        if not src or not dst:
            continue

        parsed.append({
            "src": src,
            "dst": dst,
            "pkts": flow.get("packet_count", 0),
            "bytes": flow.get("byte_count", 0),
        })
        
    return parsed

def display_flows(flows):
    """Định dạng và in bảng thống kê luồng dữ liệu."""
    print(f"\n[{get_time()}] Thu thập được {len(flows)} IPv4 flow(s)")
    print("-" * 65)

    if not flows:
        print("  (Không có traffic IPv4)")
        return

    # In Header
    print(f"  {'Nguồn':<18} → {'Đích':<18} {'Packets':>10} {'Bytes':>12}")
    print("-" * 65)
    
    # In dữ liệu
    for f in flows:
        print(f"  {f['src']:<18} → {f['dst']:<18} {f['pkts']:>10,} {f['bytes']:>12,}")
    print("-" * 65)

# ============================================================================
# VÒNG LẶP CHÍNH
# ============================================================================

def main():
    print("═" * 65)
    print(" SDN-IDS: DATA POLLING MODULE ".center(65))
    print("═" * 65)
    print(f" API Endpoint : {RYU_API_URL}")
    print(f" Chu kỳ       : {POLL_INTERVAL}s")
    print("═" * 65 + "\n")

    try:
        while True:
            raw_flows = fetch_flows()
            
            if raw_flows is not None:
                parsed = parse_flows(raw_flows)
                display_flows(parsed)
                
            time.sleep(POLL_INTERVAL)
            
    except KeyboardInterrupt:
        print(f"\n[{get_time()}] Đã dừng chương trình.")

if __name__ == "__main__":
    main()