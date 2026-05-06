#!/usr/bin/env python3
"""
ids_detector.py - Module thu thập và phân tích luồng dữ liệu SDN
"""

import time
import requests
import math
     
from datetime import datetime
from collections import defaultdict, deque

# Import module mitigation để tự động chặn attacker
try:
    from mitigation import block_ip, log as mitig_log
    MITIGATION_ENABLED = True
except ImportError:
    MITIGATION_ENABLED = False
    def block_ip(*args, **kwargs): pass
    def mitig_log(*args, **kwargs): pass

# ============================================================================
# CẤU HÌNH HỆ THỐNG
# ============================================================================

RYU_API_URL = f"http://127.0.0.1:8080/stats/flow/1"
POLL_INTERVAL = 5
TIMEOUT = 10

# Cấu hình phát hiện DDoS
MIN_TRAFFIC_VOL = 50       # Ngưỡng tối thiểu tổng packets để phân tích
ENTROPY_THRESHOLD = 1.0    # Ngưỡng cảnh báo DDoS

# Cấu hình phát hiện Port Scan
PORT_SCAN_THRESHOLD = 10   # Ngưỡng số lượng dst port khác nhau để cảnh báo

# ============================================================================
# HÀM TIỆN ÍCH
# ============================================================================

def get_time():
    """Trả về chuỗi thời gian hiện tại."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(message, is_error=False):
    """In thông báo ra console kèm dấu thời gian."""
    prefix = "✖ LỖI:" if is_error else "! INFO:"
    print(f"[{get_time()}] {prefix} {message}")

# ============================================================================
# LOGIC CỐT LÕI
# ============================================================================

def fetch_flows():
    """Gửi request tới Ryu API và trả về danh sách flow thô."""
    try:
        res = requests.get(RYU_API_URL, timeout=TIMEOUT)
        res.raise_for_status()
        return res.json().get(1, [])
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
        dst_port = match.get("tcp_dst")

        if not src or not dst:
            continue

        parsed.append({
            "src": src,
            "dst": dst,
            "dst_port": int(dst_port) if dst_port else None,
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


def compute_delta_packets(current_flows, previous_state):
    """Tính lượng packet phát sinh mới giữa chu kỳ hiện tại và chu kỳ trước đó."""
    delta_by_src = defaultdict(int)
    new_state = {}

    for flow in current_flows:
        flow_key = (flow["src"], flow["dst"])
        current_pkts = flow["pkts"]
        prev_pkts = previous_state.get(flow_key, 0)

        delta = max(current_pkts - prev_pkts, 0)
        if delta > 0:
            delta_by_src[flow["src"]] += delta

        new_state[flow_key] = current_pkts

    return dict(delta_by_src), new_state


def calculate_entropy(ip_packet_counts):
    """Tính Shannon Entropy từ phân bố packet theo IP nguồn."""
    total = sum(ip_packet_counts.values())
    if total == 0:
        return 0.0

    entropy = 0.0
    for count in ip_packet_counts.values():
        if count <= 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def analyze_ddos(sliding_window):
    """Tổng hợp dữ liệu từ cửa sổ trượt và phân tích entropy."""
    # Tổng hợp lưu lượng theo IP nguồn
    aggregated = defaultdict(int)
    for cycle_data in sliding_window:
        for src_ip, pkts in cycle_data.items():
            aggregated[src_ip] += pkts

    total_packets = sum(aggregated.values())

    # Kiểm tra ngưỡng lưu lượng tối thiểu
    if total_packets < MIN_TRAFFIC_VOL:
        log(f"Tổng traffic trong cửa sổ = {total_packets} pkts (< {MIN_TRAFFIC_VOL}). Bỏ qua phân tích.")
        return

    entropy = calculate_entropy(aggregated)
    num_sources = len(aggregated)

    print(f"\n{'═' * 65}")
    print(f"  [ENTROPY ANALYSIS] Cửa sổ {len(sliding_window)} chu kỳ | Tổng: {total_packets:,} pkts | Số IP nguồn: {num_sources}")
    print(f"  Shannon Entropy = {entropy:.4f} (Ngưỡng cảnh báo: < {ENTROPY_THRESHOLD})")

    if entropy < ENTROPY_THRESHOLD:
        print(f" * CẢNH BÁO DDoS! Traffic tập trung từ ít nguồn")
        # Liệt kê top IP nguồn đáng ngờ
        sorted_ips = sorted(aggregated.items(), key=lambda x: x[1], reverse=True)
        print(f"  {'-' * 42}")
        print(f"  {'IP Nguồn':<20} {'Packets':>10} {'Tỷ lệ':>10}")
        print(f"  {'-' * 42}")
        for ip, pkts in sorted_ips[:5]:
            ratio = pkts / total_packets * 100
            print(f"  {ip:<20} {pkts:>10,} {ratio:>9.1f}%")

        # Tự động chặn các IP nghi ngờ (top 3)
        if MITIGATION_ENABLED:
            suspicious_ips = [ip for ip, _ in sorted_ips[:3]]
            print(f"  Đang chặn các IP nghi ngờ: {suspicious_ips}")
            for ip, _ in sorted_ips[:3]:
                block_ip(ip)
    else:
        print(f"   Trạng thái: BÌNH THƯỜNG")

    print(f"{'═' * 65}")


def analyze_port_scan(flows):
    """Phát hiện Port Scan dựa trên số lượng dst port khác nhau từ cùng 1 src IP."""
    # Gom nhóm dst_port theo src_ip
    src_dst_ports = defaultdict(set)

    for flow in flows:
        src = flow.get("src")
        dst_port = flow.get("dst_port")

        if src and dst_port:
            src_dst_ports[src].add(dst_port)

    # Phát hiện port scan
    for src_ip, ports in src_dst_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            print(f"\n{'═' * 65}")
            print(f"  [PORT SCAN DETECTED] Nguồn: {src_ip}")
            print(f"  Số lượng cổng đích quét: {len(ports)} (Ngưỡng: {PORT_SCAN_THRESHOLD})")
            print(f"  Danh sách cổng: {sorted(ports)}")
            print(f"  Khuyến nghị: Block IP {src_ip}")
            print(f"{'═' * 65}")

# ============================================================================
# VÒNG LẶP CHÍNH
# ============================================================================

def main():
    print("═" * 65)
    print("SDN-IDS: IDS DETECTION MODULE".center(65))
    print("═" * 65)
    print(f" API Endpoint               : {RYU_API_URL}")
    print(f" Chu kỳ polling             : {POLL_INTERVAL}s")
    print(f" Cửa sổ trượt               : 4 chu kỳ ({4 * POLL_INTERVAL}s)")
    print(f" Ngưỡng Entropy             : {ENTROPY_THRESHOLD}")
    print(f" Ngưỡng Traffic tối thiểu   : {MIN_TRAFFIC_VOL} pkts")
    print(f" Ngưỡng Port Scan           : {PORT_SCAN_THRESHOLD} ports")
    print("═" * 65 + "\n")

    # Trạng thái lưu packet_count của chu kỳ trước
    previous_state = {}
    # Cửa sổ trượt lưu delta packets của 4 chu kỳ gần nhất
    sliding_window = deque(maxlen=4)
    # Cửa sổ trượt lưu flows cho port scan detection
    flow_window = deque(maxlen=4)

    try:
        while True:
            raw_flows = fetch_flows()

            if raw_flows is not None:
                parsed = parse_flows(raw_flows)
                display_flows(parsed)

                # Tính delta packets và đẩy vào cửa sổ trượt
                delta, previous_state = compute_delta_packets(parsed, previous_state)
                sliding_window.append(delta)

                # Lưu flows vào cửa sổ trượt cho port scan
                flow_window.append(parsed)

                # Phân tích khi cửa sổ đã đầy
                if len(sliding_window) == 4:
                    analyze_ddos(sliding_window)
                    # Gom tất cả flows trong cửa sổ để phát hiện port scan
                    all_flows = []
                    for flows in flow_window:
                        all_flows.extend(flows)
                    analyze_port_scan(all_flows)
                else:
                    log(f"Đang nạp dữ liệu...({len(sliding_window)}/4 chu kỳ)")

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n[{get_time()}] Dừng chương trình.")

if __name__ == "__main__":
    main()