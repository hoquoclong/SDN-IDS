#!/usr/bin/env python3
"""
ids_detector.py - Module thu thập và phân tích luồng dữ liệu SDN
"""

import time
import requests
import math
import sys
import codecs
     
from datetime import datetime
from collections import defaultdict, deque

if sys.stdout.encoding != 'utf-8':
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

# Import module mitigation để tự động chặn attacker
try:
    from mitigation import block_ip, log as mitig_log
    MITIGATION_ENABLED = True
except ImportError:
    MITIGATION_ENABLED = False
    def block_ip(*args, **kwargs) -> bool: return False
    def mitig_log(*args, **kwargs): pass

# ============================================================================
# CẤU HÌNH ALERT LOG
# ============================================================================

ALERT_LOG_FILE = "alerts.log"

def write_alert_log(alert_data):
    """
    Ghi alert vào file alerts.log (append mode, JSON format).
    
    Args:
        alert_data: dict chứa thông tin alert
    """
    import json
    try:
        with open(ALERT_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(alert_data, ensure_ascii=False) + '\n')
    except IOError as e:
        log(f"Lỗi ghi alert log: {e}", is_error=True)

# ============================================================================
# CẤU HÌNH HỆ THỐNG
# ============================================================================

RYU_API_URL = f"http://127.0.0.1:8080/stats/flow/1"
POLL_INTERVAL = 5
TIMEOUT = 10

# Cấu hình phát hiện DDoS
MIN_TRAFFIC_VOL = 50       # Ngưỡng tối thiểu tổng packets để phân tích
DDOS_TRAFFIC_VOL = 1000    # Ngưỡng packet trong cửa sổ để cảnh báo DoS/DDoS
ENTROPY_THRESHOLD = 1.5    # Ngưỡng cảnh báo DDoS (Source)
DST_ENTROPY_THRESHOLD = 1.5 # Ngưỡng cảnh báo DDoS phân tán (Destination)
MIN_DDOS_SOURCES = 2       # Số nguồn tối thiểu cùng dồn vào 1 đích để coi là DDoS phân tán
ATTACKER_MIN_RATIO = 0.01  # Nguồn phải chiếm tối thiểu 1% traffic liên quan để bị coi đáng ngờ

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
        data = res.json()
        return data.get("1", data.get(1, []))
    except requests.exceptions.RequestException as e:
        log(f"Lỗi kết nối Ryu Controller ({RYU_API_URL}) - Chi tiết: {e}", is_error=True)
        return []

def mac_to_ip(mac):
    if not mac or not mac.startswith("00:00:00:00:00:"):
        return None
    suffix = int(mac.split(":")[-1])
    return f"10.0.0.{suffix}"

def parse_flows(raw_flows):
    """Lọc flow rác và trích xuất lưu lượng IPv4."""
    parsed = []
    
    for flow in raw_flows:
        match = flow.get("match", {})
        src = match.get("ipv4_src") or mac_to_ip(match.get("eth_src")) or mac_to_ip(match.get("dl_src"))
        dst = match.get("ipv4_dst") or mac_to_ip(match.get("eth_dst")) or mac_to_ip(match.get("dl_dst"))
        dst_port = match.get("tcp_dst") or match.get("udp_dst")

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

    # Sắp xếp theo số lượng packets giảm dần và lấy top 10
    sorted_flows = sorted(flows, key=lambda x: x['pkts'], reverse=True)[:10]

    # In Header
    print(f"  {'Nguồn':<18} → {'Đích':<18} {'Packets':>10} {'Bytes':>12}")
    print("-" * 65)
    
    # In dữ liệu
    for f in sorted_flows:
        print(f"  {f['src']:<18} → {f['dst']:<18} {f['pkts']:>10,} {f['bytes']:>12,}")
    print("-" * 65)


def compute_delta_packets(current_flows, previous_state):
    """Tính lượng packet phát sinh mới giữa chu kỳ hiện tại và chu kỳ trước đó."""
    delta_by_src = defaultdict(int)
    delta_by_dst = defaultdict(int)
    delta_by_pair = defaultdict(int)
    new_state = {}

    for flow in current_flows:
        flow_key = (flow["src"], flow["dst"])
        current_pkts = flow["pkts"]
        prev_pkts = previous_state.get(flow_key, 0)

        delta = max(current_pkts - prev_pkts, 0)
        if delta > 0:
            delta_by_src[flow["src"]] += delta
            delta_by_dst[flow["dst"]] += delta
            delta_by_pair[flow_key] += delta

        new_state[flow_key] = current_pkts

    return {
        "src": dict(delta_by_src),
        "dst": dict(delta_by_dst),
        "pairs": dict(delta_by_pair),
    }, new_state


def calculate_entropy(ip_packet_counts):
    """Tính Shannon Entropy từ phân bố packet theo IP."""
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


def aggregate_window(sliding_window):
    """Tổng hợp dữ liệu từ cửa sổ trượt và phân tích entropy."""
    aggregated_src = defaultdict(int)
    aggregated_dst = defaultdict(int)
    aggregated_pairs = defaultdict(int)

    for cycle_data in sliding_window:
        for src_ip, pkts in cycle_data["src"].items():
            aggregated_src[src_ip] += pkts
        for dst_ip, pkts in cycle_data["dst"].items():
            aggregated_dst[dst_ip] += pkts
        for pair, pkts in cycle_data.get("pairs", {}).items():
            aggregated_pairs[pair] += pkts

    return aggregated_src, aggregated_dst, aggregated_pairs


def choose_victim_ip(aggregated_dst):
    """Chọn IP đích nhận nhiều packet nhất trong cửa sổ."""
    if not aggregated_dst:
        return None
    return max(aggregated_dst.items(), key=lambda x: x[1])[0]


def get_inbound_attackers(aggregated_pairs, victim_ip):
    """Tính packet theo nguồn chỉ trên hướng source -> victim."""
    inbound_by_src = defaultdict(int)

    if not victim_ip:
        return inbound_by_src

    for (src_ip, dst_ip), pkts in aggregated_pairs.items():
        if dst_ip == victim_ip and src_ip != victim_ip:
            inbound_by_src[src_ip] += pkts

    return inbound_by_src


def get_directional_dst_counts(aggregated_pairs, victim_ip):
    """
    Tính entropy đích theo hướng nghi vấn, bỏ chiều victim -> client/attacker.
    Điều này tránh làm DDoS phân tán bị chìm khi victim phản hồi nhiều packet.
    """
    directional_dst = defaultdict(int)

    for (src_ip, dst_ip), pkts in aggregated_pairs.items():
        if victim_ip and src_ip == victim_ip:
            continue
        directional_dst[dst_ip] += pkts

    return directional_dst


def filter_significant_sources(source_counts, total_packets):
    """Loại các nguồn nhiễu quá nhỏ trước khi phân loại và mitigation."""
    if total_packets <= 0:
        return {}

    return {
        ip: pkts
        for ip, pkts in source_counts.items()
        if pkts / total_packets >= ATTACKER_MIN_RATIO
    }


def analyze_ddos(sliding_window, all_flows=None):
    """Tổng hợp dữ liệu từ cửa sổ trượt và phân tích DoS/DDoS bằng entropy."""
    aggregated_src, aggregated_dst, aggregated_pairs = aggregate_window(sliding_window)

    total_packets = sum(aggregated_src.values())

    if total_packets < MIN_TRAFFIC_VOL:
        log(f"Tổng traffic trong cửa sổ = {total_packets} pkts (< {MIN_TRAFFIC_VOL}). Bỏ qua phân tích.")
        return

    src_entropy = calculate_entropy(aggregated_src)
    victim_ip = choose_victim_ip(aggregated_dst)
    directional_dst = get_directional_dst_counts(aggregated_pairs, victim_ip)
    dst_entropy = calculate_entropy(directional_dst)
    inbound_attackers = get_inbound_attackers(aggregated_pairs, victim_ip)
    victim_packets = sum(inbound_attackers.values())
    significant_inbound_attackers = filter_significant_sources(inbound_attackers, victim_packets)
    significant_sources = filter_significant_sources(aggregated_src, total_packets)
    num_sources = len(aggregated_src)
    num_dsts = len(directional_dst)
    num_attack_sources = len(significant_inbound_attackers)
    is_dos = src_entropy < ENTROPY_THRESHOLD and total_packets >= DDOS_TRAFFIC_VOL
    is_distributed_ddos = (
        dst_entropy < DST_ENTROPY_THRESHOLD
        and victim_packets >= DDOS_TRAFFIC_VOL
        and num_attack_sources >= MIN_DDOS_SOURCES
    )

    print(f"\n{'=' * 65}")
    print(f"  [ENTROPY ANALYSIS] Cửa sổ {len(sliding_window)} chu kỳ | Tổng: {total_packets:,} pkts")
    print(f"  Source Entropy      = {src_entropy:.4f} (IP nguồn: {num_sources}) - Ngưỡng < {ENTROPY_THRESHOLD}")
    print(f"  Destination Entropy = {dst_entropy:.4f} (IP đích hướng vào: {num_dsts}) - Ngưỡng < {DST_ENTROPY_THRESHOLD}")

    if is_distributed_ddos or is_dos:
        attack_type = "Distributed_DDoS" if is_distributed_ddos else "DoS"
        reason = "Destination entropy thấp: nhiều nguồn cùng dồn vào một đích" if is_distributed_ddos else "Source entropy thấp: traffic tập trung từ ít nguồn"
        print(f" * CẢNH BÁO {attack_type}! Traffic bất thường được phát hiện")
        print(f"   -> Lý do: {reason}")

        if victim_ip:
            print(f"   -> Đã nhận diện Victim IP (dự kiến): {victim_ip}")
            print(f"   -> Packet hướng vào victim: {victim_packets:,} từ {num_attack_sources} nguồn")

        # Liệt kê top IP nguồn đáng ngờ
        attacker_scores = significant_inbound_attackers if is_distributed_ddos else significant_sources
        sorted_ips = sorted(attacker_scores.items(), key=lambda x: x[1], reverse=True)
        print(f"  {'-' * 42}")
        print(f"  {'IP Nguồn':<20} {'Packets':>10} {'Tỷ lệ':>10}")
        print(f"  {'-' * 42}")
        for ip, pkts in sorted_ips[:5]:
            note = "(VICTIM)" if ip == victim_ip else ""
            ratio_base = victim_packets if is_distributed_ddos else total_packets
            ratio = pkts / ratio_base * 100 if ratio_base else 0
            print(f"  {ip:<20} {pkts:>10,} {ratio:>9.1f}% {note}")
        
        # Ghi alert log
        alert_data = {
            "timestamp": get_time(),
            "attack_type": attack_type,
            "victim_ip": victim_ip,
            "attacker_ips": [{"ip": ip, "packets": pkts} for ip, pkts in sorted_ips[:3]],
            "total_packets": total_packets,
            "src_entropy": round(src_entropy, 4),
            "dst_entropy": round(dst_entropy, 4),
            "reason": reason,
            "message": f"{attack_type} detected! Victim={victim_ip}, Src_Ent={src_entropy:.4f}, Dst_Ent={dst_entropy:.4f}"
        }
        write_alert_log(alert_data)

        # Tự động chặn các IP nghi ngờ (top 3)
        if MITIGATION_ENABLED:
            suspicious_ips = [ip for ip, _ in sorted_ips if ip != victim_ip][:3]
            print(f"  Đang chặn các IP nghi ngờ: {suspicious_ips}")
            for ip in suspicious_ips:
                block_ip(ip)
    else:
        print(f"   Trạng thái: BÌNH THƯỜNG")

    print(f"{'=' * 65}")


def analyze_port_scan(flows):
    """Phát hiện Port Scan dựa trên số lượng dst port khác nhau từ cùng 1 src IP đến cùng 1 đích."""
    # Gom nhóm dst_port theo cặp (src_ip, dst_ip)
    src_dst_ports = defaultdict(set)

    for flow in flows:
        src = flow.get("src")
        dst = flow.get("dst")
        dst_port = flow.get("dst_port")

        if src and dst and dst_port:
            src_dst_ports[(src, dst)].add(dst_port)

    # Phát hiện port scan
    for (src_ip, dst_ip), ports in src_dst_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            print(f"\n{'=' * 65}")
            print(f"  [PORT SCAN DETECTED] Nguồn: {src_ip} -> Đích: {dst_ip}")
            print(f"  Số lượng cổng đích quét: {len(ports)} (Ngưỡng: {PORT_SCAN_THRESHOLD})")
            print(f"  Danh sách cổng: {sorted(ports)}")
            print(f"  Khuyến nghị: Block IP {src_ip}")
            print(f"{'=' * 65}")

            # Tự động chặn IP port scan
            if MITIGATION_ENABLED:
                print(f"  Đang chặn IP {src_ip}...")
                block_ip(src_ip)
            # Ghi alert log cho port scan
            alert_data = {
                "timestamp": get_time(),
                "attack_type": "Port_Scan",
                "attacker_ip": src_ip,
                "victim_ip": dst_ip,
                "ports_scanned": sorted(list(ports)),
                "num_ports": len(ports),
                "message": f"Port Scan detected from {src_ip} to {dst_ip}: {len(ports)} ports"
            }
            write_alert_log(alert_data)

# ============================================================================
# VÒNG LẶP CHÍNH
# ============================================================================

def main():
    print("=" * 65)
    print("SDN-IDS: IDS DETECTION MODULE".center(65))
    print("=" * 65)
    print(f" API Endpoint               : {RYU_API_URL}")
    print(f" Chu kỳ polling             : {POLL_INTERVAL}s")
    print(f" Cửa sổ trượt               : 4 chu kỳ ({4 * POLL_INTERVAL}s)")
    print(f" Ngưỡng Entropy             : {ENTROPY_THRESHOLD}")
    print(f" Ngưỡng Traffic tối thiểu   : {MIN_TRAFFIC_VOL} pkts")
    print(f" Ngưỡng Traffic cảnh báo    : {DDOS_TRAFFIC_VOL} pkts")
    print(f" Ngưỡng Port Scan           : {PORT_SCAN_THRESHOLD} ports")
    print("=" * 65 + "\n")

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
                    # Gom tất cả flows trong cửa sổ
                    all_flows = []
                    for flows in flow_window:
                        all_flows.extend(flows)
                        
                    analyze_ddos(sliding_window, all_flows)
                    analyze_port_scan(all_flows)
                else:
                    log(f"Đang nạp dữ liệu...({len(sliding_window)}/4 chu kỳ)")

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n[{get_time()}] Dừng chương trình.")

if __name__ == "__main__":
    main()
