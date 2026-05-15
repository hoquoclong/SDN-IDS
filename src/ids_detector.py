#!/usr/bin/env python3
"""
ids_detector.py - Module thu thập và phân tích luồng dữ liệu SDN
"""

import time
import requests
import math
import sys
import codecs
import os
import json
import ipaddress

from datetime import datetime
from collections import defaultdict, deque

if sys.stdout.encoding != 'utf-8':
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

MITIGATION_DISABLED_ENV = "IDS_DISABLE_MITIGATION"

# Import module mitigation để tự động chặn attacker
try:
    from mitigation import block_ip, log as mitig_log
    MITIGATION_ENABLED = os.getenv(MITIGATION_DISABLED_ENV, "").strip().lower() not in {"1", "true", "yes", "on"}
except ImportError:
    MITIGATION_ENABLED = False
    def block_ip(*args, **kwargs) -> bool: return False
    def mitig_log(*args, **kwargs): pass

# ============================================================================
# CẤU HÌNH HỆ THỐNG
# ============================================================================

RYU_API_URL = f"http://127.0.0.1:8080/stats/flow/1"
POLL_INTERVAL = 5
TIMEOUT = 10
DEFAULT_PROTECTED_IPS = {"10.0.0.1"}
PROTECTED_IPS_ENV = "IDS_PROTECTED_IPS"
ALERT_LOG_FILE = "alerts.log"
ALERT_LOG_FILE_ENV = "IDS_ALERT_LOG_FILE"
DEFAULT_TRAFFIC_UNIT = "packets"

# Cấu hình phát hiện DDoS
MIN_TRAFFIC_VOL = 50       # Ngưỡng tối thiểu tổng packets để phân tích
DDOS_TRAFFIC_VOL = 1000    # Ngưỡng packet trong cửa sổ để cảnh báo DoS/DDoS
ENTROPY_THRESHOLD = 1.5    # Ngưỡng cảnh báo DDoS (Source)
DST_ENTROPY_THRESHOLD = 1.5 # Ngưỡng cảnh báo DDoS phân tán (Destination)
MIN_DDOS_SOURCES = 2       # Số nguồn tối thiểu cùng dồn vào 1 đích để coi là DDoS phân tán
ATTACKER_MIN_RATIO = 0.01  # Nguồn phải chiếm tối thiểu 1% traffic liên quan để bị coi đáng ngờ

# Cấu hình phát hiện Port Scan
PORT_SCAN_THRESHOLD = 10   # Ngưỡng số lượng dst port khác nhau để cảnh báo
PORT_SCAN_PPS_THRESHOLD = 30
PORT_SCAN_MAX_PPS = 500
PORT_SCAN_MIN_PACKETS = 100

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


def safe_int(value, default=0):
    """Chuyển giá trị số từ Ryu REST API về int, kể cả khi API trả None."""
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_alert_log_file(log_file=None):
    return log_file or os.getenv(ALERT_LOG_FILE_ENV, ALERT_LOG_FILE)


def _first_attacker_ip(alert_data):
    attacker_ip = alert_data.get("attacker_ip")
    if attacker_ip:
        return attacker_ip

    attacker_ips = alert_data.get("attacker_ips") or []
    for item in attacker_ips:
        if isinstance(item, dict) and item.get("ip"):
            return item["ip"]
        if isinstance(item, str) and item:
            return item
    return None


def _traffic_volume(alert_data):
    for key in ("traffic_volume", "packets", "total_packets"):
        value = alert_data.get(key)
        if value is not None:
            return value
    return 0


def normalize_alert(alert_data):
    """Chuẩn hóa alert nhưng vẫn giữ các field chi tiết cũ."""
    alert = dict(alert_data)
    attack_type = alert.get("attack_type") or "UNKNOWN"
    attacker_ip = _first_attacker_ip(alert)
    traffic_volume = _traffic_volume(alert)
    message = alert.get("message") or f"{attack_type} detected"

    normalized = {
        "timestamp": alert.get("timestamp") or get_time(),
        "attack_type": attack_type,
        "attacker_ip": attacker_ip,
        "traffic_volume": traffic_volume,
        "traffic_unit": alert.get("traffic_unit") or DEFAULT_TRAFFIC_UNIT,
        "message": message,
    }

    for key, value in alert.items():
        if key not in normalized:
            normalized[key] = value
    return normalized


def write_alert_log(alert_data):
    """Ghi alert đã chuẩn hóa vào alerts.log."""
    try:
        normalized = normalize_alert(alert_data)
        with open(get_alert_log_file(), "a", encoding="utf-8") as f:
            f.write(json.dumps(normalized, ensure_ascii=False) + "\n")
        return normalized
    except IOError as e:
        log(f"Lỗi ghi alert log: {e}", is_error=True)
        return None


def read_alert_log(log_file=None):
    path = get_alert_log_file(log_file)
    if not os.path.exists(path):
        return []

    alerts = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts


def load_protected_ips(env_value=None):
    """Đọc danh sách IP victim/server cần bảo vệ từ biến môi trường."""
    raw_value = os.getenv(PROTECTED_IPS_ENV, "") if env_value is None else env_value
    if not raw_value.strip():
        return set(DEFAULT_PROTECTED_IPS)

    protected_ips = set()
    for item in raw_value.split(","):
        ip = item.strip()
        if not ip:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            log(f"Bỏ qua IP không hợp lệ trong {PROTECTED_IPS_ENV}: {ip}", is_error=True)
            continue
        protected_ips.add(ip)

    return protected_ips or set(DEFAULT_PROTECTED_IPS)


PROTECTED_IPS = load_protected_ips()


def get_protected_ips(protected_ips=None):
    return PROTECTED_IPS if protected_ips is None else set(protected_ips)


def is_protected_ip(ip, protected_ips=None):
    return ip in get_protected_ips(protected_ips)


def should_block_ip(ip, protected_ips=None):
    """Không bao giờ block IP victim/server được bảo vệ."""
    return bool(ip) and not is_protected_ip(ip, protected_ips)


def safe_block_ip(ip, blocked_ips=None, protected_ips=None):
    """Block IP sau khi đã guard protected IP và tránh block trùng trong cùng chu kỳ."""
    if not should_block_ip(ip, protected_ips):
        log(f"Bỏ qua block IP được bảo vệ: {ip}")
        return False

    if blocked_ips is not None and ip in blocked_ips:
        log(f"Bỏ qua block trùng trong cùng chu kỳ: {ip}")
        return False

    blocked = block_ip(ip)
    if blocked and blocked_ips is not None:
        blocked_ips.add(ip)
    return blocked

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
            "dst_port": safe_int(dst_port) if dst_port else None,
            "pkts": safe_int(flow.get("packet_count")),
            "bytes": safe_int(flow.get("byte_count")),
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
        flow_key = (flow["src"], flow["dst"], flow.get("dst_port"))
        pair_key = (flow["src"], flow["dst"])
        current_pkts = safe_int(flow.get("pkts"))
        prev_pkts = safe_int(previous_state.get(flow_key))

        delta = max(current_pkts - prev_pkts, 0)
        if delta > 0:
            delta_by_src[flow["src"]] += delta
            delta_by_dst[flow["dst"]] += delta
            delta_by_pair[pair_key] += delta

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


def choose_victim_ip(aggregated_dst, protected_ips=None):
    """Chọn IP đích nhận nhiều packet nhất trong cửa sổ."""
    if not aggregated_dst:
        return None

    protected_ips = get_protected_ips(protected_ips)
    protected_dst = {
        ip: pkts
        for ip, pkts in aggregated_dst.items()
        if ip in protected_ips
    }
    if protected_dst:
        return max(protected_dst.items(), key=lambda x: x[1])[0]

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


def get_rate_scan_candidates(aggregated_pairs, window_seconds, protected_ips=None):
    """Tìm các cặp src -> protected dst có tốc độ giống port scan."""
    if window_seconds is None or window_seconds <= 0:
        return {}

    protected_ips = get_protected_ips(protected_ips)
    candidates = {}
    for (src_ip, dst_ip), packets in aggregated_pairs.items():
        packets = safe_int(packets)
        if src_ip in protected_ips or dst_ip not in protected_ips:
            continue

        pps = packets / window_seconds
        if PORT_SCAN_MIN_PACKETS <= packets and PORT_SCAN_PPS_THRESHOLD <= pps <= PORT_SCAN_MAX_PPS:
            candidates[(src_ip, dst_ip)] = {"packets": packets, "pps": pps}

    return candidates


def has_port_count_evidence(flows, victim_ip, protected_ips=None):
    """Kiểm tra có bằng chứng scan theo số port tới victim được bảo vệ hay không."""
    if not flows or not victim_ip:
        return False

    protected_ips = get_protected_ips(protected_ips)
    ports_by_pair = defaultdict(set)
    for flow in flows:
        src = flow.get("src")
        dst = flow.get("dst")
        dst_port = flow.get("dst_port")
        if src in protected_ips or dst != victim_ip or not dst_port:
            continue
        ports_by_pair[(src, dst)].add(dst_port)

    return any(len(ports) >= PORT_SCAN_THRESHOLD for ports in ports_by_pair.values())


def analyze_ddos(sliding_window, all_flows=None, protected_ips=None, blocked_ips=None):
    """Tổng hợp dữ liệu từ cửa sổ trượt và phân tích DoS/DDoS bằng entropy."""
    protected_ips = get_protected_ips(protected_ips)
    aggregated_src, aggregated_dst, aggregated_pairs = aggregate_window(sliding_window)

    total_packets = sum(aggregated_src.values())
    result = {"detected": False, "attack_type": None, "victim_ip": None}

    if total_packets < MIN_TRAFFIC_VOL:
        log(f"Tổng traffic trong cửa sổ = {total_packets} pkts (< {MIN_TRAFFIC_VOL}). Bỏ qua phân tích.")
        return result

    src_entropy = calculate_entropy(aggregated_src)
    victim_ip = choose_victim_ip(aggregated_dst, protected_ips)
    directional_dst = get_directional_dst_counts(aggregated_pairs, victim_ip)
    dst_entropy = calculate_entropy(directional_dst)
    inbound_attackers = get_inbound_attackers(aggregated_pairs, victim_ip)
    victim_packets = sum(inbound_attackers.values())
    significant_inbound_attackers = filter_significant_sources(inbound_attackers, victim_packets)
    num_sources = len(aggregated_src)
    num_dsts = len(directional_dst)
    num_attack_sources = len(significant_inbound_attackers)
    window_seconds = len(sliding_window) * POLL_INTERVAL
    rate_scan_candidates = get_rate_scan_candidates(aggregated_pairs, window_seconds, protected_ips)
    has_scan_evidence = (
        bool(rate_scan_candidates)
        or has_port_count_evidence(all_flows, victim_ip, protected_ips)
    )
    is_dos = (
        src_entropy < ENTROPY_THRESHOLD
        and victim_packets >= DDOS_TRAFFIC_VOL
        and not has_scan_evidence
    )
    is_distributed_ddos = (
        dst_entropy < DST_ENTROPY_THRESHOLD
        and victim_packets >= DDOS_TRAFFIC_VOL
        and num_attack_sources >= MIN_DDOS_SOURCES
        and not has_scan_evidence
    )

    print(f"\n{'=' * 65}")
    print(f"  [ENTROPY ANALYSIS] Cửa sổ {len(sliding_window)} chu kỳ | Tổng: {total_packets:,} pkts")
    print(f"  Source Entropy      = {src_entropy:.4f} (IP nguồn: {num_sources}) - Ngưỡng < {ENTROPY_THRESHOLD}")
    print(f"  Destination Entropy = {dst_entropy:.4f} (IP đích hướng vào: {num_dsts}) - Ngưỡng < {DST_ENTROPY_THRESHOLD}")

    if is_distributed_ddos or is_dos:
        attack_type = "Distributed_DDoS" if is_distributed_ddos else "DoS"
        reason = "Destination entropy thấp: nhiều nguồn cùng dồn vào một đích" if is_distributed_ddos else "Source entropy thấp: traffic tập trung từ ít nguồn"
        result = {"detected": True, "attack_type": attack_type, "victim_ip": victim_ip}
        print(f" * CẢNH BÁO {attack_type}! Traffic bất thường được phát hiện")
        print(f"   -> Lý do: {reason}")

        if victim_ip:
            print(f"   -> Đã nhận diện Victim IP (dự kiến): {victim_ip}")
            print(f"   -> Packet hướng vào victim: {victim_packets:,} từ {num_attack_sources} nguồn")

        # Liệt kê top IP nguồn đáng ngờ
        attacker_scores = significant_inbound_attackers
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
        top_attacker_ip = sorted_ips[0][0] if sorted_ips else None
        alert_data = {
            "timestamp": get_time(),
            "attack_type": attack_type,
            "attacker_ip": top_attacker_ip,
            "victim_ip": victim_ip,
            "attacker_ips": [{"ip": ip, "packets": pkts} for ip, pkts in sorted_ips[:3]],
            "traffic_volume": victim_packets,
            "traffic_unit": "packets",
            "total_packets": total_packets,
            "src_entropy": round(src_entropy, 4),
            "dst_entropy": round(dst_entropy, 4),
            "reason": reason,
            "message": f"{attack_type} detected! Victim={victim_ip}, Src_Ent={src_entropy:.4f}, Dst_Ent={dst_entropy:.4f}"
        }
        write_alert_log(alert_data)

        # Tự động chặn các IP nghi ngờ (top 3)
        if MITIGATION_ENABLED:
            suspicious_ips = [ip for ip, _ in sorted_ips if should_block_ip(ip, protected_ips)][:3]
            print(f"  Đang chặn các IP nghi ngờ: {suspicious_ips}")
            for ip in suspicious_ips:
                safe_block_ip(ip, blocked_ips, protected_ips)
    else:
        if has_scan_evidence:
            print("   Ghi chú: traffic phù hợp Port Scan, bỏ qua cảnh báo DoS để tránh nhầm chiều phản hồi.")
        print(f"   Trạng thái: BÌNH THƯỜNG")

    print(f"{'=' * 65}")
    return result


def analyze_port_scan(flows, sliding_window=None, ddos_result=None, protected_ips=None, blocked_ips=None):
    """Phát hiện Port Scan bằng số port, fallback bằng tốc độ gói tin theo cặp src -> dst."""
    protected_ips = get_protected_ips(protected_ips)
    aggregated_pairs = {}
    window_seconds = None
    if sliding_window:
        _, _, aggregated_pairs = aggregate_window(sliding_window)
        window_seconds = len(sliding_window) * POLL_INTERVAL

    # Gom nhóm dst_port theo cặp (src_ip, dst_ip)
    src_dst_ports = defaultdict(set)
    detected_pairs = set()

    for flow in flows:
        src = flow.get("src")
        dst = flow.get("dst")
        dst_port = flow.get("dst_port")

        if src and dst and dst_port and src not in protected_ips and dst in protected_ips:
            src_dst_ports[(src, dst)].add(dst_port)

    # Phát hiện port scan
    for (src_ip, dst_ip), ports in src_dst_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            packets = aggregated_pairs.get((src_ip, dst_ip), 0)
            print(f"\n{'=' * 65}")
            print(f"  [PORT SCAN DETECTED] Nguồn: {src_ip} -> Đích: {dst_ip}")
            print(f"  Số lượng cổng đích quét: {len(ports)} (Ngưỡng: {PORT_SCAN_THRESHOLD})")
            print(f"  Danh sách cổng: {sorted(ports)}")
            print(f"  Khuyến nghị: Block IP {src_ip}")
            print(f"{'=' * 65}")

            # Tự động chặn IP port scan
            if MITIGATION_ENABLED:
                print(f"  Đang chặn IP {src_ip}...")
                safe_block_ip(src_ip, blocked_ips, protected_ips)
            detected_pairs.add((src_ip, dst_ip))
            # Ghi alert log cho port scan
            alert_data = {
                "timestamp": get_time(),
                "attack_type": "Port_Scan",
                "attacker_ip": src_ip,
                "victim_ip": dst_ip,
                "traffic_volume": packets,
                "traffic_unit": "packets",
                "packets": packets,
                "pps": None,
                "window_seconds": window_seconds,
                "detection_method": "port_count",
                "ports_scanned": sorted(list(ports)),
                "num_ports": len(ports),
                "message": f"Port Scan detected from {src_ip} to {dst_ip}: {len(ports)} ports"
            }
            write_alert_log(alert_data)

    if not sliding_window:
        return

    if ddos_result and ddos_result.get("attack_type") == "Distributed_DDoS":
        log(f"Bỏ qua Port Scan theo packet-rate vì đã phát hiện {ddos_result.get('attack_type')}.")
        return

    if window_seconds is None or window_seconds <= 0:
        return

    scan_candidates = get_rate_scan_candidates(aggregated_pairs, window_seconds, protected_ips)
    for (src_ip, dst_ip), data in sorted(scan_candidates.items(), key=lambda item: item[1]["packets"], reverse=True):
        if (src_ip, dst_ip) in detected_pairs or src_ip == dst_ip:
            continue

        packets = data["packets"]
        pps = data["pps"]

        print(f"\n{'=' * 65}")
        print(f"  [SUSPECTED PORT SCAN - RATE] Nguồn: {src_ip} -> Đích: {dst_ip}")
        print(f"  Packets trong cửa sổ: {packets:,} | Tốc độ: {pps:.2f} pps")
        print(f"  Ngưỡng: >= {PORT_SCAN_MIN_PACKETS} pkts và {PORT_SCAN_PPS_THRESHOLD}-{PORT_SCAN_MAX_PPS} pps")
        print(f"  Khuyến nghị: Block IP {src_ip} (phát hiện theo tốc độ gói)")
        print(f"{'=' * 65}")

        if MITIGATION_ENABLED:
            print(f"  Đang chặn IP {src_ip}...")
            safe_block_ip(src_ip, blocked_ips, protected_ips)

        alert_data = {
            "timestamp": get_time(),
            "attack_type": "Suspected_Port_Scan_Rate",
            "attacker_ip": src_ip,
            "victim_ip": dst_ip,
            "traffic_volume": packets,
            "traffic_unit": "packets",
            "packets": packets,
            "pps": round(pps, 2),
            "window_seconds": window_seconds,
            "detection_method": "packet_rate",
            "message": f"Suspected Port Scan by packet rate from {src_ip} to {dst_ip}: {pps:.2f} pps"
        }
        write_alert_log(alert_data)

# ============================================================================
# VÒNG LẶP CHÍNH
# ============================================================================

def main():
    protected_ips = get_protected_ips()
    print("=" * 65)
    print("SDN-IDS: IDS DETECTION MODULE".center(65))
    print("=" * 65)
    print(f" API Endpoint               : {RYU_API_URL}")
    print(f" Protected IPs              : {', '.join(sorted(protected_ips))}")
    print(f" Chu kỳ polling             : {POLL_INTERVAL}s")
    print(f" Cửa sổ trượt               : 4 chu kỳ ({4 * POLL_INTERVAL}s)")
    print(f" Ngưỡng Entropy             : {ENTROPY_THRESHOLD}")
    print(f" Ngưỡng Traffic tối thiểu   : {MIN_TRAFFIC_VOL} pkts")
    print(f" Ngưỡng Traffic cảnh báo    : {DDOS_TRAFFIC_VOL} pkts")
    print(f" Ngưỡng Port Scan           : {PORT_SCAN_PPS_THRESHOLD}-{PORT_SCAN_MAX_PPS} pps / {PORT_SCAN_MIN_PACKETS} pkts")
    print(f" Alert log                  : {ALERT_LOG_FILE}")
    print(f" Mitigation                 : {'enabled' if MITIGATION_ENABLED else 'disabled'}")
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
                    blocked_this_cycle = set()
                    # Gom tất cả flows trong cửa sổ
                    all_flows = []
                    for flows in flow_window:
                        all_flows.extend(flows)
                        
                    ddos_result = analyze_ddos(sliding_window, all_flows, protected_ips, blocked_this_cycle)
                    analyze_port_scan(all_flows, sliding_window, ddos_result, protected_ips, blocked_this_cycle)
                else:
                    log(f"Đang nạp dữ liệu...({len(sliding_window)}/4 chu kỳ)")

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n[{get_time()}] Dừng chương trình.")

if __name__ == "__main__":
    main()
