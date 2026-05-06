#!/usr/bin/env python3
"""
test_ids.py - Đo Precision/Recall của IDS trong nhiều kịch bản
Chay: python3 src/test_ids.py
"""

import sys
import json
from datetime import datetime
from collections import defaultdict


# ============================================================================
# CẤU HÌNH TEST
# ============================================================================

TEST_RESULTS_FILE = "test_results.json"


def get_test_scenarios():
    """Trả về danh sách kịch bản test."""
    # Tạo Port Scan flows (49 ports)
    port_scan_flows = []
    for i in range(1, 50):
        port_scan_flows.append(
            {"src": "10.0.0.22", "dst": "10.0.0.1", "dst_port": i, "pkts": 5, "bytes": 500}
        )
    
    # Tạo Mixed flows (DDoS + Port Scan)
    mixed_flows = [
        {"src": "10.0.0.21", "dst": "10.0.0.1", "dst_port": 80, "pkts": 5000, "bytes": 500000},
        {"src": "10.0.0.21", "dst": "10.0.0.1", "dst_port": 80, "pkts": 5200, "bytes": 520000},
        {"src": "10.0.0.21", "dst": "10.0.0.1", "dst_port": 80, "pkts": 5500, "bytes": 550000},
    ]
    # Thêm port scan flows
    for i in range(1, 30):
        mixed_flows.append(
            {"src": "10.0.0.22", "dst": "10.0.0.1", "dst_port": i, "pkts": 5, "bytes": 500}
        )
    
    scenarios = [
        {
            "name": "Normal Traffic (Benign only)",
            "description": "Chỉ có traffic bình thường, không có tấn công",
            "expected_attacks": [],
            "flows": [
                {"src": "10.0.0.11", "dst": "10.0.0.1", "dst_port": 80, "pkts": 100, "bytes": 10000},
                {"src": "10.0.0.12", "dst": "10.0.0.1", "dst_port": 443, "pkts": 150, "bytes": 15000},
                {"src": "10.0.0.13", "dst": "10.0.0.1", "dst_port": 80, "pkts": 200, "bytes": 20000},
            ]
        },
        {
            "name": "DDoS Attack (Low Entropy)",
            "description": "Tấn công DDoS từ 1 IP duy nhất, traffic tập trung",
            "expected_attacks": ["DDoS"],
            "flows": [
                {"src": "10.0.0.21", "dst": "10.0.0.1", "dst_port": 80, "pkts": 5000, "bytes": 500000},
                {"src": "10.0.0.21", "dst": "10.0.0.1", "dst_port": 80, "pkts": 5200, "bytes": 520000},
                {"src": "10.0.0.21", "dst": "10.0.0.1", "dst_port": 80, "pkts": 5500, "bytes": 550000},
                {"src": "10.0.0.21", "dst": "10.0.0.1", "dst_port": 80, "pkts": 6000, "bytes": 600000},
                {"src": "10.0.0.11", "dst": "10.0.0.1", "dst_port": 80, "pkts": 10, "bytes": 1000},
                {"src": "10.0.0.12", "dst": "10.0.0.1", "dst_port": 443, "pkts": 15, "bytes": 1500},
            ]
        },
        {
            "name": "Port Scan Attack",
            "description": "Quét nhiều cổng từ 1 IP",
            "expected_attacks": ["Port_Scan"],
            "flows": port_scan_flows + [
                {"src": "10.0.0.11", "dst": "10.0.0.1", "dst_port": 80, "pkts": 100, "bytes": 10000},
            ]
        },
        {
            "name": "Mixed Traffic (DDoS + Port Scan)",
            "description": "Vừa DDoS vừa Port Scan cùng lúc",
            "expected_attacks": ["DDoS", "Port_Scan"],
            "flows": mixed_flows
        },
    ]
    return scenarios


# ============================================================================
# HÀM ĐÁNH GIÁ
# ============================================================================

def calculate_entropy(ip_packet_counts):
    """Tính Shannon Entropy."""
    import math
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


def detect_ddos(flows, min_traffic=50, entropy_threshold=1.0):
    """Giả lập DDoS detection từ flows."""
    ip_packets = defaultdict(int)
    for flow in flows:
        ip_packets[flow["src"]] += flow["pkts"]
    
    total = sum(ip_packets.values())
    if total < min_traffic:
        return []
    
    entropy = calculate_entropy(ip_packets)
    if entropy < entropy_threshold:
        return ["DDoS"]
    return []


def detect_port_scan(flows, threshold=10):
    """Giả lập Port Scan detection từ flows."""
    src_ports = defaultdict(set)
    for flow in flows:
        if flow.get("dst_port"):
            src_ports[flow["src"]].add(flow["dst_port"])
    
    detected = []
    for src, ports in src_ports.items():
        if len(ports) >= threshold:
            detected.append("Port_Scan")
            break
    return detected


def run_test_scenario(scenario):
    """Chạy 1 kịch bản test và trả về kết quả."""
    print(f"\n{'='*60}")
    print(f"Kịch bản: {scenario['name']}")
    print(f"Mô tả: {scenario['description']}")
    print(f"Expected attacks: {scenario['expected_attacks']}")
    print(f"{'='*60}")
    
    flows = scenario["flows"]
    
    detected_ddos = detect_ddos(flows)
    detected_port_scan = detect_port_scan(flows)
    
    actual_attacks = detected_ddos + detected_port_scan
    
    print(f"Detected attacks: {actual_attacks}")
    
    expected = set(scenario["expected_attacks"])
    actual = set(actual_attacks)
    
    tp = len(expected & actual)
    fp = len(actual - expected)
    fn = len(expected - actual)
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    
    result = {
        "scenario": scenario["name"],
        "expected": list(expected),
        "actual": list(actual),
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
    }
    
    print(f"TP={tp}, FP={fp}, FN={fn}")
    print(f"Precision={precision:.3f}, Recall={recall:.3f}")
    
    if fp > 0:
        print("⚠️  False Positive: Phát hiện nhầm")
    if fn > 0:
        print("⚠️  False Negative: Bỏ lỡ tấn công")
    if fp == 0 and fn == 0:
        print("✅ Hoàn hảo!")
    
    return result


def run_all_tests():
    """Chạy tất cả kịch bản và tính Precision/Recall tổng thể."""
    print("="*60)
    print("BẮT ĐẦU ĐO PRECISION/RECALL CHO SDN-IDS")
    print("="*60)
    
    scenarios = get_test_scenarios()
    all_results = []
    total_tp = 0
    total_fp = 0
    total_fn = 0
    
    for scenario in scenarios:
        result = run_test_scenario(scenario)
        all_results.append(result)
        total_tp += result["TP"]
        total_fp += result["FP"]
        total_fn += result["FN"]
    
    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    f1_score = 2 * (overall_precision * overall_recall) / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0.0
    
    summary = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_scenarios": len(scenarios),
        "overall_precision": round(overall_precision, 3),
        "overall_recall": round(overall_recall, 3),
        "f1_score": round(f1_score, 3),
        "details": all_results
    }
    
    print("\n" + "="*60)
    print("TÓM TẮT KẾT QUẢ")
    print("="*60)
    print(f"Tổng kịch bản: {summary['total_scenarios']}")
    print(f"Precision tổng thể: {summary['overall_precision']:.3f}")
    print(f"Recall tổng thể: {summary['overall_recall']:.3f}")
    print(f"F1-Score: {summary['f1_score']:.3f}")
    print("="*60)
    
    with open(TEST_RESULTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\nĐã lưu kết quả vào: {TEST_RESULTS_FILE}")
    
    return summary


if __name__ == "__main__":
    run_all_tests()
