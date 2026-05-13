#!/usr/bin/env python3
"""
mitigation.py - Module tự động chặn attacker bằng Ryu Flow-Mod
Khi IDS phát hiện tấn công, module này gửi Flow-Mod drop tới switch
"""

import requests
import json
from datetime import datetime


# ============================================================================
# CẤU HÌNH
# ============================================================================

RYU_API_URL = "http://127.0.0.1:8080"
FLOW_ADD_ENDPOINT = f"{RYU_API_URL}/stats/flowentry/add"
FLOW_DEL_ENDPOINT = f"{RYU_API_URL}/stats/flowentry/delete"

# Datapath ID (switch ID) - mặc định là 1 cho topology đơn switch
DEFAULT_DPID = 1

# Thời gian block (giây), 0 = vĩnh viễn cho đến khi xóa thủ công
BLOCK_DURATION = 300  # 5 phút


# ============================================================================
# HÀM TIỆN ÍCH
# ============================================================================

def get_time():
    """Trả về chuỗi thời gian hiện tại."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(message, is_error=False):
    """In thông báo kèm thời gian."""
    prefix = "✖ LỖI:" if is_error else "ℹ INFO:"
    print(f"[{get_time()}] {prefix} {message}")


# ============================================================================
# CORE MITIGATION LOGIC
# ============================================================================

def block_ip(src_ip, dpid=DEFAULT_DPID):
    """
    Gửi Flow-Mod để chặn tất cả traffic từ src_ip.
    
    Args:
        src_ip: IP của attacker cần chặn
        dpid: Datapath ID của switch (mặc định 1)
    
    Returns:
        bool: True nếu gửi thành công, False nếu lỗi
    """
    flow_mod = {
        "dpid": dpid,
        "match": {
            "eth_type": 2048,
            "ipv4_src": src_ip
        },
        "actions": [],  # Empty actions = DROP
        "priority": 65535,
        "idle_timeout": BLOCK_DURATION,
        "hard_timeout": 0
    }

    try:
        res = requests.post(FLOW_ADD_ENDPOINT, json=flow_mod, timeout=5)
        res.raise_for_status()
        
        log(f"Đã chặn IP {src_ip} trên switch {dpid} (timeout: {BLOCK_DURATION}s)")
        return True
        
    except requests.exceptions.RequestException as e:
        log(f"Lỗi chặn IP {src_ip}: {e}", is_error=True)
        return False


def unblock_ip(src_ip, dpid=DEFAULT_DPID):
    """
    Xóa rule chặn IP khỏi switch.
    
    Args:
        src_ip: IP cần bỏ chặn
        dpid: Datapath ID của switch
    
    Returns:
        bool: True nếu xóa thành công
    """
    flow_mod = {
        "dpid": dpid,
        "match": {
            "eth_type": 2048,
            "ipv4_src": src_ip
        }
    }

    try:
        res = requests.post(FLOW_DEL_ENDPOINT, json=flow_mod, timeout=5)
        res.raise_for_status()
        
        log(f"Đã bỏ chặn IP {src_ip} trên switch {dpid}")
        return True
        
    except requests.exceptions.RequestException as e:
        log(f"Lỗi bỏ chặn IP {src_ip}: {e}", is_error=True)
        return False


def block_ips(ip_list, dpid=DEFAULT_DPID):
    """
    Chặn nhiều IP cùng lúc.
    
    Args:
        ip_list: Danh sách IP cần chặn
        dpid: Datapath ID
    
    Returns:
        dict: Kết quả chặn cho từng IP
    """
    results = {}
    for ip in ip_list:
        results[ip] = block_ip(ip, dpid)
    return results


# ============================================================================
# TEST
# ============================================================================

if __name__ == "__main__":
    print("Module Mitigation - Test")
    print("Gửi Flow-Mod yêu cầu Ryu controller đang chạy tại", RYU_API_URL)
    
    # Test block
    # block_ip("10.0.0.21")
    
    # Test unblock
    # unblock_ip("10.0.0.21")
