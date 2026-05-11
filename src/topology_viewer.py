#!/usr/bin/env python3
"""
topology_viewer.py - Xem topo mạng SDN qua Ryu REST API
Chạy: python3 src/topology_viewer.py
"""

import requests
import json


RYU_URL = "http://127.0.0.1:8080"

def get_topology():
    try:
        res = requests.get(f"{RYU_URL}/v1.0/topology", timeout=5)
        res.raise_for_status()
        return res.json()
    except requests.exceptions.RequestException as e:
        print(f"Lỗi kết nối Ryu: {e}")
        return None

def get_switches():
    try:
        res = requests.get(f"{RYU_URL}/stats/switches", timeout=5)
        res.raise_for_status()
        return res.json()
    except:
        return []

def get_flows(dpid):
    try:
        res = requests.get(f"{RYU_URL}/stats/flow/{dpid}", timeout=5)
        res.raise_for_status()
        return res.json().get(dpid, [])
    except:
        return []

def get_ports(dpid):
    try:
        res = requests.get(f"{RYU_URL}/stats/port/{dpid}", timeout=5)
        res.raise_for_status()
        return res.json().get(dpid, [])
    except:
        return []

def display_topology():
    print("\n" + "=" * 60)
    print("SDN NETWORK TOPOLOGY VIEWER".center(60))
    print("=" * 60)

    topo = get_topology()
    if not topo:
        print("\nKhong ket noi duoc Ryu Controller!")
        print("Dang chay Ryu chua? Kiem tra: ryu-manager src/arp_monitor.py ryu.app.ofctl_rest")
        return

    switches = topo.get("switches", [])
    links = topo.get("links", [])

    print(f"\n[Switches] {len(switches)} switch(es)")
    for sw in switches:
        dpid = sw.get("dpid")
        ports = get_ports(dpid)
        print(f"  - Switch dpid={dpid} | ports={len([p for p in ports if p.get('port_no', 0) > 0])}")

    print(f"\n[Links] {len(links)} link(s)")
    for link in links:
        src = link.get("src")
        dst = link.get("dst")
        if src and dst:
            print(f"  - Switch:{src.get('dpid')} port:{src.get('port_no')} <-> Switch:{dst.get('dpid')} port:{dst.get('port_no')}")

    print(f"\n[Hosts] Tren switches:")
    for sw in switches:
        dpid = sw.get("dpid")
        flows = get_flows(dpid)
        hosts = set()
        for f in flows:
            match = f.get("match", {})
            ipv4_src = match.get("ipv4_src")
            ipv4_dst = match.get("ipv4_dst")
            if ipv4_src:
                hosts.add(ipv4_src)
            if ipv4_dst:
                hosts.add(ipv4_dst)
        if hosts:
            print(f"  Switch {dpid}: {sorted(hosts)}")

    print("\n" + "=" * 60)
    print("Truy cap Web GUI: http://127.0.0.1:8080")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    display_topology()