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
        res_sw = requests.get(f"{RYU_URL}/v1.0/topology/switches", timeout=5)
        res_sw.raise_for_status()
        
        res_link = requests.get(f"{RYU_URL}/v1.0/topology/links", timeout=5)
        res_link.raise_for_status()
        
        return {
            "switches": res_sw.json(),
            "links": res_link.json()
        }
    except requests.exceptions.RequestException as e:
        print(f"Loi ket noi Ryu: {e}")
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
        return res.json().get(str(dpid), [])
    except:
        return []

def get_ports(dpid):
    try:
        res = requests.get(f"{RYU_URL}/stats/port/{dpid}", timeout=5)
        res.raise_for_status()
        return res.json().get(str(dpid), [])
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
        raw_dpid = sw.get("dpid")
        dpid = int(raw_dpid, 16) if isinstance(raw_dpid, str) else raw_dpid
        
        ports = get_ports(dpid)
        valid_ports = 0
        for p in ports:
            try:
                if int(p.get('port_no', 0)) > 0:
                    valid_ports += 1
            except (ValueError, TypeError):
                pass
                
        print(f"  - Switch dpid={dpid} | ports={valid_ports}")

    print(f"\n[Links] {len(links)} link(s)")
    for link in links:
        src = link.get("src")
        dst = link.get("dst")
        if src and dst:
            src_dpid = int(src.get('dpid'), 16) if isinstance(src.get('dpid'), str) else src.get('dpid')
            dst_dpid = int(dst.get('dpid'), 16) if isinstance(dst.get('dpid'), str) else dst.get('dpid')
            print(f"  - Switch:{src_dpid} port:{src.get('port_no')} <-> Switch:{dst_dpid} port:{dst.get('port_no')}")

    print(f"\n[Hosts] Tren switches:")
    for sw in switches:
        raw_dpid = sw.get("dpid")
        dpid = int(raw_dpid, 16) if isinstance(raw_dpid, str) else raw_dpid
        
        flows = get_flows(dpid)
        hosts = set()
        for f in flows:
            match = f.get("match", {})
            # OpenFlow 1.3 usually uses eth_src, eth_dst
            # Nhưng ryu simple_switch_13 luu MAC trong dl_src/dl_dst (OF1.0) hoac eth_src/eth_dst (OF1.3)
            macs = []
            if "eth_src" in match: macs.append(match["eth_src"])
            if "eth_dst" in match: macs.append(match["eth_dst"])
            if "dl_src" in match: macs.append(match["dl_src"])
            if "dl_dst" in match: macs.append(match["dl_dst"])
            
            for mac in macs:
                if mac.startswith("00:00:00:00:00:"):
                    suffix = int(mac.split(":")[-1])
                    hosts.add(f"10.0.0.{suffix} ({mac})")
                    
        if hosts:
            # Sort IPs properly
            sorted_hosts = sorted(list(hosts), key=lambda x: int(x.split()[0].split('.')[-1]))
            print(f"  Switch {dpid}:")
            for h in sorted_hosts:
                print(f"    - {h}")

    print("\n" + "=" * 60)
    print("Truy cap Web GUI: http://127.0.0.1:8080")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    display_topology()