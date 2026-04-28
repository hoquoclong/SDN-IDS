#!/usr/bin/env python3
"""
topology.py - Mô hình mạng Mininet cho đề tài SDN-IDS
"""

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import OVSKernelSwitch, RemoteController

# ============================================================================
#  HẰNG SỐ CẤU HÌNH
# ============================================================================

# Số lượng host
NUM_BENIGNS = 5
NUM_ATTACKERS = 10

# Mạng & Quy hoạch IP suffix
SUBNET_PREFIX = "10.0.0"
SUBNET_MASK = "/24"
MAC_PREFIX = "00:00:00:00:00"

VICTIM_IP_SUFFIX = 1
BENIGN_IP_START = 11
ATTACKER_IP_START = 21

# Băng thông (Mbps) và Độ trễ (ms) cho từng vai trò
LINK_CONFIG = {
    'attacker': {'bw': 100, 'delay': '1ms'},
    'victim'  : {'bw': 100, 'delay': '1ms'},
    'benign'  : {'bw': 10,  'delay': '5ms'},
}

# ============================================================================
#  HÀM TIỆN ÍCH
# ============================================================================
def get_ip(ip_suffix):
	"""Sinh IPv4 kèm Subnet Mask."""
	return f"{SUBNET_PREFIX}.{ip_suffix}{SUBNET_MASK}"

def get_mac(ip_suffix):
	"""Sinh MAC có octet cuối trùng với IP."""
	return f"{MAC_PREFIX}:{ip_suffix:02d}"

def map_hosts():
	"""Lập danh sách (tên, ip_suffix) cho toàn bộ mạng."""
	hosts = [("h_vic", VICTIM_IP_SUFFIX)]

	for i in range(1, NUM_BENIGNS + 1):
		hosts.append((f"h_ben{i}", BENIGN_IP_START + i - 1))

	for i in range(1, NUM_ATTACKERS + 1):
		hosts.append((f"h_atk{i}", ATTACKER_IP_START + i - 1))

	return hosts

def verify_connectivity(hosts_dict):
    """Tự động kiểm tra kết nối từ tất cả host đến Victim."""
    victim = hosts_dict.get('h_vic')
    if not victim:
        return
        
    victim_ip = victim.IP()
    info('\nKiem tra ket noi toi victim (10.0.0.1)...\n')

    passed = 0
    for name, host in hosts_dict.items():
        if name == 'h_vic':
            continue

        result = host.cmd(f'ping -c 1 -W 1 {victim_ip}')
        if '1 received' in result:
            status = 'OK'
            passed += 1
        else:
            status = 'FAIL'
        info(f'    {name:10s} -> h_vic : {status}\n')

    info(f'\nKet qua: {passed}/{len(hosts_dict)-1} hosts ket noi thanh cong\n')

# ============================================================================
#  XÂY DỰNG TOPOLOGY
# ============================================================================
def ids_topology():
	"""Tạo, khởi động và mở CLI Mininet"""
	info("*** Dang khoi tao topo Mininet cho SDN-IDS\n")

	net = Mininet(
		controller=RemoteController, 
		switch=OVSKernelSwitch, 
		link=TCLink, 
		build=False,
		autoStaticArp=False
	)

	# 1. Khởi tạo Controller từ Ryu
	net.addController(
		"Ryu_controller",
		controller=RemoteController,
		ip="127.0.0.1",
		port=6633,
	)
	info(f"*** Da cau hinh RemoteController: 127.0.0.1:6633 (Ryu_controller)\n")

	# 2. Khởi tạo Switch trung tâm
	core_switch = net.addSwitch("s1", cls=OVSKernelSwitch, protocols="OpenFlow13")
	info(f"*** Da them core switch: s1 (OpenFlow13)\n")

	host_objects = {}

	# 3. Tạo Host và Link dựa trên map_hosts
	for host_name, ip_suffix in map_hosts():
		host_ip = get_ip(ip_suffix)
		host_mac = get_mac(ip_suffix)

		# 1. Tạo tất cả host từ danh sách
		host = net.addHost(host_name, ip=host_ip, mac=host_mac)
		host_objects[host_name] = host
		info(f"*** Da them host {host_name}: IP={host_ip}, MAC={host_mac}\n")

		# 2. Kết nối mọi host với switch trung tâm với băng thông và độ trễ theo vai trò
		link_config = LINK_CONFIG.get(host_name.split('_')[0])
		if link_config:
			net.addLink(host, core_switch, bw=link_config['bw'], delay=link_config['delay'])
		else:
			net.addLink(host, core_switch, bw=100)
		info(f"*** Da ket noi {host_name} <-> s1\n")

	# 4. Build và Start mạng
	info("*** Xay dung va khoi dong mang\n")
	net.build()
	net.start()

	# 5. In Port Mapping
	info('\nPort mapping tren Switch s1:\n')
	for i, (name, host) in enumerate(host_objects.items(), start=1):
		info(f'    Port {i:2d} -> {name:8s} ({host.IP()})\n')

	# 6. Kiểm tra kết nối
	verify_connectivity(host_objects)

	info("*** Mininet da khoi dong. Dang vao CLI (go 'exit' de dung).\n")
	CLI(net)

	info("*** Dang dung Mininet\n")
	net.stop()

if __name__ == "__main__":
	setLogLevel("info")
	ids_topology()