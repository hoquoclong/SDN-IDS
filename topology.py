"""topology.py - Mô hình mạng Mininet cho đề tài SDN-IDS"""

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import OVSKernelSwitch, RemoteController

# Số lượng host
NUM_BENIGNS = 5
NUM_ATTACKERS = 10

# Mạng
SUBNET_PREFIX = "10.0.0"
SUBNET_MASK = "/24"
MAC_PREFIX = "00:00:00:00:00"

# Quy hoạch IP suffix cho host
VICTIM_IP_SUFFIX = 1
BENIGN_IP_START = 11
ATTACKER_IP_START = 21

def get_ip(ip_suffix):
	"""Sinh IPv4 kèm mask."""
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

def ids_topology():
	"""Tạo, khởi động và mở CLI Mininet"""
	info("*** Dang khoi tao topo Mininet cho SDN-IDS\n")

	net = Mininet(controller=RemoteController, switch=OVSKernelSwitch, link=TCLink, build=False)

	net.addController(
		"Ryu_controller",
		controller=RemoteController,
		ip="127.0.0.1",
		port=6633,
	)
	info(
		f"*** Da cau hinh RemoteController: 127.0.0.1:6633"
		f"(Ryu_controller)\n"
	)

	core_switch = net.addSwitch("s1", cls=OVSKernelSwitch, protocols="OpenFlow13")
	info(f"*** Da them core switch: s1 (OpenFlow13)\n")

	host_objects = {}

	for host_name, ip_suffix in map_hosts():
		host_ip = get_ip(ip_suffix)
		host_mac = get_mac(ip_suffix)

		# 1. Tạo tất cả host từ danh sách
		host = net.addHost(host_name, ip=host_ip, mac=host_mac)
		host_objects[host_name] = host
		info(f"*** Da them host {host_name}: IP={host_ip}, MAC={host_mac}\n")

		# 2. Kết nối mọi host với switch trung tâm
		net.addLink(host, core_switch, bw=100)
		info(f"*** Da ket noi {host_name} <-> s1\n")

	info("*** Xay dung va khoi dong mang\n")
	net.build()
	net.start()

	info("*** Mininet da khoi dong. Dang vao CLI (go 'exit' de dung).\n")
	CLI(net)

	info("*** Dang dung Mininet\n")
	net.stop()

if __name__ == "__main__":
	setLogLevel("info")
	ids_topology()