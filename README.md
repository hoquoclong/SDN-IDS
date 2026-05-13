# SDN Intrusion Detection System (IDS)

Hệ thống phát hiện xâm nhập (IDS) cho mạng SDN, sử dụng Mininet, Ryu Controller và Python3.
Phát hiện các loại tấn công: **DDoS**, **Port Scan**, **ARP Spoofing**. Tự động chặn attacker và sinh alert log.

---

## Mục lục

- [Công nghệ](#công-nghệ-sử-dụng)
- [Cài đặt](#cài-đặt)
- [Cấu trúc](#cấu-trúc-dự-án)
- [Hướng dẫn chạy](#hướng-dẫn-chạy)

---

## Công nghệ sử dụng

- **Mininet**: Tạo topology mạng ảo
- **Ryu Controller** (v4.34):
  - `ryu.app.ofctl_rest` (REST API để lấy flow stats)
  - `ryu.app.simple_switch_13` (switch l2 cơ bản)
  - `src/arp_monitor.py` (ARP Spoofing detection)
- **Python 3.8** (bắt buộc)
- **eventlet 0.30.2** (tương thích với Ryu)
- **Tools**: `hping3` (DDoS), `nmap` (Port Scan), `arpspoof` (ARP Spoofing)

---

## Cài đặt (Ubuntu Server 22.04)

### 1. Cài đặt hệ thống

```bash
sudo apt-get update
sudo apt-get install -y mininet hping3 nmap dsniff git curl software-properties-common
```

### 2. Cài đặt Python 3.8

```bash
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install -y python3.8 python3.8-venv python3.8-dev python3.8-distutils
```

### 3. Clone và cài đặt project

```bash
git clone https://github.com/hoquoclong/SDN-IDS.git
cd SDN-IDS

# Tạo virtual environment Python 3.8
python3.8 -m venv .venv

# Kích hoạt venv
source .venv/bin/activate

# Nâng cấp pip
python3.8 -m ensurepip
python3.8 -m pip install --upgrade pip

# Cài đặt các thư viện cần thiết
python3.8 -m pip install eventlet==0.30.2 requests

# Clone dự án mã nguồn Ryu từ GitHub và cài đặt
cd ~
git clone https://github.com/faucetsdn/ryu.git
cd ryu
python3.8 -m pip install .

# Quay lại thư mục dự án SDN-IDS
cd ~/SDN-IDS

# Sửa lỗi mất thư mục giao diện Web GUI của Ryu (nếu có)
cp -r ~/ryu/ryu/app/gui_topology/html .venv/lib/python3.8/site-packages/ryu/app/gui_topology/

# Kiểm tra cài đặt
ryu-manager --version
```

---

## Cấu trúc dự án

```
SDN-IDS/
├── README.md                   # File này
├── alerts.log                 # File log alert (tự động tạo)
├── test_results.json          # Kết quả Precision/Recall
├── pyproject.toml            # Cấu hình project
├── .venv/                    # Virtual environment (Python 3.8)
├── src/
│   ├── topology.py          # Tạo mạng Mininet
│   ├── topology_viewer.py   # Xem topo qua Ryu REST API
│   ├── ids_detector.py      # IDS chính: polling, DDoS, Port Scan detection
│   ├── mitigation.py        # Module chặn IP (Flow-Mod drop)
│   ├── arp_monitor.py       # Ryu app phát hiện ARP Spoofing
│   └── test_ids.py          # Đo Precision/Recall
└── scripts/
    ├── ddos.sh              # Script sinh DDoS (hping3)
    ├── port_scan.sh         # Script sinh Port Scan (nmap)
    └── arp_spoofing.sh      # Script sinh ARP Spoofing (arpspoof)
```

---

## Tính năng

### 1. Topology Mininet

- 1 Victim (`h_vic`, 10.0.0.1)
- 5 Benign hosts (`h_ben1` - `h_ben5`, 10.0.0.11 - 10.0.0.15)
- 10 Attacker hosts (`h_atk1` - `h_atk10`, 10.0.0.21 - 10.0.0.30)
- 1 Switch (`s1`) chạy OpenFlow 1.3
- Kết nối Ryu Controller (127.0.0.1:6633)

### 2. Phát hiện tấn công

| Loại tấn công    | Phương pháp phát hiện                                        | Ngưỡng phát hiện |
| ---------------- | ------------------------------------------------------------ | ---------------- |
| **DDoS**         | Tính **Shannon Entropy** nguồn/đích (cửa sổ 4 chu kỳ × 5s)   | Entropy thấp + traffic cao |
| **Port Scan**    | Đếm số **dst port khác nhau** hoặc fallback theo packet-rate | >= 10 ports hoặc 30-500 pps |
| **ARP Spoofing** | So sánh **MAC-IP** trong ARP packet với bảng tin cậy         | MAC không khớp hoặc IP lạ |

### 3. Mitigation (Tự động chặn)

- Gửi **Flow-Mod** đến switch để DROP traffic từ attacker IP
- Thời gian chặn: 300 giây (5 phút) - có thể thay đổi trong `src/mitigation.py` (`BLOCK_DURATION`)
- Tự động chặn top 3 IP nghi ngờ nhất (DDoS) hoặc IP quét port (Port Scan)

### 4. Alert Log

- Ghi log vào file `alerts.log` (JSON format)
- Thông tin: timestamp, attack_type, attacker_ip, traffic volume, message

---

## Hướng dẫn chạy

### Bước 1: Kích hoạt Virtual Environment

```bash
cd ~/SDN-IDS
source .venv/bin/activate
```

### Bước 2: Khởi động Ryu Controller

```bash
ryu-manager ryu.app.simple_switch_13 ryu.app.gui_topology.gui_topology src/arp_monitor.py ryu.app.ofctl_rest ryu.app.rest_topology
```

- API endpoint: `http://127.0.0.1:8080`
- ARP Monitor sẽ load bảng tin cậy và lắng nghe ARP packets
- **Giữ terminal này mở**

### Bước 3: Khởi động Mininet Topology (terminal mới)

```bash
sudo python3.8 src/topology.py
```

- Tự động tạo 16 hosts + 1 switch
- Kiểm tra kết nối đến victim (10.0.0.1)
- **Giữ terminal này mở**

### Bước 4: Xem Topology (terminal mới)

```bash
python3.8 src/topology_viewer.py
```

Hoặc truy cập trực tiếp qua trình duyệt:

- `http://127.0.0.1:8080/v1.0/topology` - Xem topo JSON
- `http://127.0.0.1:8080/stats/switches` - Danh sách switch
- `http://127.0.0.1:8080/stats/flow/1` - Flow entries

### Bước 5: Chạy IDS Detector (terminal mới)

```bash
python3.8 src/ids_detector.py
```

- Polling mỗi 5 giây lấy flow stats
- Phát hiện DDoS (entropy) và Port Scan (port counting)
- Tự động chặn attacker qua Flow-Mod
- Victim/server được bảo vệ mặc định là `10.0.0.1`. Có thể đổi hoặc cấu hình nhiều victim bằng biến môi trường:

```bash
IDS_PROTECTED_IPS=10.0.0.5 python3.8 src/ids_detector.py
IDS_PROTECTED_IPS=10.0.0.5,10.0.0.8 python3.8 src/ids_detector.py
```

- **Giữ terminal này mở**

### Bước 6: Sinh tấn công (trong Mininet CLI)

**DDoS:**

```bash
h_atk1 hping3 -S --flood -V -p 80 10.0.0.1
```

Hoặc khi dùng script:

```bash
TARGET_IP=10.0.0.5 scripts/ddos.sh
```

**Port Scan:**

```bash
h_atk2 nmap -p 1-1000 10.0.0.1
```

Hoặc khi dùng script:

```bash
TARGET_IP=10.0.0.5 TARGET_PORTS=1-1000 scripts/port_scan.sh
```

Nếu flow stats của Ryu không có `tcp_dst/udp_dst`, IDS sẽ dùng fallback theo tốc độ gói và sinh alert `Suspected_Port_Scan_Rate`.

**ARP Spoofing:**

```bash
h_atk3 arpspoof -i h_atk3-eth0 -t 10.0.0.1 10.0.0.11
```

Hoặc dùng script trong Mininet CLI:

```bash
h_atk3 scripts/arp_spoofing.sh
h_atk3 SPOOFED_IP=10.0.0.2 scripts/arp_spoofing.sh
```

Lưu ý: với topology hiện tại, nên spoof một IP có trong bảng tin cậy, ví dụ `10.0.0.11`. Nếu dùng IP ngoài topology như `10.0.0.2`, hệ thống sẽ ghi `ARP_UNKNOWN_BINDING` thay vì `ARP_SPOOFING`.

### Bước 7: Kiểm tra kết quả

- IDS console: Xem alert realtime của DDoS/Port Scan
- Ryu console: Xem alert realtime của ARP Spoofing
- File `alerts.log`: Xem toàn bộ alerts (JSON format), bao gồm ARP Spoofing. Lưu ý `ids_detector.py` không in alert ARP vì ARP được xử lý trực tiếp trong Ryu app `src/arp_monitor.py`.

---
