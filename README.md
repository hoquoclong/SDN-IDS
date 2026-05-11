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
- **Python 3.8+**
- **eventlet 0.30.2** (tương thích với Ryu)
- **Tools**: `hping3` (DDoS), `nmap` (Port Scan), `arpspoof` (ARP Spoofing)

---

## Cài đặt

```bash
# Cài đặt Mininet
sudo apt-get install mininet

# Cài đặt hping3, nmap, dsniff (arpspoof)
sudo apt-get install hping3 nmap dsniff

# Clone repo
git clone https://github.com/hoquoclong/SDN-IDS.git
cd SDN-IDS

# Tạo virtual environment Python 3.8
uv venv --python 3.8 .venv

# Kích hoạt venv và cài đặt dependencies
source .venv/bin/activate
python -m pip install ryu==4.34 eventlet==0.30.2 requests
```

---

## Cấu trúc dự án

```
SDN-IDS/
├── README.md                   # File này
├── alerts.log                 # File log alert (tự động tạo)
├── test_results.json          # Kết quả Precision/Recall
├── pyproject.toml            # Cấu hình uv project
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

| Loại tấn công | Phương pháp phát hiện | Ngưỡng phát hiện |
|--------------|---------------------|-------------------|
| **DDoS** | Tính **Shannon Entropy** của IP nguồn (cửa sổ 4 chu kỳ × 5s) | Entropy < 1.0 |
| **Port Scan** | Đếm số **dst port khác nhau** từ 1 src IP | > 10 ports |
| **ARP Spoofing** | So sánh **MAC-IP** trong ARP packet với bảng tin cậy | MAC không khớp |

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
cd SDN-IDS
source .venv/bin/activate
```

### Bước 2: Khởi động Ryu Controller
```bash
ryu-manager src/arp_monitor.py ryu.app.ofctl_rest
```
- API endpoint: `http://127.0.0.1:8080`
- ARP Monitor sẽ load bảng tin cậy và lắng nghe ARP packets

### Bước 3: Khởi động Mininet Topology (terminal mới)
```bash
sudo python3 src/topology.py
```
- Tự động tạo 16 hosts + 1 switch
- Kiểm tra kết nối đến victim (10.0.0.1)

### Bước 4: Xem Topology (terminal mới)
```bash
# Cách 1: Dùng script xem topo
python3 src/topology_viewer.py

# Cách 2: Truy cập trực tiếp qua trình duyệt
# http://127.0.0.1:8080/v1.0/topology - Xem topo JSON
# http://127.0.0.1:8080/stats/switches - Danh sách switch
# http://127.0.0.1:8080/stats/flow/1 - Flow entries
```

### Bước 5: Chạy IDS Detector (terminal mới)
```bash
python3 src/ids_detector.py
```
- Polling mỗi 5 giây lấy flow stats
- Phát hiện DDoS (entropy) và Port Scan (port counting)
- Tự động chặn attacker qua Flow-Mod

### Bước 6: Sinh tấn công (để test)

**DDoS (trong Mininet CLI):**
```bash
h_atk1 hping3 -S --flood -V -p 80 10.0.0.1
```

**Port Scan:**
```bash
h_atk2 nmap -p 1-1000 10.0.0.1
```

**ARP Spoofing:**
```bash
h_atk3 arpspoof -i h_atk3-eth0 -t 10.0.0.1 10.0.0.2
```

### Bước 7: Kiểm tra kết quả
- IDS console: Xem alert realtime
- File `alerts.log`: Xem toàn bộ alerts (JSON format)
- Ryu console: Xem ARP Spoofing alerts

---