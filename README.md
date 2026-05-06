# SDN Intrusion Detection System (IDS)

Hệ thống phát hiện xâm nhập (IDS) cho mạng SDN, sử dụng Mininet, Ryu Controller và Python3.  
Phát hiện các loại tấn công: **DDoS**, **Port Scan**, **ARP Spoofing**. Tự động chặn attacker và sinh alert log.

---

## 📋 Mục lục

- [Tính năng](#tính-năng)
- [Công nghệ sử dụng](#công-nghệ-sử-dụng)
- [Cài đặt](#cài-dặt)
- [Cấu trúc dự án](#cấu-trúc-dự-án)
- [Hướng dẫn chạy](#hướng-dẫn-chạy)
- [Kiểm thử & Kết quả](#kiểm-thử--kết-quả)
- [Giảng viên](#giảng-viên)

---

## ✅ Tính năng

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
- Thời gian chặn: 300 giây (5 phút) mỗi lần phát hiện
- Tự động chặn top 3 IP nghi ngờ (DDoS) hoặc IP quét port (Port Scan)

### 4. Alert Log
- Ghi log vào file `alerts.log` (JSON format)
- Thông tin: timestamp, attack_type, attacker_ip, traffic volume, message

---

## 🛠 Công nghệ sử dụng

- **Mininet**: Tạo topology mạng ảo
- **Ryu Controller**: 
  - `ryu.app.ofctl_rest` (REST API để lấy flow stats)
  - `ryu.app.simple_switch_13` (switch l2 cơ bản)
  - `src/arp_monitor.py` (ARP Spoofing detection)
- **Python3**: IDS detector, Mitigation module, Test module
- **Tools**: `hping3` (DDoS), `nmap` (Port Scan), `arpspoof` (ARP Spoofing)

---

## 📦 Cài đặt

```bash
# Cài đặt Mininet (nếu chưa có)
sudo apt-get install mininet

# Cài đặt Ryu
pip3 install ryu

# Cài đặt Python dependencies
pip3 install requests

# Clone repo
git clone https://github.com/hoquoclong/SDN-IDS.git
cd SDN-IDS
```

---

## 📁 Cấu trúc dự án

```
SDN-IDS/
├── README.md                   # File này
├── alerts.log                 # File log alert (tự động tạo)
├── test_results.json          # Kết quả Precision/Recall
├── main.py                   # Entry point (hiện để trống, dùng src/ids_detector.py)
├── pyproject.toml            # Cấu hình uv project
├── src/
│   ├── topology.py          # Tạo mạng Mininet
│   ├── ids_detector.py      # IDS chính: polling, DDoS, Port Scan detection
│   ├── mitigation.py        # Module chặn IP (Flow-Mod drop)
│   ├── arp_monitor.py       # Ryu app phát hiện ARP Spoofing
│   └── test_ids.py          # Đo Precision/Recall
└── scripts/
    ├── ddos.sh              # Script sinh DDoS (hping3)
    ├── port_scan.sh         # Script sinh Port Scan (nmap)
    └── arp_spoofing.sh     # Script sinh ARP Spoofing (arpspoof)
```

---

## 🚀 Hướng dẫn chạy

### Bước 1: Khởi động Ryu Controller
```bash
ryu-manager src/arp_monitor.py ryu.app.ofctl_rest ryu.app.simple_switch_13
```
- API endpoint: `http://127.0.0.1:8080`
- ARP Monitor sẽ load bảng tin cậy và lắng nghe ARP packets

### Bước 2: Khởi động Mininet Topology
```bash
sudo python3 src/topology.py
```
- Tự động tạo 16 hosts + 1 switch
- Kiểm tra kết nối đến victim (10.0.0.1)

### Bước 3: Chạy IDS Detector
```bash
python3 src/ids_detector.py
```
- Polling mỗi 5 giây lấy flow stats
- Phát hiện DDoS (entropy) và Port Scan (port counting)
- Tự động chặn attacker qua Flow-Mod

### Bước 4: Sinh tấn công (để test)

**DDoS (mở terminal mới trong Mininet CLI):**
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

### Bước 5: Kiểm tra kết quả
- IDS console: Xem alert realtime
- File `alerts.log`: Xem toàn bộ alerts (JSON format)
- Ryu console: Xem ARP Spoofing alerts

---

## 📊 Kiểm thử & Kết quả

### Chạy test Precision/Recall
```bash
python3 src/test_ids.py
```

### Kết quả đo lường (4 kịch bản test)

| Kịch bản | Expected | Detected | Precision | Recall |
|-----------|----------|-----------|-----------|--------|
| Normal Traffic | Không | Không | 1.000 | 1.000 |
| DDoS Attack | DDoS | DDoS | 1.000 | 1.000 |
| Port Scan | Port_Scan | Port_Scan (+ DDoS FP) | 0.500 | 1.000 |
| Mixed (DDoS + Port Scan) | Cả 2 | Cả 2 | 1.000 | 1.000 |

**Tổng thể:**
- **Precision:** 0.800
- **Recall:** 1.000
- **F1-Score:** 0.889

> Lưu ý: Port Scan test có False Positive do DDoS detection nhạy cảm với traffic tập trung từ 1 IP. Có thể điều chỉnh ENTROPY_THRESHOLD để cải thiện.

---

## 📝 Comment code

Toàn bộ code đều có **docstring** và **comment đầy đủ** theo chuẩn Python:
- Mỗi function đều có docstring mô tả chức năng, tham số, giá trị trả về
- Các đoạn code phức tạp đều có inline comments
- Tên biến, hàm có ý nghĩa, dễ hiểu

Ví dụ:
```python
def calculate_entropy(ip_packet_counts):
    """
    Tính Shannon Entropy từ phân bố packet theo IP nguồn.
    
    Args:
        ip_packet_counts: dict {ip: packet_count}
    
    Returns:
        float: Giá trị entropy (0.0 - log2(N))
    """
    total = sum(ip_packet_counts.values())
    if total == 0:
        return 0.0
    # Tính entropy: H = -Σ(p * log2(p))
    entropy = 0.0
    for count in ip_packet_counts.values():
        if count <= 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy
```

---

**Tác giả:** hoquoclong  
**Repo:** https://github.com/hoquoclong/SDN-IDS
