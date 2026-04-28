#!/bin/bash
# ==============================================================================
# Tên script : port_scan.sh
# Chức năng  : Mô phỏng hành vi rà quét tình trạng cổng mạng (Port Scanning).
# Công cụ    : nmap
# ==============================================================================

TARGET_IP="10.0.0.1"

echo "[*] Khởi chạy tiến trình rà quét cổng mạng..."
echo "[*] Mục tiêu (Target): $TARGET_IP"

# ------------------------------------------------------------------------------
# Chú giải tham số thực thi:
#   -p 1-1000 : Chỉ định phạm vi rà quét từ cổng 1 đến cổng 1000.
#   -T4       : Cấu hình tham số thời gian ở mức Aggressive để tăng tốc độ.
#   -n        : Vô hiệu hóa tính năng phân giải tên miền nhằm tối ưu hiệu năng.
# ------------------------------------------------------------------------------

nmap -p 1-1000 -T4 -n "$TARGET_IP"

echo "[+] Quá trình rà quét đã hoàn tất."