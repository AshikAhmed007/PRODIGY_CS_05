# 🌐 Fancy Network Packet Analyzer (Python + Scapy + Rich)

A visually enhanced network packet analyzer built using **Scapy** and **Rich** in Python. This tool captures live packets from the network interface and displays structured, colorful packet details in the terminal.

> ⚠️ For **educational and authorized use only**. Requires administrator/root privileges.

---

## ✨ Features

- 📦 **Live packet sniffing** using `scapy`
- 📘 **Structured display** with `rich` tables and panels
- 🌐 **Supports protocols**: Ethernet, IP, TCP, UDP, ICMP
- 🔍 Optional **IP address filter** to capture only relevant traffic
- 📄 Displays payload content for TCP, UDP, ICMP, and raw IP data
- 🕒 Includes human-readable timestamps for each captured packet

---

## 🧰 Requirements

- Python 3.x
- `scapy`
- `rich`

Install with:

```bash
pip install scapy rich
```

---

## 🚀 Usage

1. **Clone the Repository**:

```bash
git clone https://github.com/your-username/fancy-packet-analyzer.git
cd fancy-packet-analyzer
```

2. **Run the Script with Admin Privileges**:

```bash
sudo python3 packet_sniffer.py
```

3. **Optional IP Filter**:

When prompted, you can enter a specific IP to monitor, or just press Enter to capture all packets.

---

## 🖥 Output Example

- Ethernet, IP, TCP, UDP, and ICMP packet details shown in colorized rich tables
- Payloads printed in styled panels with size info
- Automatic timestamping for each captured packet

---

## 📁 File Structure

```
packet_sniffer.py     # Main packet analysis script
README.md             # Documentation file
```

---

## ⚠️ Disclaimer

This tool is for **educational and authorized use only**. Do not use it on networks without explicit permission.

---

> Developed by Ashik Ahmed 🛡️
