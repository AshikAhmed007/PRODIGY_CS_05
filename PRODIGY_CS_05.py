from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()
user_ip_filter = None  # Global filter from user input

def decode_payload(payload: bytes) -> str:
    try:
        return payload.decode("utf-8", errors="replace")
    except Exception:
        return str(payload)

def print_payload(title: str, payload: bytes):
    if payload:
        content = decode_payload(payload)
        console.print(Panel(Text(content, style="bold white on blue"), title=f"📦 {title}", subtitle=f"Payload Size: {len(payload)} bytes", style="cyan"))

def analyze_packet(packet):
    global user_ip_filter

    if not packet.haslayer(IP):
        return

    ip = packet[IP]

    if user_ip_filter and (ip.src != user_ip_filter and ip.dst != user_ip_filter):
        return  # Skip packets not involving specified IP

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    console.rule(f"[bold yellow]🕒 Packet Captured at {timestamp}[/bold yellow]")

    # Ethernet
    if packet.haslayer(Ether):
        eth = packet[Ether]
        eth_table = Table(title="🔌 Ethernet Frame", header_style="bold magenta", box=box.ROUNDED)
        eth_table.add_column("Field", style="bold cyan")
        eth_table.add_column("Value", style="bold white")
        eth_table.add_row("📤 Source MAC", eth.src)
        eth_table.add_row("📥 Destination MAC", eth.dst)
        eth_table.add_row("🔢 Type", hex(eth.type))
        console.print(eth_table)

    ip_table = Table(title="🌐 IP Packet", header_style="bold blue", box=box.ROUNDED)
    ip_table.add_column("Field", style="bold cyan")
    ip_table.add_column("Value", style="bold white")
    ip_table.add_row("📤 Source IP", ip.src)
    ip_table.add_row("📥 Destination IP", ip.dst)
    ip_table.add_row("🧭 Version", str(ip.version))
    ip_table.add_row("📦 Header Length", f"{ip.ihl * 4} bytes")
    ip_table.add_row("⏱ TTL", str(ip.ttl))
    ip_table.add_row("📡 Protocol", str(ip.proto))
    console.print(ip_table)

    # TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = tcp.sprintf("%flags%")
        tcp_table = Table(title="🚚 TCP Segment", header_style="bold green", box=box.ROUNDED)
        tcp_table.add_column("Field", style="bold cyan")
        tcp_table.add_column("Value", style="bold white")
        tcp_table.add_row("🔼 Source Port", str(tcp.sport))
        tcp_table.add_row("🔽 Destination Port", str(tcp.dport))
        tcp_table.add_row("🧾 Sequence Number", str(tcp.seq))
        tcp_table.add_row("✅ ACK", str(tcp.ack))
        tcp_table.add_row("🚩 Flags", flags)
        console.print(tcp_table)

        print_payload("TCP Payload", bytes(tcp.payload))

    # UDP
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        udp_table = Table(title="📦 UDP Segment", header_style="bold magenta", box=box.ROUNDED)
        udp_table.add_column("Field", style="bold cyan")
        udp_table.add_column("Value", style="bold white")
        udp_table.add_row("🔼 Source Port", str(udp.sport))
        udp_table.add_row("🔽 Destination Port", str(udp.dport))
        udp_table.add_row("📏 Length", str(udp.len))
        console.print(udp_table)

        print_payload("UDP Payload", bytes(udp.payload))

    # ICMP
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        icmp_table = Table(title="📢 ICMP Packet", header_style="bold red", box=box.ROUNDED)
        icmp_table.add_column("Field", style="bold cyan")
        icmp_table.add_column("Value", style="bold white")
        icmp_table.add_row("📌 Type", str(icmp.type))
        icmp_table.add_row("📎 Code", str(icmp.code))
        icmp_table.add_row("📮 Checksum", str(icmp.chksum))
        console.print(icmp_table)

        print_payload("ICMP Payload", bytes(icmp.payload))

    else:
        raw_payload = bytes(ip.payload)
        print_payload("Raw IP Payload", raw_payload)

def main():
    global user_ip_filter

    console.print("[bold green]🌐 Starting Fancy Network Packet Analyzer...[/bold green]")
    user_input = console.input("🔍 Enter IP to filter (leave blank for all): ").strip()

    if user_input:
        user_ip_filter = user_input
        console.print(f"📌 Filtering packets for IP: [cyan]{user_ip_filter}[/cyan]")
    else:
        console.print("📡 Capturing all packets (no IP filter applied).")

    console.print("💡 Press [bold red]Ctrl+C[/bold red] to stop.\n")
    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    main()
