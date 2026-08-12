#!/usr/bin/env python3

# Revision Counter:
# - Added -dst, revision tracking, -p/--port, --geoip-db: 1-5
# - Improved Exclusion Logic: 6
# - High-Performance Regex: 7
# - Kernel-Level BPF Injection: 8
# - Added Bandwidth Tracking (Bytes/Mbps) & ASN Enrichment: 9
# - Expanded ASN column width: 10
# - Added Interactive Terminal UI (TUI) using Python 'rich': 11
# - Replaced 'any' with dual simultaneous tcpdump instances: 12
# - Added countdown timer & progress bar, plus -cli flag: 13
# - Disabled per-second data updating & fixed destination IP regex truncation: 14
# - Fixed "Updated" timestamp & countdown bar: 15
# - Sub-revisions 16.1 - 16.7: UI tuning, -cli standalone guard, setup docs
# - Added Top Protocols & Ports table with PPS metric when -t < 40: 17
# - Sub-revisions 17.1 - 17.4: Service lookup dictionary, startup ramp-up, port decoupling
# - Major Release 18.0: Added dedicated DDoS Victim Target Focus Panel
# - Added "Script Started at" timestamp & -file flag for 15s /tmp/ .pcapng dump: 18.1
# - Added -s 128 snaplen flag to PCAP capture to limit file payload size: 18.2
# - Implemented Port Tier Priority: 18.3 - 18.6
# - Fixed DDoS Target Port resolution & snaplen ordering: 18.8
# - Added TOP-IP_config.txt parser (defaulting to eno1), fixed -p tier supremacy, forced dumpcap -s 128 global snaplen: 18.9
# - v19.2: Fixed double counting bug, protocol fallback (IP instead of UDP), added victim source tracking and ASN summary
# - v19.3: Added regex debug output to diagnose packet capture accuracy issues
REVISION = "19.3"

# Operational Requirements / Prerequisites (RHEL / Rocky Linux / CentOS):
# ------------------------------------------------------------------------
# dnf install -y python3-pip wireshark
# pip3 install rich geoip2

import subprocess
import time
import datetime
import re
import sys
import os
import argparse
import ipaddress
import select
import socket
import shutil
from collections import Counter, defaultdict

# --- Dependency Check: Rich ---
try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# --- Dependency Check: GeoIP2 ---
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

# --- ANSI Color Codes for CLI Mode ---
YELLOW = "\033[93m"
BOLD = "\033[1m"
RED = "\033[91m"
RESET = "\033[0m"

CONFIG_FILE = "TOP-IP_config.txt"
DEFAULT_DURATION = 15
DEFAULT_TOP_N = 10
DEFAULT_TCPDUMP_CMD = "/usr/sbin/tcpdump"

# Global timestamp recorded when the process launches
SCRIPT_START_TIME = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Comprehensive built-in map for network service resolution
KNOWN_SERVICES = {
    '20': 'FTP-DATA', '21': 'FTP', '22': 'SSH', '23': 'TELNET', '25': 'SMTP',
    '53': 'DNS', '67': 'DHCP-S', '68': 'DHCP-C', '69': 'TFTP', '80': 'HTTP',
    '88': 'KERBEROS', '110': 'POP3', '123': 'NTP', '137': 'NETBIOS-NS',
    '138': 'NETBIOS-DGM', '139': 'NETBIOS-SSN', '143': 'IMAP', '161': 'SNMP',
    '162': 'SNMP-TRAP', '179': 'BGP', '389': 'LDAP', '443': 'HTTPS',
    '445': 'SMB', '465': 'SMTPS', '500': 'ISAKMP/IPSEC', '514': 'SYSLOG',
    '5201': 'IPERF3', '636': 'LDAPS', '853': 'DOT (DNS/TLS)', '993': 'IMAPS', 
    '995': 'POP3S', '1194': 'OPENVPN', '1433': 'MSSQL', '1521': 'ORACLE', 
    '1701': 'L2TP', '1723': 'PPTP', '1812': 'RADIUS', '2049': 'NFS', 
    '3306': 'MYSQL', '3389': 'RDP', '4500': 'NAT-T/IPSEC', '5060': 'SIP', 
    '5061': 'SIPS', '5201': 'IPERF3', '5432': 'POSTGRESQL', '5900': 'VNC', '6379': 'REDIS', 
    '8080': 'HTTP-ALT', '8443': 'HTTPS-ALT', '8801': 'ZOOM', '9000': 'SONARQUBE', 
    '9092': 'KAFKA', '9200': 'ELASTIC', '27017': 'MONGODB'
}

WELL_KNOWN_MAX = 1023

def load_config():
    """Loads configuration options from TOP-IP_config.txt if present."""
    config = {"interfaces": ["eno1"]}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        key, val = key.strip().lower(), val.strip()
                        if key == "interfaces":
                            ifaces = [i.strip() for i in val.split(',') if i.strip()]
                            if ifaces:
                                config["interfaces"] = ifaces
        except Exception:
            pass
    return config

def identify_target_port(src_port, dst_port, target_p_cli=None):
    """
    Selects the true server/listening port over ephemeral client ports.

    Priority:
      - Explicit -p override
      - Known service ports
      - Well-known ports (<1024)
      - Destination port fallback
    """

    sp_str = str(src_port) if src_port else ""
    dp_str = str(dst_port) if dst_port else ""

    #
    # Explicit CLI override always wins
    #
    if target_p_cli:
        return str(target_p_cli)

    #
    # Prefer destination service ports
    #
    if dp_str in KNOWN_SERVICES:
        return dp_str

    #
    # Then source service ports
    #
    if sp_str in KNOWN_SERVICES:
        return sp_str

    try:
        s_val = int(sp_str) if sp_str else 65535
        d_val = int(dp_str) if dp_str else 65535

        #
        # Prefer well-known server ports
        #
        if d_val <= WELL_KNOWN_MAX and s_val > WELL_KNOWN_MAX:
            return dp_str

        if s_val <= WELL_KNOWN_MAX and d_val > WELL_KNOWN_MAX:
            return sp_str

    except ValueError:
        pass

    #
    # Default to destination port
    #
    return dp_str if dp_str else (sp_str if sp_str else "0")

def check_dependencies(cli_mode):
    """Verify required libraries are installed."""
    if not cli_mode and not RICH_AVAILABLE:
        print("\n[!] Error: The 'rich' library is required for TUI mode.", file=sys.stderr)
        print("    Install prerequisites using:\n", file=sys.stderr)
        print("    dnf install -y python3-pip wireshark", file=sys.stderr)
        print("    pip3 install rich geoip2\n", file=sys.stderr)
        print("    (Or run in basic text mode using -cli)\n", file=sys.stderr)
        sys.exit(1)

def format_bytes(byte_count):
    """Converts raw byte count into human-readable units."""
    if byte_count < 1024:
        return f"{byte_count} B"
    elif byte_count < 1024**2:
        return f"{byte_count / 1024:.2f} KB"
    elif byte_count < 1024**3:
        return f"{byte_count / (1024**2):.2f} MB"
    else:
        return f"{byte_count / (1024**3):.2f} GB"

def get_country_code(ip_str, geoip_country_reader):
    """Looks up ISO country code."""
    if not geoip_country_reader:
        return '??'
    try:
        res = geoip_country_reader.country(ip_str)
        return res.country.iso_code or '??'
    except Exception:
        return '??'

def get_asn_org(ip_str, geoip_asn_reader, is_first_row=False):
    """Looks up Autonomous System Organization name or returns usage hint on first row if missing."""
    if not geoip_asn_reader:
        if is_first_row:
            return 'Use --geoip-asn-db parameter for output'
        return 'N/A'
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
            return 'Private/Local'

        res = geoip_asn_reader.asn(ip_str)
        return res.autonomous_system_organization or f"AS{res.autonomous_system_number}" or 'Unknown'
    except geoip2.errors.AddressNotFoundError:
        return 'Not Found'
    except Exception:
        return 'N/A'

def get_port_service(proto, port_num):
    """Resolves port number to service name."""
    port_str = str(port_num)
    if port_str in KNOWN_SERVICES:
        return KNOWN_SERVICES[port_str]
    try:
        srv = socket.getservbyport(int(port_num), proto.lower())
        return srv.upper()
    except Exception:
        port_num_int = int(port_num)
        if port_num_int >= 1024:
            return 'EPHEMERAL/DYNAMIC'
        return 'CUSTOM'

def get_filter_from_file(filepath):
    """Reads the exclusion file and constructs a BPF filter string."""
    if not filepath or not os.path.exists(filepath):
        return ""
    
    with open(filepath, 'r') as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    
    if not lines:
        return ""

    content = " ".join(lines)
    if any(keyword in content.lower() for keyword in ['host', 'not', 'net', 'port', 'and']):
        return f"and ({content})"
    else:
        ip_list = " or ".join([f"host {ip}" for ip in lines])
        return f"and not ({ip_list})"

def make_ip_table(title, pkt_data, byte_data, total_pkts, top_n, duration, country_reader, asn_reader):
    """Generates a styled Rich Table for Top IPs."""
    table = Table(title=f"[bold yellow]{title}[/bold yellow]", box=box.ROUNDED, expand=True)
    
    table.add_column("CC", style="cyan", width=3, no_wrap=True)
    table.add_column("ASN / Organization", style="green", ratio=5, no_wrap=True)
    table.add_column("IP Address", style="bold white", ratio=2.5, no_wrap=True)
    table.add_column("Packets", justify="right", style="magenta", width=10, no_wrap=True)
    table.add_column("Throughput", justify="right", style="yellow", width=11, no_wrap=True)
    table.add_column("Share", justify="right", style="cyan", width=6, no_wrap=True)

    if not pkt_data:
        table.add_row("-", "No traffic captured", "-", "0", "0.00 Mbps", "0.0%")
        return table

    for idx, (ip, pkt_count) in enumerate(pkt_data.most_common(top_n)):
        c_code = get_country_code(ip, country_reader)
        asn_org = get_asn_org(ip, asn_reader, is_first_row=(idx == 0))

        b_count = byte_data.get(ip, 0)
        mbps = (b_count * 8) / (duration * 1_000_000)
        
        pct = (pkt_count / total_pkts) if total_pkts > 0 else 0.0
        pct_str = f"{pct * 100:>5.1f}%"

        table.add_row(
            c_code,
            asn_org,
            ip,
            f"{pkt_count:,}",
            f"{mbps:.2f} Mbps",
            pct_str
        )

    return table

def make_port_table(port_pkts, port_bytes, total_pkts, duration, top_n=10):
    """Generates a styled Rich Table for Top IP Protocols & Ports."""
    table = Table(title="[bold yellow]Top 10 IP Protocols & Ports[/bold yellow]", box=box.ROUNDED, expand=True)
    
    table.add_column("Proto / Port", style="bold cyan", ratio=2, no_wrap=True)
    table.add_column("Service", style="green", ratio=2, no_wrap=True)
    table.add_column("Packets", justify="right", style="magenta", ratio=2, no_wrap=True)
    table.add_column("Packets/Sec (PPS)", justify="right", style="bold yellow", ratio=2, no_wrap=True)
    table.add_column("Volume", justify="right", style="blue", ratio=2, no_wrap=True)
    table.add_column("Throughput", justify="right", style="yellow", ratio=2, no_wrap=True)

    if not port_pkts:
        table.add_row("-", "No port data captured", "0", "0.0 pps", "0 B", "0.00 Mbps")
        return table

    for proto_port, pkt_count in port_pkts.most_common(top_n):
        parts = proto_port.split('/')
        proto = parts[0] if len(parts) > 0 else "IP"
        port = parts[1] if len(parts) > 1 else "0"
        
        service_name = get_port_service(proto, port)
        pps = pkt_count / duration if duration > 0 else 0.0
        b_count = port_bytes.get(proto_port, 0)
        formatted_vol = format_bytes(b_count)
        mbps = (b_count * 8) / (duration * 1_000_000)

        table.add_row(
            f"{proto}/{port}",
            service_name,
            f"{pkt_count:,}",
            f"{pps:,.1f} pps",
            formatted_vol,
            f"{mbps:.2f} Mbps"
        )

    return table

def make_victim_panel(dst_p, dst_b, ip_port_counts, tot_p, duration, country_reader, asn_reader):
    """Generates a dedicated DDoS Victim Target Focus Panel for the Top 1 Destination IP."""
    if not dst_p or tot_p == 0:
        return Panel("[dim]No active victim target detected (no traffic captured).[/dim]", title="[bold red]🚨 DDoS VICTIM TARGET FOCUS[/bold red]", box=box.ROUNDED)

    top_victim_ip, victim_pkts = dst_p.most_common(1)[0]
    victim_bytes = dst_b.get(top_victim_ip, 0)
    victim_mbps = (victim_bytes * 8) / (duration * 1_000_000)
    victim_pps = victim_pkts / duration if duration > 0 else 0.0
    victim_pct = (victim_pkts / tot_p * 100) if tot_p > 0 else 0.0
    victim_asn = get_asn_org(top_victim_ip, asn_reader)
    if len(victim_asn) > 30:
        victim_asn = victim_asn[:27] + "..."
    victim_cc = get_country_code(top_victim_ip, country_reader)

    top_victim_ports = []
    if top_victim_ip in ip_port_counts:
        for p_key, p_cnt in ip_port_counts[top_victim_ip].most_common(3):
            parts = p_key.split('/')
            pr = parts[0]
            pt = parts[1]
            srv = get_port_service(pr, pt)
            p_pps = p_cnt / duration if duration > 0 else 0.0
            top_victim_ports.append(f"[cyan]{pr}/{pt}[/cyan] ({srv} - [bold yellow]{p_pps:,.1f} pps[/bold yellow])")

    ports_str = " │ ".join(top_victim_ports) if top_victim_ports else "None"

    line1 = (
        f"[bold white]Victim Target IP:[/bold white] [bold red]{top_victim_ip}[/bold red] [dim]({victim_cc} │ {victim_asn})[/dim]  │  "
        f"[bold white]Traffic Share:[/bold white] [bold black on red] {victim_pct:.1f}% [/bold black on red]"
    )
    line2 = (
        f"[bold white]Attack Rate:[/bold white] [bold magenta]{victim_pkts:,} pkts[/bold magenta] ([bold yellow]{victim_pps:,.1f} pps[/bold yellow])  │  "
        f"[bold white]Throughput:[/bold white] [bold yellow]{victim_mbps:.2f} Mbps[/bold yellow]  │  "
        f"[bold white]Target Ports:[/bold white] {ports_str}"
    )

    return Panel(f"{line1}\n{line2}", title="[bold red]🚨 DDoS VICTIM TARGET FOCUS[/bold red]", box=box.ROUNDED)

def build_dashboard(interfaces_str, duration, bpf, src_p, dst_p, src_b, dst_b, port_p, port_b, ip_port_counts, ip_port_bytes, tot_p, tot_b, top_n, country_reader, asn_reader, elapsed_seconds=0, last_updated_time="Initializing...", is_capturing=True, active_pcap_file=None):
    """Assembles the full Rich Layout dashboard."""
    show_port_table = top_n < 40

    layout = Layout()
    if show_port_table:
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="victim", size=4),
            Layout(name="ip_body", ratio=3),
            Layout(name="port_body", ratio=2),
            Layout(name="footer", size=3)
        )
    else:
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="victim", size=4),
            Layout(name="ip_body", ratio=5),
            Layout(name="footer", size=3)
        )

    layout["ip_body"].split_row(
        Layout(name="left"),
        Layout(name="right")
    )

    rem_secs = max(0, int(duration - elapsed_seconds))

    disp_bpf = bpf
    if len(disp_bpf) > 65:
        disp_bpf = disp_bpf[:62] + "..."

    header_line_1 = (
        f"[bold white]Interfaces:[/bold white] [green]{interfaces_str}[/green]  │  "
        f"[bold white]Interval:[/bold white] [yellow]{duration}s[/yellow]  │  "
        f"[bold white]Filter:[/bold white] [cyan]{disp_bpf}[/cyan]  │  "
        f"[bold white]Started:[/bold white] [dim]{SCRIPT_START_TIME}[/dim]  │  "
        f"[bold white]Last Updated:[/bold white] [bold white]{last_updated_time}[/bold white]"
    )
    
    if is_capturing:
        pcap_msg = f"  │  [bold red]💾 CAPTURING PCAP (-s 128):[/bold red] [bold yellow]{active_pcap_file}[/bold yellow]" if active_pcap_file else ""
        header_line_2 = (
            f"[bold white]⏱️  COUNTDOWN TO REFRESH:[/bold white] [bold yellow]{rem_secs:2d}s REMAINING[/bold yellow] "
            f"[dim](Interval: {duration}s)[/dim]{pcap_msg}"
        )
    else:
        header_line_2 = "[bold green]🔄 REFRESHING DATA...[/bold green]"

    layout["header"].update(Panel(f"{header_line_1}\n{header_line_2}", title=f"[bold cyan]TOP IP Analyzer Dashboard (Rev {REVISION})[/bold cyan]", box=box.ROUNDED))

    layout["victim"].update(make_victim_panel(dst_p, dst_b, ip_port_counts, tot_p, duration, country_reader, asn_reader))

    left_table = make_ip_table("Top Source IPs", src_p, src_b, tot_p, top_n, duration, country_reader, asn_reader)
    right_table = make_ip_table("Top Destination IPs", dst_p, dst_b, tot_p, top_n, duration, country_reader, asn_reader)

    layout["left"].update(left_table)
    layout["right"].update(right_table)

    if show_port_table:
        port_table = make_port_table(port_p, port_b, tot_p, duration, top_n=10)
        layout["port_body"].update(port_table)

    tot_vol_str = format_bytes(tot_b)
    avg_mbps = (tot_b * 8) / (duration * 1_000_000)
    avg_pps = tot_p / duration if duration > 0 else 0.0
    footer_text = (
        f"[bold white]Total Counted Packets:[/bold white] [bold magenta]{tot_p:,}[/bold magenta] ({avg_pps:,.1f} pps)   │   "
        f"[bold white]Total Volume:[/bold white] [bold blue]{tot_vol_str}[/bold blue]   │   "
        f"[bold white]Average Bandwidth:[/bold white] [bold yellow]{avg_mbps:.2f} Mbps[/bold yellow]"
    )
    layout["footer"].update(Panel(footer_text, box=box.ROUNDED))

    return layout

def print_cli_results(src_pkts, dst_pkts, src_bytes, dst_bytes, port_pkts, port_bytes, ip_port_counts, ip_port_bytes, victim_source_counts, attacker_asn_counts, total_pkts, total_bytes, top_n, duration, country_reader, asn_reader):
    """Outputs traditional scrolling CLI text results."""
    now = datetime.datetime.now()
    print(f"\n{YELLOW}{BOLD}{now.strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"Script Started at: {SCRIPT_START_TIME}")

    if dst_pkts and total_pkts > 0:
        top_victim_ip, victim_pkts = dst_pkts.most_common(1)[0]
        victim_bytes = dst_bytes.get(top_victim_ip, 0)
        victim_mbps = (victim_bytes * 8) / (duration * 1_000_000)
        victim_pps = victim_pkts / duration if duration > 0 else 0.0
        victim_pct = (victim_pkts / total_pkts * 100)
        victim_asn = get_asn_org(top_victim_ip, asn_reader)
        victim_cc = get_country_code(top_victim_ip, country_reader)

        top_victim_ports = []
        if top_victim_ip in ip_port_counts:
            for p_key, p_cnt in ip_port_counts[top_victim_ip].most_common(3):
                parts = p_key.split('/')
                pr, pt = parts[0], parts[1]
                srv = get_port_service(pr, pt)
                p_pps = p_cnt / duration if duration > 0 else 0.0
                top_victim_ports.append(f"{pr}/{pt} ({srv} - {p_pps:,.1f} pps)")

        ports_str = " | ".join(top_victim_ports) if top_victim_ports else "None"

        print(f"\n=== 🚨 DDoS VICTIM TARGET FOCUS ===")
        print(f"Target IP: {top_victim_ip} ({victim_cc} | {victim_asn}) | Traffic Share: {victim_pct:.1f}%")
        print(f"Attack Rate: {victim_pkts:,} pkts ({victim_pps:,.1f} pps) | Throughput: {victim_mbps:.2f} Mbps | Target Ports: {ports_str}")

        if top_victim_ip in victim_source_counts:
            print("\n--- Top Attack Sources ---")
            for src_ip, src_count in victim_source_counts[top_victim_ip].most_common(10):
                print(f"{src_ip:<20} {src_count:>12,d}")

    def render_cli_table(title, pkt_data, byte_data):
        print(f"\n--- {title} ---")
        if not pkt_data: 
            print("No data found.")
            return

        header = f"{'Country':<8} {'ASN / Organization':<45} {'IP Address':<28} {'Packets':>12} {'Throughput':>12}"
        print(header)
        print("-" * len(header))

        for idx, (ip, pkt_count) in enumerate(pkt_data.most_common(top_n)):
            c_code = get_country_code(ip, country_reader)
            asn_org = get_asn_org(ip, asn_reader, is_first_row=(idx == 0))

            b_count = byte_data.get(ip, 0)
            mbps = (b_count * 8) / (duration * 1_000_000)

            print(f"{c_code:<8} {asn_org:<45} {ip:<28} {pkt_count:>12d} {mbps:>10.2f} Mbps")

    render_cli_table("Top Source IPs", src_pkts, src_bytes)
    render_cli_table("Top Destination IPs", dst_pkts, dst_bytes)

    if top_n < 40 and port_pkts:
        print("\n--- Top 10 IP Protocols & Ports ---")
        p_header = f"{'Proto/Port':<15} {'Service':<20} {'Packets':>12} {'PPS':>12} {'Volume':>12} {'Throughput':>12}"
        print(p_header)
        print("-" * len(p_header))
        for proto_port, pkt_count in port_pkts.most_common(10):
            parts = proto_port.split('/')
            proto, port = (parts[0], parts[1]) if len(parts) > 1 else ("IP", "0")
            srv = get_port_service(proto, port)
            pps = pkt_count / duration if duration > 0 else 0.0
            b_cnt = port_bytes.get(proto_port, 0)
            vol_str = format_bytes(b_cnt)
            mbps = (b_cnt * 8) / (duration * 1_000_000)
            print(f"{proto_port:<15} {srv:<20} {pkt_count:>12d} {pps:>10.1f} pps {vol_str:>12} {mbps:>10.2f} Mbps")

    if attacker_asn_counts:
        print("\n--- Top Attacking ASNs ---")
        for asn_name, asn_count in attacker_asn_counts.most_common(10):
            print(f"{asn_name:<40} {asn_count:>12,d}")

    total_vol_str = format_bytes(total_bytes)
    avg_mbps = (total_bytes * 8) / (duration * 1_000_000)
    avg_pps = total_pkts / duration if duration > 0 else 0.0
    print(f"\nTotal Packets: {total_pkts:,} ({avg_pps:,.1f} pps) | Total Volume: {total_vol_str} | Avg Speed: {avg_mbps:.2f} Mbps")
    print("\n" + "="*120 + "\n")

def trigger_pcap_dump(interfaces, bpf):
    """Spawns a background raw PCAP capture process to /tmp/ explicitly truncating snaplen with -s 128 globally before interfaces."""
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%MM%S')
    pcap_filename = f"/tmp/sherlock_capture_{timestamp}.pcapng"

    dumpcap_bin = shutil.which("dumpcap")
    tcpdump_bin = shutil.which("tcpdump") or DEFAULT_TCPDUMP_CMD

    cmd = []
    if dumpcap_bin:
        cmd = [dumpcap_bin, "-P", "-s", "128", "-a", "duration:15", "-w", pcap_filename]
        for iface in interfaces:
            cmd.extend(["-i", iface])
        if bpf:
            cmd.extend(["-f", bpf])
    else:
        cmd = [tcpdump_bin, "-s", "128", "-i", interfaces[0], "-G", "15", "-W", "1", "-w", pcap_filename, "-n"]
        if bpf:
            cmd.append(bpf)

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc, pcap_filename
    except Exception:
        return None, None

def capture_and_analyze(interfaces, duration, tcpdump_cmd, ipv6_only, filter_string, target_dst, target_port, live_tui=None, ui_args=None, last_results=None, last_updated_time="Initializing...", active_pcap_file=None):
    src_pkt_counts, dst_pkt_counts = Counter(), Counter()
    src_byte_counts, dst_byte_counts = Counter(), Counter()
    port_pkt_counts, port_byte_counts = Counter(), Counter()
    ip_port_counts = defaultdict(Counter)
    ip_port_bytes = defaultdict(Counter)
    victim_source_counts = defaultdict(Counter)
    attacker_asn_counts = Counter()
    total_packets = 0
    total_bytes = 0
    
    # DEBUG COUNTERS
    total_lines_read = 0
    total_matches = 0
    sample_lines = []

    if ipv6_only:
        pattern = re.compile(r"IP6 ([0-9a-fA-F:]+)(?:\.(\d+))? > ([0-9a-fA-F:]+)(?:\.(\d+))?.*length (\d+)")
    else:
        pattern = re.compile(r"IP (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\.(\d+))? > (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\.(\d+))?.*length (\d+)")

    bpf = "ip6" if ipv6_only else "ip"
    if target_dst: bpf += f" and dst {target_dst}"
    if target_port: bpf += f" and port {target_port}"
    if filter_string: bpf += f" {filter_string}"

    processes = []
    readers = []

    for iface in interfaces:
        cmd = [tcpdump_cmd, "-i", iface, "-n", "-l", bpf]
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            processes.append(p)
            readers.append(p.stdout)
        except Exception:
            pass

    if not readers:
        return src_pkt_counts, dst_pkt_counts, src_byte_counts, dst_byte_counts, port_pkt_counts, port_byte_counts, ip_port_counts, ip_port_bytes, victim_source_counts, attacker_asn_counts, total_packets, total_bytes, bpf

    start_time = time.time()
    last_ui_update = 0
    spinner_chars = ['-', '\\', '|', '/']
    spinner_idx = 0

    if live_tui is None:
        print(f"Capturing on [{', '.join(interfaces)}] for {duration}s... ", end='', flush=True)

    try:
        while True:
            elapsed = time.time() - start_time
            if elapsed >= duration:
                break

            if time.time() - last_ui_update > 0.2:
                last_ui_update = time.time()
                if live_tui and ui_args:
                    prev_sp, prev_dp, prev_sb, prev_db, prev_pp, prev_pb, prev_ipp, prev_ipb, prev_tp, prev_tb = last_results if last_results else (Counter(), Counter(), Counter(), Counter(), Counter(), Counter(), defaultdict(Counter), defaultdict(Counter), 0, 0)
                    
                    dashboard = build_dashboard(
                        ", ".join(interfaces), duration, bpf,
                        prev_sp, prev_dp, prev_sb, prev_db, prev_pp, prev_pb, prev_ipp, prev_ipb,
                        prev_tp, prev_tb, ui_args.top,
                        ui_args.country_reader, ui_args.asn_reader,
                        elapsed_seconds=elapsed,
                        last_updated_time=last_updated_time,
                        is_capturing=True,
                        active_pcap_file=active_pcap_file
                    )
                    live_tui.update(dashboard)
                elif live_tui is None:
                    rem = max(0, int(duration - elapsed))
                    sys.stdout.write(f"\rCapturing on [{', '.join(interfaces)}] for {duration}s... {spinner_chars[spinner_idx]} ({rem}s left)")
                    sys.stdout.flush()
                    spinner_idx = (spinner_idx + 1) % len(spinner_chars)

            rlist, _, _ = select.select(readers, [], [], 0.05)
            for stream in rlist:
                line = stream.readline()
                if not line:
                    continue

                total_lines_read += 1
                
                # Store first 5 unmatched lines for debugging
                match = pattern.search(line)
                if not match and len(sample_lines) < 5:
                    sample_lines.append(line.strip())
                
                if match:
                    total_matches += 1
                    s_ip = match.group(1)
                    s_port = match.group(2)
                    d_ip = match.group(3)
                    d_port = match.group(4)
                    pkt_len = int(match.group(5))

                    src_pkt_counts[s_ip] += 1
                    dst_pkt_counts[d_ip] += 1
                    src_byte_counts[s_ip] += pkt_len
                    dst_byte_counts[d_ip] += pkt_len

                    victim_source_counts[d_ip][s_ip] += 1

                    if ui_args and ui_args.asn_reader:
                        attacker_asn = get_asn_org(s_ip, ui_args.asn_reader)
                        attacker_asn_counts[attacker_asn] += 1

                    line_lower = line.lower()

                    if "flags [" in line_lower:
                        proto = "TCP"
                    elif "udp" in line_lower:
                        proto = "UDP"
                    else:
                        proto = "IP"

                    #
                    # Victim-aware port selection
                    #
                    if target_dst:

                        #
                        # Traffic headed toward victim
                        #
                        if d_ip == target_dst and d_port:
                            target_p = d_port

                        #
                        # Traffic originating from victim
                        #
                        elif s_ip == target_dst and s_port:
                            target_p = s_port

                        else:
                            target_p = identify_target_port(
                                s_port,
                                d_port,
                                target_p_cli=target_port
                            )

                    else:
                        target_p = identify_target_port(
                            s_port,
                            d_port,
                            target_p_cli=target_port
                        )

                    if target_p and target_p != "0":

                        port_key = f"{proto}/{target_p}"

                        if target_dst:

                            if d_ip == target_dst:
                                port_pkt_counts[port_key] += 1
                                port_byte_counts[port_key] += pkt_len

                                ip_port_counts[d_ip][port_key] += 1
                                ip_port_bytes[d_ip][port_key] += pkt_len

                        else:

                            port_pkt_counts[port_key] += 1
                            port_byte_counts[port_key] += pkt_len

                            ip_port_counts[d_ip][port_key] += 1
                            ip_port_bytes[d_ip][port_key] += pkt_len

                    total_packets += 1
                    total_bytes += pkt_len

        if live_tui is None:
            sys.stdout.write("\r" + " " * 80 + "\r")
            print("Capture complete.")
            # DEBUG OUTPUT
            print(f"\n{'='*80}")
            print(f"DEBUG STATS:")
            print(f"  Total lines read from tcpdump: {total_lines_read}")
            print(f"  Total regex matches: {total_matches}")
            if total_lines_read > 0:
                print(f"  Match rate: {total_matches/total_lines_read*100:.1f}% ({total_lines_read - total_matches} unmatched)")
            else:
                print(f"  Match rate: 0% (no lines read)")
            print(f"\nSample of UNMATCHED lines (first 5):")
            for i, line in enumerate(sample_lines, 1):
                print(f"  {i}. {line}")
            print(f"{'='*80}\n")

    finally:
        for p in processes:
            p.terminate()

    return src_pkt_counts, dst_pkt_counts, src_byte_counts, dst_byte_counts, port_pkt_counts, port_byte_counts, ip_port_counts, ip_port_bytes, victim_source_counts, attacker_asn_counts, total_packets, total_bytes, bpf

class UIArgs:
    def __init__(self, top, country_reader, asn_reader):
        self.top = top
        self.country_reader = country_reader
        self.asn_reader = asn_reader

if __name__ == "__main__":
    local_cfg = load_config()

    parser = argparse.ArgumentParser(description="TOP IP Analyzer", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-i", "--interfaces", nargs="+", default=local_cfg["interfaces"], help="Network interfaces to capture on.")
    parser.add_argument("-d", "--duration", type=int, default=DEFAULT_DURATION, help="Interval length in seconds.")
    parser.add_argument("-t", "--top", type=int, default=DEFAULT_TOP_N, help="Top N entries per table.")
    parser.add_argument("-6", "--ipv6", action="store_true", help="Capture IPv6 traffic only.")
    parser.add_argument("-x", "--exclude-file", help="File containing IPs or a raw tcpdump filter string.")
    parser.add_argument("-dst", "--target-destination", help="Target destination IP.")
    parser.add_argument("-p", "--port", type=int, help="Target port.")
    parser.add_argument("--geoip-db", help="Path to MaxMind GeoLite2-Country.mmdb")
    parser.add_argument("--geoip-asn-db", help="Path to MaxMind GeoLite2-ASN.mmdb")
    parser.add_argument("-cli", "--cli", action="store_true", help="Run in traditional scrolling text CLI mode instead of TUI dashboard.")
    parser.add_argument("-file", "--file", action="store_true", help="Dump a single 15-second raw .pcapng packet capture file to /tmp/ with -s 128 snaplen.")
    args = parser.parse_args()

    check_dependencies(args.cli)

    filter_string = get_filter_from_file(args.exclude_file)
    
    country_reader = None
    asn_reader = None

    if args.geoip_db and GEOIP2_AVAILABLE:
        try:
            country_reader = geoip2.database.Reader(args.geoip_db)
        except Exception:
            pass

    if args.geoip_asn_db and GEOIP2_AVAILABLE:
        try:
            asn_reader = geoip2.database.Reader(args.geoip_asn_db)
        except Exception:
            pass

    interfaces_label = ", ".join(args.interfaces)

    pcap_proc = None
    pcap_filepath = None
    if args.file:
        bpf_rule = "ip6" if args.ipv6 else "ip"
        if args.target_destination: bpf_rule += f" and dst {args.target_destination}"
        if args.port: bpf_rule += f" and port {args.port}"
        if filter_string: bpf_rule += f" {filter_string}"
        
        pcap_proc, pcap_filepath = trigger_pcap_dump(args.interfaces, bpf_rule)
        if pcap_filepath and args.cli:
            print(f"💾 Spawned 15s PCAP Dump (-s 128): {pcap_filepath}")

    target_duration = args.duration
    if target_duration >= 15:
        ramp_intervals = [2, 4, 8]
    else:
        ramp_intervals = []

    try:
        if args.cli:
            print(f"TOP IP Analyzer (Revision {REVISION}) [CLI Mode] Loop (Press Ctrl+C to stop)")
            print(f"Script Started at: {SCRIPT_START_TIME}")
            print(f"Interfaces: {interfaces_label}, Target Duration: {target_duration}s, Top: {args.top}")
            print("--------------------------------------------------------------------------------\n")
            
            for dur in ramp_intervals:
                s_p, d_p, s_b, d_b, p_p, p_b, ip_p, ip_b, vsc, aac, tot_p, tot_b, _ = capture_and_analyze(
                    args.interfaces, dur, DEFAULT_TCPDUMP_CMD, 
                    args.ipv6, filter_string, args.target_destination, args.port,
                    live_tui=None
                )
                print_cli_results(s_p, d_p, s_b, d_b, p_p, p_b, ip_p, ip_b, vsc, aac, tot_p, tot_b, args.top, dur, country_reader, asn_reader)

            while True:
                s_p, d_p, s_b, d_b, p_p, p_b, ip_p, ip_b, vsc, aac, tot_p, tot_b, _ = capture_and_analyze(
                    args.interfaces, target_duration, DEFAULT_TCPDUMP_CMD, 
                    args.ipv6, filter_string, args.target_destination, args.port,
                    live_tui=None
                )
                print_cli_results(s_p, d_p, s_b, d_b, p_p, p_b, ip_p, ip_b, vsc, aac, tot_p, tot_b, args.top, target_duration, country_reader, asn_reader)
        else:
            ui_context = UIArgs(args.top, country_reader, asn_reader)
            initial_layout = build_dashboard(interfaces_label, target_duration, "Initializing capture...", Counter(), Counter(), Counter(), Counter(), Counter(), Counter(), defaultdict(Counter), defaultdict(Counter), 0, 0, args.top, country_reader, asn_reader, elapsed_seconds=0, last_updated_time="Initializing...", is_capturing=True, active_pcap_file=pcap_filepath)

            last_data_results = None
            last_updated_time = "Initializing..."

            with Live(initial_layout, console=console, refresh_per_second=5, screen=True) as live:
                for dur in ramp_intervals:
                    s_p, d_p, s_b, d_b, p_p, p_b, ip_p, ip_b, vsc, aac, tot_p, tot_b, active_bpf = capture_and_analyze(
                        args.interfaces, dur, DEFAULT_TCPDUMP_CMD, 
                        args.ipv6, filter_string, args.target_destination, args.port,
                        live_tui=live, ui_args=ui_context, last_results=last_data_results,
                        last_updated_time=last_updated_time, active_pcap_file=pcap_filepath
                    )
                    last_data_results = (s_p, d_p, s_b, d_b, p_p, p_b, ip_p, ip_b, tot_p, tot_b)
                    last_updated_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    final_dashboard = build_dashboard(
                        interfaces_label, dur, active_bpf,
                        s_p, d_p, s_b, d_b, p_p, p_b, ip_p, ip_b,
                        tot_p, tot_b, args.top, country_reader, asn_reader,
                        elapsed_seconds=dur,
                        last_updated_time=last_updated_time,
                        is_capturing=False, active_pcap_file=pcap_filepath
                    )
                    live.update(final_dashboard)

                while True:
                    s_p, d_p, s_b, d_b, p_p, p_b, ip_p, ip_b, vsc, aac, tot_p, tot_b, active_bpf = capture_and_analyze(
                        args.interfaces, target_duration, DEFAULT_TCPDUMP_CMD, 
                        args.ipv6, filter_string, args.target_destination, args.port,
                        live_tui=live, ui_args=ui_context, last_results=last_data_results,
                        last_updated_time=last_updated_time, active_pcap_file=pcap_filepath
                    )
                    
                    last_data_results = (s_p, d_p, s_b, d_b, p_p, p_b, ip_p, ip_b, tot_p, tot_b)
                    last_updated_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    final_dashboard = build_dashboard(
                        interfaces_label, target_duration, active_bpf,
                        s_p, d_p, s_b, d_b, p_p, p_b, ip_p, ip_b,
                        tot_p, tot_b, args.top, country_reader, asn_reader,
                        elapsed_seconds=target_duration,
                        last_updated_time=last_updated_time,
                        is_capturing=False, active_pcap_file=pcap_filepath
                    )
                    live.update(final_dashboard)
    except KeyboardInterrupt:
        if country_reader: country_reader.close()
        if asn_reader: asn_reader.close()
        print("\nExiting TOP IP Analyzer.")
