"""
app/forensics/packet_sniffer.py
==================================

B-02: packet analysis. This implementation reads and analyzes .pcap
files (packet captures) rather than sniffing live traffic off the wire.

WHY PCAP FILES INSTEAD OF LIVE SNIFFING
--------------------------------------------
Live packet sniffing needs a raw socket, which needs root/administrator
privileges (or a specific capability grant) on every operating system --
that's a genuine barrier to anyone cloning this repo just to run the
tests or try the tool, not a minor inconvenience. The project blueprint
explicitly allows for this: "scapy (or pcap file parser)." Every function
here works identically whether the pcap came from a live `tcpdump`/scapy
capture on a real network or a file someone hands you during an incident
response engagement -- which is, realistically, the more common forensics
scenario: analyzing a capture, not capturing live.

WHAT THIS EXTRACTS
------------------------
- HTTP headers (method, host, user-agent) from unencrypted HTTP traffic
- DNS queries (what domains were being looked up)
- TLS SNI (Server Name Indication -- visible even in ENCRYPTED HTTPS
  traffic, because the destination hostname is sent in the clear during
  the TLS handshake, before encryption starts)
- Port scan patterns (see detect_port_scan below)
"""

from collections import defaultdict
from dataclasses import dataclass, field

from scapy.all import IP, TCP, UDP, rdpcap, wrpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS


@dataclass
class TrafficSummary:
    http_requests: list[dict] = field(default_factory=list)
    dns_queries: list[str] = field(default_factory=list)
    tls_sni_hostnames: list[str] = field(default_factory=list)


def analyze_pcap(pcap_path: str) -> TrafficSummary:
    """
    Reads every packet in a .pcap file and extracts the protocol-level
    details listed in the module docstring. Packets that don't match any
    of the layers this function looks for are silently skipped -- most
    real captures contain plenty of traffic (ACKs, keepalives) that
    carries no forensically interesting content.
    """
    packets = rdpcap(pcap_path)
    summary = TrafficSummary()

    for packet in packets:
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            summary.http_requests.append(
                {
                    "method": _decode(http_layer.Method),
                    "host": _decode(http_layer.Host),
                    "path": _decode(http_layer.Path),
                    "user_agent": _decode(getattr(http_layer, "User_Agent", None)),
                }
            )

        if packet.haslayer(DNSQR):
            query_name = _decode(packet[DNSQR].qname).rstrip(".")
            summary.dns_queries.append(query_name)

        if packet.haslayer(TLSClientHello):
            sni = _extract_sni(packet[TLSClientHello])
            if sni:
                summary.tls_sni_hostnames.append(sni)

    return summary


def _decode(value) -> str | None:
    """Scapy fields are often raw bytes -- normalize to a plain string for anything downstream."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _extract_sni(client_hello) -> str | None:
    """
    The SNI hostname is buried in the TLS ClientHello's extensions list --
    this walks that list looking for the server_name extension
    specifically (extension type 0).
    """
    extensions = getattr(client_hello, "ext", None) or []
    for extension in extensions:
        server_names = getattr(extension, "servernames", None)
        if server_names:
            for entry in server_names:
                hostname = getattr(entry, "servername", None)
                if hostname:
                    return _decode(hostname)
    return None


# --- Port scan detection ---------------------------------------------------

PORT_SCAN_DISTINCT_PORT_THRESHOLD = 10


def detect_port_scans(pcap_path: str) -> dict[str, list[int]]:
    """
    A simple, well-established heuristic: if a single source IP sends
    SYN packets (connection attempts) to many DISTINCT destination ports
    on the same host, that's a classic port scan signature -- a normal
    client talks to a small, predictable set of ports (80, 443, maybe a
    couple more), not dozens of different ones in quick succession.

    Returns a dict of {source_ip: [scanned_ports]} for every source IP
    that crossed the threshold -- empty dict means no scan pattern found.
    """
    packets = rdpcap(pcap_path)
    ports_by_source = defaultdict(set)

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            tcp_layer = packet[TCP]
            # SYN flag set, ACK flag not set = a new connection attempt,
            # not a response to one -- exactly the signature of probing
            # for open ports rather than normal two-way traffic.
            if tcp_layer.flags & 0x02 and not (tcp_layer.flags & 0x10):
                ports_by_source[packet[IP].src].add(tcp_layer.dport)

    return {
        ip: sorted(ports)
        for ip, ports in ports_by_source.items()
        if len(ports) >= PORT_SCAN_DISTINCT_PORT_THRESHOLD
    }


def save_suspicious_flows(pcap_path: str, source_ips: list[str], output_path: str) -> int:
    """
    Filters a pcap down to only the packets involving the given source
    IPs (e.g. IPs flagged by detect_port_scans) and writes them to a new
    pcap file -- useful for handing a focused, much smaller capture to
    someone doing deeper manual investigation, instead of the entire
    original capture. Returns the number of packets written.
    """
    packets = rdpcap(pcap_path)
    suspicious = [
        p for p in packets if p.haslayer(IP) and p[IP].src in source_ips
    ]
    wrpcap(output_path, suspicious)
    return len(suspicious)
