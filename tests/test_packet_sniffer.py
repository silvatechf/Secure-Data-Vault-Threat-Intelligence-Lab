"""
tests/test_packet_sniffer.py
===============================

Tests build small, synthetic .pcap files in memory with scapy's packet
CRAFTING (not live capture -- no raw sockets, no root privileges needed),
write them to a temp file, then run this project's own analyzer against
that file. This proves the parsing logic against real pcap bytes, not
just mocked data structures.
"""

from scapy.all import DNS, IP, TCP, UDP, DNSQR, wrpcap
from scapy.layers.http import HTTP, HTTPRequest

from app.forensics.packet_sniffer import analyze_pcap, detect_port_scans, save_suspicious_flows


def _write_pcap(tmp_path, packets, filename="capture.pcap"):
    pcap_path = tmp_path / filename
    wrpcap(str(pcap_path), packets)
    return str(pcap_path)


class TestHttpExtraction:
    def test_http_request_is_extracted(self, tmp_path):
        packet = (
            IP(src="10.0.0.5", dst="93.184.216.34")
            / TCP(sport=54321, dport=80)
            / HTTP()
            / HTTPRequest(
                Method=b"GET", Host=b"example.com", Path=b"/index.html", User_Agent=b"TestAgent/1.0"
            )
        )
        pcap_path = _write_pcap(tmp_path, [packet])

        summary = analyze_pcap(pcap_path)

        assert len(summary.http_requests) == 1
        assert summary.http_requests[0]["method"] == "GET"
        assert summary.http_requests[0]["host"] == "example.com"
        assert summary.http_requests[0]["path"] == "/index.html"


class TestTlsSniExtraction:
    def test_sni_hostname_is_extracted_from_client_hello(self, tmp_path):
        from scapy.layers.tls.extensions import TLS_Ext_ServerName, ServerName
        from scapy.layers.tls.handshake import TLSClientHello
        from scapy.layers.tls.record import TLS

        client_hello = TLSClientHello(
            version=0x0303,
            ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=b"evil-c2-server.example")])],
        )
        packet = (
            IP(src="10.0.0.5", dst="1.2.3.4")
            / TCP(sport=54321, dport=443)
            / TLS(msg=[client_hello])
        )
        pcap_path = _write_pcap(tmp_path, [packet])

        summary = analyze_pcap(pcap_path)

        assert "evil-c2-server.example" in summary.tls_sni_hostnames


class TestDnsExtraction:
    def test_dns_query_is_extracted(self, tmp_path):
        packet = (
            IP(src="10.0.0.5", dst="8.8.8.8")
            / UDP(sport=54321, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="suspicious-domain.example"))
        )
        pcap_path = _write_pcap(tmp_path, [packet])

        summary = analyze_pcap(pcap_path)

        assert "suspicious-domain.example" in summary.dns_queries

    def test_multiple_dns_queries_are_all_captured(self, tmp_path):
        packets = [
            IP(src="10.0.0.5", dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            for domain in ["one.example", "two.example", "three.example"]
        ]
        pcap_path = _write_pcap(tmp_path, packets)

        summary = analyze_pcap(pcap_path)

        assert set(summary.dns_queries) == {"one.example", "two.example", "three.example"}


class TestPortScanDetection:
    def test_many_distinct_syn_ports_from_one_source_is_flagged(self, tmp_path):
        # 15 SYN packets to 15 different ports from the same source -- a
        # textbook port scan signature.
        packets = [
            IP(src="10.0.0.99", dst="10.0.0.1") / TCP(sport=40000 + i, dport=1000 + i, flags="S")
            for i in range(15)
        ]
        pcap_path = _write_pcap(tmp_path, packets)

        results = detect_port_scans(pcap_path)

        assert "10.0.0.99" in results
        assert len(results["10.0.0.99"]) == 15

    def test_normal_traffic_to_few_ports_is_not_flagged(self, tmp_path):
        # A normal client: a handful of connections to the same 2 ports
        # (e.g. repeatedly reconnecting to a web server).
        packets = [
            IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=50000 + i, dport=80, flags="S")
            for i in range(5)
        ] + [
            IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=50100 + i, dport=443, flags="S")
            for i in range(5)
        ]
        pcap_path = _write_pcap(tmp_path, packets)

        results = detect_port_scans(pcap_path)

        assert results == {}

    def test_syn_ack_responses_are_not_counted_as_scan_attempts(self, tmp_path):
        """
        A SYN-ACK is a RESPONSE to a connection attempt, not a new probe --
        counting these would flag a normal server answering many clients
        as if it were the attacker.
        """
        packets = [
            IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=80, dport=40000 + i, flags="SA")
            for i in range(20)
        ]
        pcap_path = _write_pcap(tmp_path, packets)

        results = detect_port_scans(pcap_path)

        assert results == {}


class TestSaveSuspiciousFlows:
    def test_only_packets_from_flagged_ips_are_saved(self, tmp_path):
        packets = [
            IP(src="10.0.0.99", dst="10.0.0.1") / TCP(dport=22, flags="S"),
            IP(src="10.0.0.99", dst="10.0.0.1") / TCP(dport=23, flags="S"),
            IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=80, flags="S"),  # not flagged
        ]
        input_pcap = _write_pcap(tmp_path, packets)
        output_pcap = str(tmp_path / "suspicious.pcap")

        count = save_suspicious_flows(input_pcap, source_ips=["10.0.0.99"], output_path=output_pcap)

        assert count == 2
        summary = analyze_pcap(output_pcap)  # sanity: the file is readable
        assert summary is not None
