"""Tests for goodluck.py"""

import argparse
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

import goodluck


class TestParsePortsSingle(unittest.TestCase):
    """Port parsing: single ports and comma lists."""

    def test_single_port(self):
        self.assertEqual(goodluck.parse_ports("80"), [80])

    def test_comma_list(self):
        self.assertEqual(goodluck.parse_ports("22,80,443"), [22, 80, 443])

    def test_duplicates_removed(self):
        result = goodluck.parse_ports("80,80,80")
        self.assertEqual(result, [80])

    def test_sorted_output(self):
        result = goodluck.parse_ports("443,22,80")
        self.assertEqual(result, [22, 80, 443])


class TestParsePortsRange(unittest.TestCase):
    """Port parsing: ranges."""

    def test_simple_range(self):
        result = goodluck.parse_ports("1-5")
        self.assertEqual(result, [1, 2, 3, 4, 5])

    def test_mixed_range_and_list(self):
        result = goodluck.parse_ports("22,80,100-102")
        self.assertEqual(result, [22, 80, 100, 101, 102])

    def test_invalid_range_reversed(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            goodluck.parse_ports("1024-1")

    def test_port_zero_rejected(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            goodluck.parse_ports("0")

    def test_port_above_65535_rejected(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            goodluck.parse_ports("65536")

    def test_non_numeric_rejected(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            goodluck.parse_ports("abc")


class TestServiceLookup(unittest.TestCase):
    """Service name resolution."""

    def test_known_port_http(self):
        name = goodluck.get_service_name(80, "tcp")
        self.assertIn(name.lower(), ("http", "www", "www-http"))

    def test_known_port_ssh(self):
        name = goodluck.get_service_name(22, "tcp")
        self.assertEqual(name, "ssh")

    def test_unknown_port(self):
        name = goodluck.get_service_name(59999, "tcp")
        self.assertEqual(name, "")


class TestBannerClean(unittest.TestCase):
    """Banner cleaning."""

    def test_clean_multiline(self):
        raw = "SSH-2.0-OpenSSH_8.9p1\r\nProtocol mismatch."
        result = goodluck._clean_banner(raw)
        self.assertNotIn("\r\n", result)
        self.assertIn("SSH-2.0-OpenSSH_8.9p1", result)


class TestExtractVersion(unittest.TestCase):
    """Version extraction from banners."""

    def test_empty_banner(self):
        self.assertEqual(goodluck.extract_version(""), "")

    def test_ssh_banner(self):
        result = goodluck.extract_version("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        self.assertIn("SSH-2.0", result)

    def test_long_banner_truncated(self):
        long_banner = "X" * 200
        result = goodluck.extract_version(long_banner)
        self.assertTrue(len(result) <= 84)  # 80 + "..."


class TestArgParser(unittest.TestCase):
    """Argument parser construction."""

    def test_defaults(self):
        parser = goodluck.build_parser()
        args = parser.parse_args(["192.168.1.1"])
        self.assertEqual(args.target, "192.168.1.1")
        self.assertEqual(args.ports, "1-1024")
        self.assertEqual(args.method, "connect")
        self.assertEqual(args.threads, 100)
        self.assertEqual(args.timeout, 1.0)
        self.assertIsNone(args.output)
        self.assertFalse(args.quiet)

    def test_all_flags(self):
        parser = goodluck.build_parser()
        args = parser.parse_args([
            "10.0.0.1", "-p", "22,80", "-m", "syn",
            "-t", "50", "--timeout", "2.5", "-o", "out.json", "-q"
        ])
        self.assertEqual(args.target, "10.0.0.1")
        self.assertEqual(args.ports, "22,80")
        self.assertEqual(args.method, "syn")
        self.assertEqual(args.threads, 50)
        self.assertEqual(args.timeout, 2.5)
        self.assertEqual(args.output, "out.json")
        self.assertTrue(args.quiet)

    def test_invalid_method_rejected(self):
        parser = goodluck.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["target", "-m", "xmas"])


class TestWriteJson(unittest.TestCase):
    """JSON output."""

    def test_write_and_read(self):
        results = [{"port": 22, "state": "open", "service": "ssh", "version": ""}]
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            goodluck.write_json(results, path, "127.0.0.1", "connect", 1.23)
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data["target"], "127.0.0.1")
            self.assertEqual(data["method"], "connect")
            self.assertEqual(len(data["results"]), 1)
            self.assertEqual(data["results"][0]["port"], 22)
        finally:
            os.unlink(path)


class TestVersion(unittest.TestCase):
    """Module version."""

    def test_version_string(self):
        self.assertEqual(goodluck.__version__, "1.0.0")


if __name__ == "__main__":
    unittest.main()
