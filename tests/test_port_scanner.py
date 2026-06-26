import socket
from port_scanner import parse_ports, resolve_host


def test_parse_ports_ranges_and_lists():
    assert parse_ports("20-22") == [20, 21, 22]
    assert parse_ports("22,80,443") == [22, 80, 443]
    assert parse_ports("1-3,5,7-8") == [1, 2, 3, 5, 7, 8]


def test_parse_ports_filters_out_of_range_and_duplicates():
    assert parse_ports("0,65536,22,22") == [22]


def test_resolve_host_localhost():
    ip = resolve_host("localhost")
    # Should return a string IPv4 address like '127.0.0.1'
    assert isinstance(ip, str)
    assert ip.count(".") == 3
