"""Tests voor _rewrite_host_header en _inject_xforwarded in proxy.py."""
import sys
sys.path.insert(0, "/home/admin/py_proxy")

from proxy import _rewrite_host_header, _inject_xforwarded


def test_rewrite_host_single_request():
    data = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
    result = _rewrite_host_header(data, "127.0.0.1:8088")
    assert b"Host: 127.0.0.1:8088\r\n" in result
    assert b"Host: example.com" not in result


def test_rewrite_host_keepalive():
    req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    data = req + req
    result = _rewrite_host_header(data, "127.0.0.1:8088")
    assert result.count(b"Host: 127.0.0.1:8088\r\n") == 2
    assert b"Host: example.com" not in result


def test_inject_xforwarded_single_request():
    data = b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n"
    result = _inject_xforwarded(data, "1.2.3.4")
    assert b"X-Forwarded-For: 1.2.3.4\r\n" in result
    # XFF staat na de request-regel, vóór Host
    xff_pos = result.index(b"X-Forwarded-For")
    host_pos = result.index(b"Host:")
    assert xff_pos < host_pos


def test_inject_xforwarded_keepalive():
    req = b"GET /api HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n"
    data = req + b"POST /submit HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n"
    result = _inject_xforwarded(data, "5.6.7.8")
    assert result.count(b"X-Forwarded-For: 5.6.7.8\r\n") == 2


def test_inject_xforwarded_does_not_corrupt_body():
    data = b"POST / HTTP/1.1\r\nHost: h\r\n\r\nhello world"
    result = _inject_xforwarded(data, "1.1.1.1")
    assert result.endswith(b"hello world")
    assert b"X-Forwarded-For: 1.1.1.1\r\n" in result


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"  OK  {name}")
    print("Alle tests geslaagd.")
