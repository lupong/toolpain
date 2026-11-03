"""M4: sinkhole DNS + catch-all TCP, exercised on loopback (no Docker)."""

from __future__ import annotations

import asyncio
import socket
import ssl

import pytest
from dnslib import QTYPE, DNSRecord

from sandbox.sandbox import parse_sinkhole_logs
from sandbox.sinkhole.server import Sinkhole, parse_overrides, parse_sni


@pytest.fixture()
async def sink():
    s = Sinkhole(
        bind="127.0.0.1",
        answer_ip="10.66.7.53",
        tcp_ports=(0, 0),
        dns_port=0,
        overrides={"fixture.local": "10.66.7.80"},
    )
    await s.start()
    yield s
    await s.stop()


async def _dns(port: int, name: str, qtype: str = "A") -> DNSRecord:
    loop = asyncio.get_running_loop()
    query = DNSRecord.question(name, qtype).pack()
    fut: asyncio.Future[bytes] = loop.create_future()

    class P(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
            if not fut.done():
                fut.set_result(data)

    transport, _ = await loop.create_datagram_endpoint(P, remote_addr=("127.0.0.1", port))
    transport.sendto(query)
    try:
        return DNSRecord.parse(await asyncio.wait_for(fut, 3))
    finally:
        transport.close()


async def test_dns_answers_everything_with_sinkhole(sink: Sinkhole) -> None:
    reply = await _dns(sink.bound_dns_port, "collector.sinkhole.local")
    assert [str(rr.rdata) for rr in reply.rr] == ["10.66.7.53"]
    reply = await _dns(sink.bound_dns_port, "anything.example.com")
    assert [str(rr.rdata) for rr in reply.rr] == ["10.66.7.53"]
    reply = await _dns(sink.bound_dns_port, "fixture.local")
    assert [str(rr.rdata) for rr in reply.rr] == ["10.66.7.80"]
    aaaa = await _dns(sink.bound_dns_port, "collector.sinkhole.local", "AAAA")
    assert aaaa.rr == []
    names = [(r["host"], r["qtype"]) for r in sink.records if r["proto"] == "dns"]
    assert ("collector.sinkhole.local", "A") in names
    assert QTYPE.AAAA == 28


async def test_http_request_logged_with_body(sink: Sinkhole) -> None:
    port = sink.bound_tcp_ports[0]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    body = "report=weekly&data=decoy-secret-xyz"
    writer.write(
        (
            f"POST /collect HTTP/1.1\r\nHost: collector.sinkhole.local\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}"
        ).encode()
    )
    await writer.drain()
    assert (await reader.read(100)).startswith(b"HTTP/1.1 200")
    writer.close()
    rec = next(r for r in sink.records if r["proto"] == "http")
    assert rec["host"] == "collector.sinkhole.local"
    assert rec["request_line"] == "POST /collect HTTP/1.1"
    assert "decoy-secret-xyz" in rec["data"]


async def test_tls_sni_logged_without_certificate(sink: Sinkhole) -> None:
    port = sink.bound_tcp_ports[1]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # client side of a test against our own sinkhole
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        await asyncio.open_connection(
            "127.0.0.1",
            port,
            ssl=ctx,
            server_hostname="collector.sinkhole.local",
            ssl_handshake_timeout=3,
        )
    for _ in range(20):
        if any(r["proto"] == "tls" for r in sink.records):
            break
        await asyncio.sleep(0.1)
    rec = next(r for r in sink.records if r["proto"] == "tls")
    assert rec["host"] == "collector.sinkhole.local"


async def test_raw_tcp_logged(sink: Sinkhole) -> None:
    sock = socket.create_connection(("127.0.0.1", sink.bound_tcp_ports[0]), 3)
    sock.sendall(b"hello")
    sock.close()
    for _ in range(30):
        if any(r["proto"] == "tcp" for r in sink.records):
            break
        await asyncio.sleep(0.1)
    assert any(r["proto"] == "tcp" and r["data"] == "hello" for r in sink.records)


def test_helpers() -> None:
    assert parse_overrides("a.local=1.2.3.4, b.local=5.6.7.8") == {
        "a.local": "1.2.3.4",
        "b.local": "5.6.7.8",
    }
    assert parse_sni(b"\x16\x03\x01") is None
    lines = '{"ts": 1.0, "proto": "dns", "host": "x.local", "qtype": "A", "src_ip": "1.1.1.1"}\n'
    lines += '{"ts": 2.0, "proto": "ready", "ports": [80]}\nnot json\n'
    recs = parse_sinkhole_logs(lines)
    assert len(recs) == 1 and recs[0].host == "x.local"
