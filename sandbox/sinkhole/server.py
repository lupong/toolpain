"""Sinkhole: answers every DNS name with its own IP and logs whatever connects.

Runs as one container on the per-scan internal network (``.53``). Self-contained on purpose
(stdlib + ``dnslib`` only) so the image stays tiny. Every observation is emitted as one JSON
line on stdout (``docker logs``) and kept in memory for tests.

* DNS (UDP+TCP): every A query -> ``answer_ip``; AAAA/other -> empty NOERROR. Optional
  ``overrides`` map specific names (e.g. ``fixture.local``) to other in-sandbox IPs.
* TCP catch-all on a list of ports: plain HTTP (request line, headers, body preview), TLS
  (SNI parsed from the ClientHello, no certificate needed), or raw bytes. Then it closes.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import struct
import sys
import time
from collections.abc import Callable
from typing import Any

from dnslib import QTYPE, RR, A, DNSRecord

DEFAULT_PORTS = (80, 443, 8080, 8443, 8000, 3000, 5000, 9000, 25, 21, 22)
READ_TIMEOUT = 2.0
BODY_LIMIT = 4096

Emit = Callable[[dict[str, Any]], None]


def parse_sni(data: bytes) -> str | None:
    """Extract the SNI host name from a TLS ClientHello, or None."""
    try:
        if len(data) < 6 or data[0] != 0x16:
            return None
        pos = 5 + 4  # record header + handshake header
        pos += 2 + 32  # client version + random
        pos += 1 + data[pos]  # session id
        (cs_len,) = struct.unpack_from("!H", data, pos)
        pos += 2 + cs_len
        pos += 1 + data[pos]  # compression methods
        (ext_total,) = struct.unpack_from("!H", data, pos)
        pos += 2
        end = min(len(data), pos + ext_total)
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack_from("!HH", data, pos)
            pos += 4
            if ext_type == 0 and ext_len >= 5:
                name_len = struct.unpack_from("!H", data, pos + 3)[0]
                return data[pos + 5 : pos + 5 + name_len].decode("ascii", "replace")
            pos += ext_len
    except (IndexError, struct.error):
        return None
    return None


def parse_http(data: bytes) -> tuple[str, dict[str, str], str] | None:
    """Return (request_line, headers, body_preview) for a plain HTTP request."""
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    if not lines or " HTTP/" not in lines[0]:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    return lines[0], headers, body[:BODY_LIMIT].decode("utf-8", "replace")


class Sinkhole:
    def __init__(
        self,
        *,
        bind: str = "0.0.0.0",
        answer_ip: str = "127.0.0.1",
        tcp_ports: tuple[int, ...] = DEFAULT_PORTS,
        dns_port: int = 53,
        overrides: dict[str, str] | None = None,
        emit: Emit | None = None,
    ) -> None:
        self.bind = bind
        self.answer_ip = answer_ip
        self.tcp_ports = tcp_ports
        self.dns_port = dns_port
        self.overrides = {k.lower().rstrip("."): v for k, v in (overrides or {}).items()}
        self._emit = emit
        self.records: list[dict[str, Any]] = []
        self.bound_tcp_ports: list[int] = []
        self.bound_dns_port: int = 0
        self._servers: list[asyncio.AbstractServer] = []
        self._transport: asyncio.DatagramTransport | None = None

    # -- logging ---------------------------------------------------------
    def record(self, proto: str, **fields: Any) -> dict[str, Any]:
        rec = {"ts": time.time(), "proto": proto, **fields}
        self.records.append(rec)
        if self._emit:
            self._emit(rec)
        return rec

    # -- DNS -------------------------------------------------------------
    def answer_dns(self, wire: bytes, src_ip: str) -> bytes | None:
        try:
            request = DNSRecord.parse(wire)
        except Exception:
            return None
        reply = request.reply()
        for q in request.questions:
            name = str(q.qname).rstrip(".").lower()
            qtype = QTYPE[q.qtype]
            self.record("dns", host=name, qtype=qtype, src_ip=src_ip)
            if qtype == "A":
                ip = self.overrides.get(name, self.answer_ip)
                reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(ip), ttl=1))
        return reply.pack()

    # -- TCP catch-all -----------------------------------------------------
    async def _handle_tcp(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int
    ) -> None:
        peer = writer.get_extra_info("peername") or ("", 0)
        src = peer[0]
        try:
            data = await self._read_request(reader)
            sni = parse_sni(data)
            http = parse_http(data) if sni is None else None
            if sni is not None:
                self.record("tls", host=sni, port=port, src_ip=src)
            elif http:
                line, headers, body = http
                host = headers.get("host", "").split(":")[0]
                self.record(
                    "http",
                    host=host,
                    port=port,
                    src_ip=src,
                    request_line=line,
                    headers=headers,
                    data=body,
                )
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
            else:
                self.record("tcp", port=port, src_ip=src, data=data[:256].decode("latin-1"))
        except (TimeoutError, ConnectionError):
            self.record("tcp", port=port, src_ip=src, data="")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def _read_request(self, reader: asyncio.StreamReader) -> bytes:
        buf = b""
        try:
            buf = await asyncio.wait_for(reader.read(8192), READ_TIMEOUT)
            if b"\r\n\r\n" in buf:
                head, _, body = buf.partition(b"\r\n\r\n")
                want = 0
                for line in head.decode("latin-1").lower().split("\r\n"):
                    if line.startswith("content-length:"):
                        want = min(int(line.split(":")[1].strip() or 0), BODY_LIMIT)
                while len(body) < want:
                    more = await asyncio.wait_for(reader.read(4096), READ_TIMEOUT)
                    if not more:
                        break
                    body += more
                buf = head + b"\r\n\r\n" + body
        except TimeoutError:
            pass
        return buf

    # -- lifecycle ---------------------------------------------------------
    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        sinkhole = self

        class DnsProtocol(asyncio.DatagramProtocol):
            def connection_made(self, transport: asyncio.BaseTransport) -> None:
                sinkhole._transport = transport  # type: ignore[assignment]

            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                reply = sinkhole.answer_dns(data, addr[0])
                if reply and sinkhole._transport:
                    sinkhole._transport.sendto(reply, addr)

        transport, _ = await loop.create_datagram_endpoint(
            DnsProtocol, local_addr=(self.bind, self.dns_port)
        )
        self._transport = transport  # type: ignore[assignment]
        self.bound_dns_port = transport.get_extra_info("sockname")[1]

        async def dns_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                head = await asyncio.wait_for(reader.readexactly(2), READ_TIMEOUT)
                wire = await reader.readexactly(struct.unpack("!H", head)[0])
                peer = writer.get_extra_info("peername") or ("", 0)
                reply = self.answer_dns(wire, peer[0])
                if reply:
                    writer.write(struct.pack("!H", len(reply)) + reply)
                    await writer.drain()
            except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                writer.close()

        dns_server = await asyncio.start_server(
            dns_tcp, self.bind, self.bound_dns_port if self.dns_port else 0
        )
        self._servers.append(dns_server)

        for port in self.tcp_ports:
            try:
                server = await asyncio.start_server(
                    lambda r, w, p=port: self._handle_tcp(r, w, p), self.bind, port
                )
            except OSError:
                continue
            self._servers.append(server)
            self.bound_tcp_ports.append(server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()
        for server in self._servers:
            server.close()
            await server.wait_closed()
        self._servers.clear()


def _own_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))  # no packet sent; picks the local interface
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _emit_stdout(rec: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(rec) + "\n")
    sys.stdout.flush()


def parse_overrides(raw: str) -> dict[str, str]:
    pairs = (item.split("=", 1) for item in raw.split(",") if "=" in item)
    return {k.strip(): v.strip() for k, v in pairs}


async def serve() -> None:
    ports = os.environ.get("SINKHOLE_PORTS")
    sink = Sinkhole(
        answer_ip=os.environ.get("SINKHOLE_IP") or _own_ip(),
        tcp_ports=tuple(int(p) for p in ports.split(",")) if ports else DEFAULT_PORTS,
        dns_port=int(os.environ.get("SINKHOLE_DNS_PORT", "53")),
        overrides=parse_overrides(os.environ.get("SINKHOLE_OVERRIDES", "")),
        emit=_emit_stdout,
    )
    await sink.start()
    _emit_stdout({"ts": time.time(), "proto": "ready", "ports": sink.bound_tcp_ports})
    await asyncio.Event().wait()


def main() -> None:
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
