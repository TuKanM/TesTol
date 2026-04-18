#!/usr/bin/env python3
"""
TuKaN HTTP Proxy with Fake SNI Injection
Works like a DPI bypass by sending a fake TLS ClientHello first.
"""

import asyncio
import os
import socket
import struct
import ssl
from urllib.parse import urlparse

# ========== Configuration ==========
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
CONNECT_IP = os.getenv("CONNECT_IP", "104.19.229.21")
CONNECT_PORT = int(os.getenv("CONNECT_PORT", "443"))
FAKE_SNI = os.getenv("FAKE_SNI", "hcaptcha.com").encode()
# ===================================

print(f"""
╔══════════════════════════════════════════════════════════════╗
║              TuKaN HTTP Proxy with SNI Spoofing              ║
╠══════════════════════════════════════════════════════════════╣
║  Listen:   {LISTEN_HOST}:{LISTEN_PORT}
║  Target:   {CONNECT_IP}:{CONNECT_PORT}
║  Fake SNI: {FAKE_SNI.decode()}
╚══════════════════════════════════════════════════════════════╝
""")

def create_fake_client_hello(sni: bytes) -> bytes:
    """
    Build a realistic TLS 1.2 ClientHello with the given SNI.
    This packet is sent to the target server BEFORE any real data.
    """
    # TLS 1.2
    tls_version = b"\x03\x03"
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)

    # Common cipher suites
    cipher_suites = (
        b"\xc0\x2b\xc0\x2f\xcc\xa8\xcc\xa9\xc0\x2c\xc0\x30"
        b"\xc0\x09\xc0\x13\x00\x2f\x00\x35\x00\x3c\x00\x3d"
    )
    compression = b"\x01\x00"

    # SNI extension
    sni_len = len(sni)
    sni_extension = (
        b"\x00\x00" +  # extension type server_name
        (sni_len + 5).to_bytes(2, 'big') +
        (sni_len + 3).to_bytes(2, 'big') +
        b"\x00" +
        sni_len.to_bytes(2, 'big') +
        sni
    )

    # Other extensions to look real
    other_extensions = (
        b"\x00\x0b\x00\x02\x01\x00" +      # ec_point_formats
        b"\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01" +
        b"\x00\x12\x00\x00"               # signed_certificate_timestamp
    )

    extensions = sni_extension + other_extensions

    # Handshake header
    handshake_type = b"\x01"
    handshake_len = (
        2 + 32 + 1 + 32 + 2 + len(cipher_suites) + 1 + 2 + len(extensions)
    )
    handshake_len_bytes = handshake_len.to_bytes(3, 'big')

    # Record layer
    record = (
        b"\x16" +                         # handshake record
        tls_version +
        (handshake_len + 4).to_bytes(2, 'big') +  # length of record
        handshake_type +
        handshake_len_bytes +
        tls_version +
        random_bytes +
        len(session_id).to_bytes(1, 'big') + session_id +
        len(cipher_suites).to_bytes(2, 'big') + cipher_suites +
        compression +
        len(extensions).to_bytes(2, 'big') + extensions
    )
    return record

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle an incoming HTTP CONNECT request (HTTPS proxy)"""
    addr = writer.get_extra_info('peername')
    print(f"[+] New connection from {addr}")

    try:
        # Read first line of HTTP request
        data = await reader.readline()
        if not data:
            writer.close()
            return

        parts = data.split()
        if len(parts) < 3 or parts[0] != b'CONNECT':
            # Not a CONNECT request – we only support HTTPS proxy
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        # Parse destination (ignored, we always redirect to our target)
        # Actually we will still forward to the requested host but through our fake SNI?
        # For DPI bypass we must send fake SNI to the real target IP.
        # Here we simply ignore the client's requested host and always connect to our CONNECT_IP.
        host_header = parts[1].decode()
        print(f"[-] Client requested: {host_header} (will be overridden)")

        # Send HTTP 200 Connection Established
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        # Now create connection to our real target
        target_reader, target_writer = await asyncio.open_connection(CONNECT_IP, CONNECT_PORT)
        print(f"[+] Connected to target {CONNECT_IP}:{CONNECT_PORT}")

        # Send fake ClientHello to the target (this is the key for DPI bypass)
        fake_hello = create_fake_client_hello(FAKE_SNI)
        target_writer.write(fake_hello)
        await target_writer.drain()
        print(f"[+] Sent fake ClientHello with SNI: {FAKE_SNI.decode()}")

        # Start bidirectional relaying
        async def relay(r, w, direction):
            try:
                while True:
                    chunk = await r.read(8192)
                    if not chunk:
                        break
                    w.write(chunk)
                    await w.drain()
                    print(f"[{direction}] {len(chunk)} bytes")
            except Exception as e:
                print(f"[{direction}] Error: {e}")
            finally:
                w.close()

        task_client_to_target = asyncio.create_task(relay(reader, target_writer, "C→T"))
        task_target_to_client = asyncio.create_task(relay(target_reader, writer, "T→C"))

        await asyncio.gather(task_client_to_target, task_target_to_client)

    except Exception as e:
        print(f"[-] Exception: {e}")
    finally:
        writer.close()
        print(f"[-] Connection closed from {addr}")

async def main():
    server = await asyncio.start_server(
        handle_client,
        host=LISTEN_HOST,
        port=LISTEN_PORT
    )
    print(f"[*] HTTP Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
