import asyncio
import json
import os
import socket
import ssl
from datetime import datetime

# بارگذاری تنظیمات
with open('config.json', 'r') as f:
    config = json.load(f)

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = int(config["LISTEN_PORT"])
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = int(config["CONNECT_PORT"])
FAKE_SNI = config["FAKE_SNI"]

print(f"""
╔════════════════════════════════════════╗
║     TuKaN Proxy Server - Railway       ║
╠════════════════════════════════════════╣
║ Listen: {LISTEN_HOST}:{LISTEN_PORT}
║ Target: {CONNECT_IP}:{CONNECT_PORT}
║ SNI: {FAKE_SNI}
╚════════════════════════════════════════╝
""")

async def handle_client(reader, writer):
    """مدیریت اتصالات کلاینت"""
    client_addr = writer.get_extra_info('peername')
    print(f"[+] New connection from {client_addr}")
    
    try:
        # دریافت درخواست اولیه از کلاینت
        data = await asyncio.wait_for(reader.read(1024), timeout=10)
        if not data:
            writer.close()
            return
        
        # ساخت هدر جعلی TLS
        fake_hello = create_fake_tls_hello()
        
        # اتصال به سرور مقصد
        target_reader, target_writer = await asyncio.open_connection(
            CONNECT_IP, CONNECT_PORT
        )
        
        # ارسال TLS Hello جعلی
        target_writer.write(fake_hello)
        await target_writer.drain()
        
        # منتظر پاسخ
        response = await asyncio.wait_for(target_reader.read(4096), timeout=5)
        
        # ارسال پاسخ به کلاینت
        writer.write(response)
        await writer.drain()
        
        # شروع پروکسی دوطرفه
        await asyncio.gather(
            proxy_data(reader, target_writer, "client->target"),
            proxy_data(target_reader, writer, "target->client")
        )
        
    except asyncio.TimeoutError:
        print(f"[-] Timeout for {client_addr}")
    except Exception as e:
        print(f"[-] Error for {client_addr}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def proxy_data(reader, writer, direction):
    """پروکسی داده بین دو سوکت"""
    try:
        while True:
            data = await reader.read(8192)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except:
        pass
    finally:
        writer.close()

def create_fake_tls_hello():
    """ساخت TLS ClientHello جعلی با SNI دلخواه"""
    
    # قالب ساده TLS ClientHello
    tls_version = b'\x03\x03'  # TLS 1.2
    random = os.urandom(32)
    session_id = os.urandom(32)
    
    # ساخت SNI Extension
    sni_bytes = FAKE_SNI.encode()
    sni_extension = (
        b'\x00\x00' +  # Extension type: server_name
        (len(sni_bytes) + 5).to_bytes(2, 'big') +  # Extension length
        (len(sni_bytes) + 3).to_bytes(2, 'big') +  # Server name list length
        b'\x00' +  # Name type: hostname
        len(sni_bytes).to_bytes(2, 'big') +
        sni_bytes
    )
    
    # ساخت کامل ClientHello
    client_hello = (
        b'\x16' +  # Handshake
        tls_version +  # Version
        (len(random) + len(session_id) + 4 + len(sni_extension) + 2).to_bytes(2, 'big') +  # Length
        b'\x01' +  # Handshake type: ClientHello
        b'\x00\x00\x00' +  # Handshake length placeholder
        tls_version +  # Client version
        random +
        (len(session_id)).to_bytes(1, 'big') + session_id +
        b'\x00\x02' +  # Cipher suites length
        b'\x13\x02' +  # Cipher suite: TLS_AES_256_GCM_SHA384
        b'\x01\x00' +  # Compression methods length
        b'\x00' +  # No compression
        (len(sni_extension)).to_bytes(2, 'big') +
        sni_extension
    )
    
    # Fix handshake length
    handshake_len = len(client_hello) - 5
    client_hello = client_hello[:3] + handshake_len.to_bytes(3, 'big') + client_hello[6:]
    
    return client_hello

async def main():
    server = await asyncio.start_server(
        handle_client,
        LISTEN_HOST,
        LISTEN_PORT
    )
    
    print(f"[✓] Server running on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[✓] Forwarding to {CONNECT_IP}:{CONNECT_PORT}")
    print(f"[✓] Fake SNI: {FAKE_SNI}")
    print("\n[!] Waiting for connections...\n")
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
