import asyncio
import socket
import os
import struct
import json

# Load config
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
CONNECT_IP = os.getenv("CONNECT_IP", "104.19.229.21")
CONNECT_PORT = int(os.getenv("CONNECT_PORT", "443"))
FAKE_SNI = os.getenv("FAKE_SNI", "hcaptcha.com").encode()

print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    TuKaN SOCKS5 Relay                        ║
╠══════════════════════════════════════════════════════════════╣
║  Listen: {LISTEN_HOST}:{LISTEN_PORT}                                      
║  Target: {CONNECT_IP}:{CONNECT_PORT}                                     
║  Fake SNI: {FAKE_SNI.decode()}                                          
╚══════════════════════════════════════════════════════════════╝
""")


def create_fake_client_hello(sni: bytes) -> bytes:
    import os
    tls_version = b"\x03\x03"
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)
    cipher_suites = b"\x00\x2f\x00\x35\x00\x3c\x00\x3d\xc0\x2b\xc0\x2f\xcc\xa8\xcc\xa9"
    compression = b"\x01\x00"
    
    sni_len = len(sni)
    sni_extension = (
        b"\x00\x00" +
        (sni_len + 5).to_bytes(2, 'big') +
        (sni_len + 3).to_bytes(2, 'big') +
        b"\x00" +
        sni_len.to_bytes(2, 'big') +
        sni
    )
    
    client_hello = (
        b"\x16" +
        tls_version +
        (len(random_bytes) + len(session_id) + len(cipher_suites) + len(compression) + len(sni_extension) + 6).to_bytes(2, 'big') +
        b"\x01" +
        b"\x00\x00\x00" +
        tls_version +
        random_bytes +
        len(session_id).to_bytes(1, 'big') + session_id +
        len(cipher_suites).to_bytes(2, 'big') + cipher_suites +
        compression +
        len(sni_extension).to_bytes(2, 'big') + sni_extension
    )
    return client_hello


async def socks5_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Perform SOCKS5 handshake"""
    # Read version and methods
    data = await reader.read(2)
    if data[0] != 0x05:
        return False
    
    nmethods = data[1]
    methods = await reader.read(nmethods)
    
    # No authentication
    writer.write(b"\x05\x00")
    await writer.drain()
    return True


async def handle_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
    """Handle SOCKS5 client connection"""
    client_addr = client_writer.get_extra_info('peername')
    print(f"[+] New SOCKS5 connection from {client_addr}")
    
    try:
        # SOCKS5 handshake
        if not await socks5_handshake(client_reader, client_writer):
            client_writer.close()
            return
        
        # Read request
        data = await client_reader.read(4)
        if data[0] != 0x05:
            return
        
        cmd = data[1]
        if cmd != 0x01:  # CONNECT
            client_writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        
        addr_type = data[3]
        
        if addr_type == 0x01:  # IPv4
            addr_data = await client_reader.read(4)
            port_data = await client_reader.read(2)
            port = struct.unpack('>H', port_data)[0]
            print(f"[-] Client requested connection to {'.'.join(map(str, addr_data))}:{port}")
            # Always redirect to our target
        elif addr_type == 0x03:  # Domain
            domain_len = await client_reader.read(1)
            domain = await client_reader.read(domain_len[0])
            port_data = await client_reader.read(2)
            port = struct.unpack('>H', port_data)[0]
            print(f"[-] Client requested connection to {domain.decode()}:{port}")
        
        # Connect to target
        target_reader, target_writer = await asyncio.open_connection(CONNECT_IP, CONNECT_PORT)
        print(f"[+] Connected to target {CONNECT_IP}:{CONNECT_PORT}")
        
        # Send fake ClientHello
        fake_hello = create_fake_client_hello(FAKE_SNI)
        target_writer.write(fake_hello)
        await target_writer.drain()
        print(f"[+] Sent fake ClientHello with SNI: {FAKE_SNI.decode()}")
        
        # Send success response
        client_writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await client_writer.drain()
        
        # Relay data bidirectionally
        async def relay(reader, writer, direction: str):
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
                    print(f"[{direction}] Relayed {len(data)} bytes")
            except Exception as e:
                print(f"[{direction}] Error: {e}")
            finally:
                writer.close()
        
        task1 = asyncio.create_task(relay(client_reader, target_writer, "C->T"))
        task2 = asyncio.create_task(relay(target_reader, client_writer, "T->C"))
        
        await asyncio.gather(task1, task2)
        
    except Exception as e:
        print(f"[-] Error handling {client_addr}: {e}")
    finally:
        client_writer.close()
        print(f"[-] Connection closed from {client_addr}")


async def main():
    server = await asyncio.start_server(
        handle_client,
        host=LISTEN_HOST,
        port=LISTEN_PORT
    )
    
    print(f"[*] SOCKS5 Relay running on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[*] Forwarding to {CONNECT_IP}:{CONNECT_PORT}")
    
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
