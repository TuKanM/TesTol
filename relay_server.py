import asyncio
import socket
import json
import os
from typing import Tuple, Dict

# Load config from environment variables or default
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
CONNECT_IP = os.getenv("CONNECT_IP", "104.19.229.21")
CONNECT_PORT = int(os.getenv("CONNECT_PORT", "443"))
FAKE_SNI = os.getenv("FAKE_SNI", "hcaptcha.com").encode()

print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    TuKaN Relay Server                        ║
╠══════════════════════════════════════════════════════════════╣
║  Listen: {LISTEN_HOST}:{LISTEN_PORT}                                      
║  Target: {CONNECT_IP}:{CONNECT_PORT}                                     
║  Fake SNI: {FAKE_SNI.decode()}                                          
╚══════════════════════════════════════════════════════════════╝
""")

# Store active connections
connections: Dict[Tuple, asyncio.StreamReader] = {}


def create_fake_client_hello(sni: bytes) -> bytes:
    """Create a fake TLS ClientHello with the specified SNI"""
    # TLS 1.2 ClientHello template (minimal)
    tls_version = b"\x03\x03"  # TLS 1.2
    
    # Random 32 bytes
    import os
    random_bytes = os.urandom(32)
    
    # Session ID (32 bytes)
    session_id = os.urandom(32)
    
    # Cipher suites
    cipher_suites = b"\x00\x2f\x00\x35\x00\x3c\x00\x3d\xc0\x2b\xc0\x2f\xcc\xa8\xcc\xa9"
    
    # Compression methods
    compression = b"\x01\x00"
    
    # Extensions
    # SNI Extension
    sni_len = len(sni)
    sni_extension = (
        b"\x00\x00" +  # SNI extension type
        (sni_len + 5).to_bytes(2, 'big') +  # Total length
        (sni_len + 3).to_bytes(2, 'big') +  # Server name list length
        b"\x00" +  # HostName type
        sni_len.to_bytes(2, 'big') +  # HostName length
        sni  # HostName
    )
    
    # Build ClientHello
    client_hello = (
        b"\x16" +  # Handshake
        tls_version +  # TLS version
        (len(random_bytes) + len(session_id) + len(cipher_suites) + len(compression) + len(sni_extension) + 6).to_bytes(2, 'big') +
        b"\x01" +  # ClientHello
        b"\x00\x00\x00" +  # Length placeholder
        tls_version +
        random_bytes +
        len(session_id).to_bytes(1, 'big') + session_id +
        len(cipher_suites).to_bytes(2, 'big') + cipher_suites +
        compression +
        len(sni_extension).to_bytes(2, 'big') + sni_extension
    )
    
    return client_hello


async def handle_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
    """Handle incoming client connection"""
    client_addr = client_writer.get_extra_info('peername')
    print(f"[+] New connection from {client_addr}")
    
    try:
        # Create connection to target server
        target_reader, target_writer = await asyncio.open_connection(CONNECT_IP, CONNECT_PORT)
        print(f"[+] Connected to target {CONNECT_IP}:{CONNECT_PORT}")
        
        # Send fake TLS ClientHello first
        fake_hello = create_fake_client_hello(FAKE_SNI)
        target_writer.write(fake_hello)
        await target_writer.drain()
        print(f"[+] Sent fake ClientHello with SNI: {FAKE_SNI.decode()}")
        
        # Wait a bit for the fake packet to be processed
        await asyncio.sleep(0.1)
        
        # Create bidirectional relay tasks
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
        
        # Run both directions concurrently
        task1 = asyncio.create_task(relay(client_reader, target_writer, "C->T"))
        task2 = asyncio.create_task(relay(target_reader, client_writer, "T->C"))
        
        # Wait for either task to complete
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
    
    print(f"[*] Relay server running on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[*] Forwarding to {CONNECT_IP}:{CONNECT_PORT}")
    print(f"[*] Fake SNI: {FAKE_SNI.decode()}")
    
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
