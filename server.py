import asyncio
import json
import os
import uuid
import base64
import struct
import socket
from datetime import datetime

# ==================== تنظیمات ====================
CONFIG = {
    "LISTEN_HOST": "0.0.0.0",
    "LISTEN_PORT": 40443,
    "CONNECT_IP": "104.19.229.21",
    "CONNECT_PORT": 443,
    "FAKE_SNI": "hcaptcha.com"
}

# تولید UUID یکتا
SERVER_UUID = str(uuid.uuid4())
PROJECT_NAME = os.environ.get("RAILWAY_SERVICE_NAME", "TuKaN")
RAILWAY_URL = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")

if not RAILWAY_URL:
    RAILWAY_URL = f"{PROJECT_NAME}.up.railway.app"

# ==================== Sniffer کلاس ====================
class ProtocolSniffer:
    """شناسایی پروتکل ترافیک"""
    
    @staticmethod
    def sniff(data: bytes) -> dict:
        """تشخیص نوع پروتکل از روی داده"""
        result = {
            "protocol": "unknown",
            "tls": False,
            "http": False,
            "websocket": False,
            "vless": False,
            "details": {}
        }
        
        if not data:
            return result
        
        # بررسی TLS/SSL
        if data[0] == 0x16 and len(data) > 2:
            result["tls"] = True
            result["protocol"] = "tls"
            # استخراج SNI از TLS ClientHello
            sni = ProtocolSniffer.extract_sni(data)
            if sni:
                result["details"]["sni"] = sni
        
        # بررسی HTTP
        if data.startswith(b'GET') or data.startswith(b'POST') or data.startswith(b'PUT') or data.startswith(b'HEAD'):
            result["http"] = True
            result["protocol"] = "http"
            # استخراج هدرها
            lines = data.split(b'\r\n')
            if lines:
                result["details"]["method"] = lines[0].decode('utf-8', errors='ignore')
        
        # بررسی WebSocket upgrade
        if b'Upgrade: websocket' in data or b'upgrade: websocket' in data:
            result["websocket"] = True
            result["protocol"] = "websocket"
        
        # بررسی VLESS (ساده شده)
        if len(data) > 20 and data[0] == 0x01:
            result["vless"] = True
            result["protocol"] = "vless"
        
        return result
    
    @staticmethod
    def extract_sni(data: bytes) -> str:
        """استخراج SNI از TLS ClientHello"""
        try:
            if len(data) < 43:
                return ""
            
            # موقعیت شروع extension ها
            pos = 43
            if len(data) < pos + 2:
                return ""
            
            session_id_len = data[pos]
            pos += 1 + session_id_len
            
            if len(data) < pos + 2:
                return ""
            
            cipher_suites_len = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2 + cipher_suites_len
            
            if len(data) < pos + 1:
                return ""
            
            compression_methods_len = data[pos]
            pos += 1 + compression_methods_len
            
            if len(data) < pos + 2:
                return ""
            
            extensions_len = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2
            
            end = pos + extensions_len
            while pos < end and pos + 4 <= len(data):
                ext_type = struct.unpack('>H', data[pos:pos+2])[0]
                ext_len = struct.unpack('>H', data[pos+2:pos+4])[0]
                pos += 4
                
                if ext_type == 0x0000:  # Server Name Extension
                    if pos + 5 <= len(data):
                        name_len = struct.unpack('>H', data[pos+3:pos+5])[0]
                        if pos + 5 + name_len <= len(data):
                            return data[pos+5:pos+5+name_len].decode('utf-8', errors='ignore')
                pos += ext_len
        except:
            pass
        return ""

# ==================== VLESS پروتکل هندلر ====================
class VLESSHandler:
    """مدیریت پروتکل VLESS"""
    
    @staticmethod
    def parse_header(data: bytes) -> dict:
        """پارس هدر VLESS"""
        try:
            if len(data) < 20:
                return None
            
            # بررسی ورژن
            version = data[0]
            if version != 0x01:
                return None
            
            # استخراج UUID (16 بایت)
            uuid_bytes = data[1:17]
            
            # استخراج command (1 بایت)
            command = data[17]
            
            # استخراج port (2 بایت)
            port = struct.unpack('>H', data[18:20])[0]
            
            # استخراج address type و address
            pos = 20
            if len(data) <= pos:
                return None
            
            addr_type = data[pos]
            pos += 1
            
            address = ""
            if addr_type == 0x01:  # IPv4
                if len(data) >= pos + 4:
                    address = socket.inet_ntoa(data[pos:pos+4])
                    pos += 4
            elif addr_type == 0x02:  # Domain
                if len(data) >= pos + 1:
                    domain_len = data[pos]
                    pos += 1
                    if len(data) >= pos + domain_len:
                        address = data[pos:pos+domain_len].decode('utf-8', errors='ignore')
                        pos += domain_len
            
            return {
                "version": version,
                "uuid": str(uuid.UUID(bytes=uuid_bytes)),
                "command": command,
                "port": port,
                "address": address,
                "addr_type": addr_type
            }
        except Exception as e:
            print(f"Error parsing VLESS header: {e}")
            return None

# ==================== تابع اصلی ====================
async def handle_client(reader, writer):
    """مدیریت اتصالات کلاینت با Sniffing"""
    client_addr = writer.get_extra_info('peername')
    print(f"\n[+] New connection from {client_addr}")
    
    try:
        # دریافت داده اولیه
        initial_data = await asyncio.wait_for(reader.read(4096), timeout=10)
        if not initial_data:
            writer.close()
            return
        
        # Sniff کردن پروتکل
        sniff_result = ProtocolSniffer.sniff(initial_data)
        print(f"[*] Sniff result: {sniff_result['protocol']}")
        if sniff_result['details']:
            print(f"[*] Details: {sniff_result['details']}")
        
        # اتصال به سرور مقصد
        target_reader, target_writer = await asyncio.open_connection(
            CONFIG['CONNECT_IP'],
            CONFIG['CONNECT_PORT']
        )
        
        # ساخت TLS ClientHello جعلی با SNI دلخواه
        fake_tls_hello = create_fake_tls_hello()
        target_writer.write(fake_tls_hello)
        await target_writer.drain()
        
        # دریافت پاسخ TLS ServerHello
        tls_response = await asyncio.wait_for(target_reader.read(8192), timeout=10)
        
        # ارسال پاسخ به کلاینت
        writer.write(tls_response)
        await writer.drain()
        
        # اگر درخواست WebSocket بود
        if sniff_result['websocket'] or b'websocket' in initial_data.lower():
            print("[*] WebSocket upgrade detected, switching protocol...")
            # ارسال WebSocket upgrade response
            ws_response = (
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + base64.b64encode(os.urandom(16)) + b"\r\n\r\n"
            )
            writer.write(ws_response)
            await writer.drain()
        
        # پروکسی دوطرفه
        await asyncio.gather(
            proxy_data(reader, target_writer, "client->target", sniff_result),
            proxy_data(target_reader, writer, "target->client", sniff_result)
        )
        
    except asyncio.TimeoutError:
        print(f"[-] Timeout from {client_addr}")
    except Exception as e:
        print(f"[-] Error from {client_addr}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def proxy_data(reader, writer, direction, sniff_result=None):
    """پروکسی داده بین دو سوکت با Logging"""
    try:
        while True:
            data = await reader.read(8192)
            if not data:
                break
            
            # لاگ کردن حجم داده
            if sniff_result:
                print(f"[{direction}] {len(data)} bytes")
            
            writer.write(data)
            await writer.drain()
    except:
        pass

def create_fake_tls_hello():
    """ساخت TLS ClientHello جعلی با SNI دلخواه"""
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)
    sni_bytes = CONFIG['FAKE_SNI'].encode()
    
    # ساخت SNI Extension
    sni_extension = (
        b'\x00\x00' +  # Extension type: server_name
        (len(sni_bytes) + 5).to_bytes(2, 'big') +  # Extension length
        (len(sni_bytes) + 3).to_bytes(2, 'big') +  # Server name list length
        b'\x00' +  # Name type: hostname
        len(sni_bytes).to_bytes(2, 'big') +
        sni_bytes
    )
    
    # Cipher suites (TLS 1.3 + 1.2)
    cipher_suites = b'\x13\x02\x13\x03\x13\x01\xc0\x2f\xc0\x2b'
    
    # ساخت ClientHello
    client_hello = (
        b'\x16\x03\x03' +  # Handshake + TLS 1.2
        (len(random_bytes) + len(session_id) + 2 + len(cipher_suites) + 2 + len(sni_extension) + 2).to_bytes(2, 'big') +
        b'\x01\x00\x00\x00' +  # Handshake type
        b'\x03\x03' +  # Client version
        random_bytes +
        len(session_id).to_bytes(1, 'big') + session_id +
        len(cipher_suites).to_bytes(2, 'big') + cipher_suites +
        b'\x01\x00' +  # Compression
        len(sni_extension).to_bytes(2, 'big') +
        sni_extension
    )
    
    # Fix handshake length
    handshake_len = len(client_hello) - 5
    client_hello = client_hello[:3] + handshake_len.to_bytes(3, 'big') + client_hello[6:]
    
    return client_hello

def print_configs():
    """چاپ کانفیگ‌ها در لاگ"""
    print("\n" + "="*70)
    print("🚀 TUKAN V2RAY SERVER WITH SNIFFER")
    print("="*70)
    print(f"📡 Listen: {CONFIG['LISTEN_HOST']}:{CONFIG['LISTEN_PORT']}")
    print(f"🎯 Target: {CONFIG['CONNECT_IP']}:{CONFIG['CONNECT_PORT']}")
    print(f"🔒 Fake SNI: {CONFIG['FAKE_SNI']}")
    print(f"🌐 Public URL: {RAILWAY_URL}:{CONFIG['LISTEN_PORT']}")
    print(f"🆔 UUID: {SERVER_UUID}")
    
    # لینک VLESS
    vless_link = (
        f"vless://{SERVER_UUID}@{RAILWAY_URL}:{CONFIG['LISTEN_PORT']}"
        f"?encryption=none&security=tls&sni={CONFIG['FAKE_SNI']}"
        f"&type=ws&host={CONFIG['FAKE_SNI']}&path=%2F"
        f"#TuKaN-VLESS"
    )
    
    # لینک VMESS
    vmess_config = {
        "v": "2",
        "ps": "TuKaN-VMESS",
        "add": RAILWAY_URL,
        "port": CONFIG['LISTEN_PORT'],
        "id": SERVER_UUID,
        "aid": "0",
        "net": "ws",
        "type": "none",
        "host": CONFIG['FAKE_SNI'],
        "path": "/",
        "tls": "tls",
        "sni": CONFIG['FAKE_SNI']
    }
    vmess_link = f"vmess://{base64.b64encode(json.dumps(vmess_config).encode()).decode()}"
    
    print("\n" + "="*70)
    print("📱 V2RAY CONFIGURATION LINKS")
    print("="*70)
    print(f"\n🔗 VLESS LINK:")
    print(f"{vless_link}")
    print(f"\n🔗 VMESS LINK:")
    print(f"{vmess_link}")
    print("\n" + "="*70)
    print("💡 Sniffer is active - will detect TLS/HTTP/WebSocket/VLESS")
    print("="*70 + "\n")

async def main():
    print_configs()
    
    server = await asyncio.start_server(
        handle_client,
        CONFIG['LISTEN_HOST'],
        CONFIG['LISTEN_PORT']
    )
    
    print(f"✅ Server is listening on {CONFIG['LISTEN_HOST']}:{CONFIG['LISTEN_PORT']}")
    print("💡 Sniffer ready to detect protocols...\n")
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
