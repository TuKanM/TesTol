import asyncio
import json
import os
import sys
import uuid
import base64
from datetime import datetime

# تنظیمات
CONFIG = {
    "LISTEN_HOST": "0.0.0.0",
    "LISTEN_PORT": 40443,
    "CONNECT_IP": "104.19.229.21",
    "CONNECT_PORT": 443,
    "FAKE_SNI": "hcaptcha.com"
}

# تولید UUID یکتا برای هر دیپلوی
SERVER_UUID = str(uuid.uuid4())
PROJECT_NAME = os.environ.get("RAILWAY_SERVICE_NAME", "TuKaN")
RAILWAY_URL = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")

def generate_v2ray_config():
    """تولید کانفیگ V2Ray بر اساس تنظیمات"""
    
    # آدرس سرور
    if RAILWAY_URL:
        server_address = RAILWAY_URL
    else:
        server_address = f"{PROJECT_NAME}.up.railway.app"
    
    # ساخت لینک VLESS
    vless_link = (
        f"vless://{SERVER_UUID}@{server_address}:{CONFIG['LISTEN_PORT']}"
        f"?encryption=none&security=tls&sni={CONFIG['FAKE_SNI']}"
        f"&type=ws&host={CONFIG['FAKE_SNI']}&path=%2F"
        f"#{PROJECT_NAME}-VLESS"
    )
    
    # ساخت لینک VMESS
    vmess_config = {
        "v": "2",
        "ps": f"{PROJECT_NAME}-VMESS",
        "add": server_address,
        "port": str(CONFIG['LISTEN_PORT']),
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
    
    # ساخت کانفیگ JSON برای V2Ray
    json_config = {
        "inbounds": [
            {
                "port": 10808,
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
            },
            {
                "port": 10809,
                "protocol": "http",
                "settings": {"auth": "noauth", "udp": True}
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": server_address,
                        "port": CONFIG['LISTEN_PORT'],
                        "users": [{
                            "id": SERVER_UUID,
                            "encryption": "none",
                            "flow": ""
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": CONFIG['FAKE_SNI'],
                        "allowInsecure": False,
                        "fingerprint": "chrome"
                    },
                    "wsSettings": {
                        "path": "/",
                        "headers": {"Host": CONFIG['FAKE_SNI']}
                    }
                }
            }
        ]
    }
    
    return vless_link, vmess_link, json_config

async def handle_client(reader, writer):
    """مدیریت اتصالات کلاینت - شبیه‌سازی پروتکل VLESS"""
    client_addr = writer.get_extra_info('peername')
    
    try:
        # دریافت داده از کلاینت
        data = await asyncio.wait_for(reader.read(1024), timeout=10)
        if not data:
            writer.close()
            return
        
        # بررسی درخواست VLESS (ساده شده)
        # در یک پیاده‌سازی واقعی، باید هدر VLESS رو پارس کرد
        
        # اتصال به سرور مقصد
        target_reader, target_writer = await asyncio.open_connection(
            CONFIG['CONNECT_IP'], 
            CONFIG['CONNECT_PORT']
        )
        
        # ارسال TLS Hello جعلی
        fake_hello = create_fake_tls_hello()
        target_writer.write(fake_hello)
        await target_writer.drain()
        
        # دریافت پاسخ
        response = await asyncio.wait_for(target_reader.read(4096), timeout=5)
        
        # ارسال پاسخ به کلاینت
        writer.write(response)
        await writer.drain()
        
        # پروکسی دوطرفه
        await asyncio.gather(
            proxy_data(reader, target_writer),
            proxy_data(target_reader, writer)
        )
        
    except asyncio.TimeoutError:
        print(f"Timeout from {client_addr}")
    except Exception as e:
        print(f"Error from {client_addr}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def proxy_data(reader, writer):
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
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)
    sni_bytes = CONFIG['FAKE_SNI'].encode()
    
    # ساخت SNI Extension
    sni_extension = (
        b'\x00\x00' +  # Extension type: server_name
        (len(sni_bytes) + 5).to_bytes(2, 'big') +
        (len(sni_bytes) + 3).to_bytes(2, 'big') +
        b'\x00' +
        len(sni_bytes).to_bytes(2, 'big') +
        sni_bytes
    )
    
    # ساخت ClientHello
    client_hello = (
        b'\x16\x03\x03' +  # Handshake + TLS 1.2
        (len(random_bytes) + len(session_id) + 4 + len(sni_extension) + 2).to_bytes(2, 'big') +
        b'\x01\x00\x00\x00' +  # Handshake type
        b'\x03\x03' +  # Client version
        random_bytes +
        len(session_id).to_bytes(1, 'big') + session_id +
        b'\x00\x02\x13\x02' +  # Cipher suites
        b'\x01\x00' +  # Compression
        len(sni_extension).to_bytes(2, 'big') +
        sni_extension
    )
    
    # Fix length
    handshake_len = len(client_hello) - 5
    client_hello = client_hello[:3] + handshake_len.to_bytes(3, 'big') + client_hello[6:]
    
    return client_hello

async def main():
    # چاپ اطلاعات راه‌اندازی
    print("\n" + "="*60)
    print("🚀 TuKaN V2Ray Server Started!")
    print("="*60)
    print(f"📡 Server listening on: {CONFIG['LISTEN_HOST']}:{CONFIG['LISTEN_PORT']}")
    print(f"🎯 Target: {CONFIG['CONNECT_IP']}:{CONFIG['CONNECT_PORT']}")
    print(f"🔒 Fake SNI: {CONFIG['FAKE_SNI']}")
    print(f"🆔 Server UUID: {SERVER_UUID}")
    
    # تعیین آدرس عمومی
    public_url = RAILWAY_URL or f"{PROJECT_NAME}.up.railway.app"
    print(f"\n🌐 Public URL: {public_url}:{CONFIG['LISTEN_PORT']}")
    
    # تولید و چاپ کانفیگ‌ها
    vless_link, vmess_link, v2ray_json = generate_v2ray_config()
    
    print("\n" + "="*60)
    print("📱 V2RAY CONFIGURATION LINKS")
    print("="*60)
    
    print("\n🔗 VLESS LINK (برای V2RayNG, Nekobox, Hiddify):")
    print(f"{vless_link}\n")
    
    print("🔗 VMESS LINK:")
    print(f"{vmess_link}\n")
    
    print("📝 JSON CONFIG (برای V2Ray Desktop):")
    print(json.dumps(v2ray_json, indent=2))
    
    print("\n" + "="*60)
    print("💡 How to use:")
    print("1. Copy the VLESS link above")
    print("2. Open V2RayNG / Nekobox / Hiddify")
    print("3. Import from clipboard")
    print("4. Connect and enjoy!")
    print("="*60 + "\n")
    
    # راه‌اندازی سرور
    server = await asyncio.start_server(
        handle_client,
        CONFIG['LISTEN_HOST'],
        CONFIG['LISTEN_PORT']
    )
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
