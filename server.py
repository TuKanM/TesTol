import asyncio
import json
import os
import uuid
import base64

CONFIG = {
    "LISTEN_HOST": "0.0.0.0",
    "LISTEN_PORT": 40443,
    "CONNECT_IP": "104.19.229.21",
    "CONNECT_PORT": 443,
    "FAKE_SNI": "hcaptcha.com"
}

SERVER_UUID = str(uuid.uuid4())
RAILWAY_URL = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "testol-production-9f3b.up.railway.app")

async def handle_client(reader, writer):
    """پروکسی ساده - هر چی میاد رو به سرور مقصد می‌فرسته"""
    client_addr = writer.get_extra_info('peername')
    print(f"[+] Connection from {client_addr}")
    
    try:
        # اتصال به سرور مقصد
        target_reader, target_writer = await asyncio.open_connection(
            CONFIG['CONNECT_IP'],
            CONFIG['CONNECT_PORT']
        )
        
        # پروکسی دوطرفه
        await asyncio.gather(
            relay(reader, target_writer),
            relay(target_reader, writer)
        )
        
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def relay(reader, writer):
    """انتقال داده بین دو سوکت"""
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

def print_config():
    print("\n" + "="*60)
    print("🚀 TUKAN TCP PROXY")
    print("="*60)
    print(f"🌐 Server: {RAILWAY_URL}:{CONFIG['LISTEN_PORT']}")
    
    # کانفیگ ساده برای V2Ray (HTTP proxy)
    config = {
        "outbounds": [{
            "protocol": "http",
            "settings": {
                "servers": [{
                    "address": RAILWAY_URL,
                    "port": CONFIG['LISTEN_PORT']
                }]
            }
        }]
    }
    
    print("\n📱 For V2Ray (HTTP Proxy):")
    print(f"http://{RAILWAY_URL}:{CONFIG['LISTEN_PORT']}")
    print("\n" + "="*60)

async def main():
    print_config()
    server = await asyncio.start_server(handle_client, "0.0.0.0", CONFIG['LISTEN_PORT'])
    print(f"✅ Proxy running on 0.0.0.0:{CONFIG['LISTEN_PORT']}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
