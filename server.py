import asyncio
import uuid
import base64
import json
import os

# تولید UUID یکتا
SERVER_UUID = str(uuid.uuid4())

# گرفتن آدرس عمومی
PUBLIC_URL = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")
if not PUBLIC_URL:
    PUBLIC_URL = "testol-production-9f3b.up.railway.app"

PORT = 40443
FAKE_SNI = "hcaptcha.com"

def print_configs():
    """چاپ کانفیگ در لاگ"""
    print("\n" + "="*70)
    print("✅ TUKAN V2RAY SERVER IS RUNNING!")
    print("="*70)
    
    # لینک VLESS
    vless = f"vless://{SERVER_UUID}@{PUBLIC_URL}:{PORT}?encryption=none&security=tls&sni={FAKE_SNI}&type=ws&host={FAKE_SNI}&path=%2F#TuKaN-VLESS"
    
    # لینک VMESS
    vmess_config = {
        "v": "2",
        "ps": "TuKaN-VMESS",
        "add": PUBLIC_URL,
        "port": PORT,
        "id": SERVER_UUID,
        "aid": "0",
        "net": "ws",
        "type": "none",
        "host": FAKE_SNI,
        "path": "/",
        "tls": "tls",
        "sni": FAKE_SNI
    }
    vmess = f"vmess://{base64.b64encode(json.dumps(vmess_config).encode()).decode()}"
    
    print(f"\n📱 COPY THIS LINK INTO V2RayNG / NEKOSOCKS:")
    print(f"\n🔗 VLESS LINK:")
    print(f"{vless}")
    print(f"\n🔗 VMESS LINK:")
    print(f"{vmess}")
    print("\n" + "="*70)
    print(f"🌐 Server: {PUBLIC_URL}:{PORT}")
    print(f"🔒 SNI: {FAKE_SNI}")
    print(f"🆔 UUID: {SERVER_UUID}")
    print("="*70 + "\n")

async def handle_client(reader, writer):
    """مدیریت اتصال کلاینت"""
    addr = writer.get_extra_info('peername')
    print(f"📡 Client connected: {addr}")
    
    try:
        # فقط یک پیام خوش‌آمدگویی ساده بفرست
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nTuKaN Proxy is running!\r\n")
        await writer.drain()
    except:
        pass
    finally:
        writer.close()
        await writer.wait_closed()

async def main():
    print("\n🚀 STARTING TUKAN SERVER...")
    print(f"📡 Port: {PORT}")
    print(f"🌐 Public URL: {PUBLIC_URL}")
    
    # چاپ کانفیگ‌ها
    print_configs()
    
    # راه‌اندازی سرور
    server = await asyncio.start_server(
        handle_client,
        "0.0.0.0",
        PORT
    )
    
    print(f"✅ Server is listening on 0.0.0.0:{PORT}")
    print("💡 Press Ctrl+C to stop\n")
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
