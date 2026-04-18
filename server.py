import os
import sys

print("Starting TuKaN server...")
print(f"Python version: {sys.version}")
print(f"Current directory: {os.getcwd()}")

try:
    # تست import ها
    import asyncio
    print("✓ asyncio imported")
    
    # تنظیمات ساده
    LISTEN_PORT = int(os.environ.get("PORT", 40443))
    print(f"✓ Port configured: {LISTEN_PORT}")
    
    async def handle_client(reader, writer):
        print("Client connected!")
        writer.close()
    
    async def main():
        print("Starting server...")
        server = await asyncio.start_server(
            handle_client,
            "0.0.0.0",
            LISTEN_PORT
        )
        print(f"✓ Server running on port {LISTEN_PORT}")
        print("Waiting for connections...")
        await server.serve_forever()
    
    asyncio.run(main())
    
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
