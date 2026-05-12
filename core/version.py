import asyncio

async def active_probe(reader, writer, port):
    try:
        # 1. Listen for immediate welcome banners (like SSH, FTP, SMTP)
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            if data:
                return data.decode(errors="ignore").strip().split('\n')[0]
        except asyncio.TimeoutError:
            pass # No welcome banner, time to actively probe

        # 2. HTTP specific probe (looking for the Server header)
        if port in [80, 443, 8080]:
            # HEAD asks the server to just return headers, not the whole webpage
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            
            response_text = data.decode(errors="ignore")
            
            # Loop through the lines to find the actual software version
            for line in response_text.split('\r\n'):
                if line.lower().startswith('server:'):
                    # This will return something like "Server: SimpleHTTP/0.6 Python/3.11"
                    return line.strip()
            
            # If the server hides its version, fallback to the status code
            return response_text.split('\n')[0].strip()

        # 3. Generic probe for unknown services
        else:
            writer.write(b"\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            return data.decode(errors="ignore").split("\n")[0].strip()

    except Exception:
        return "Unknown Service"
