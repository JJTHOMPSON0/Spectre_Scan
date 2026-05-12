async def grab_banner(reader, writer):
    try:
        writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
        await writer.drain()

        data = await reader.read(1024)

        return data.decode(errors="ignore").split("\n")[0]

    except:
        return "Unknown"