def parse_ports(port_string):
    """Parse port input like "1-1024", "22,80,443", or "1,10-20"."""
    if not port_string:
        raise ValueError("Port specification cannot be empty")

    ports = set()
    for piece in port_string.split(","):
        piece = piece.strip()
        if not piece:
            continue

        if "-" in piece:
            start, end = piece.split("-", 1)
            start = int(start)
            end = int(end)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {piece}")
            ports.update(range(start, end + 1))
        else:
            port = int(piece)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port number: {port}")
            ports.add(port)

    return sorted(ports)
