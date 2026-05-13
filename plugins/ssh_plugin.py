import socket

PLUGIN_NAME = "ssh_plugin"
PLUGIN_CATEGORIES = ["default", "ssh"]
PORTS = [22]
SERVICE_KEYWORDS = ["SSH"]

def run(target, port, banner):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()

        return {
            "banner": banner,
        }
    except Exception:
        return None