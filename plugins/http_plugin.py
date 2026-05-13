import requests

PLUGIN_NAME = "http_plugin"
PLUGIN_CATEGORIES = ["default", "http"]
PORTS = [80, 443, 8080]
SERVICE_KEYWORDS = ["HTTP"]

def run(target, port, banner):
    try:
        url = f"http://{target}:{port}"
        r = requests.get(url, timeout=3, verify=False)

        return {
            "server": r.headers.get("Server"),
            "title": r.text[:100],
        }
    except Exception:
        return None