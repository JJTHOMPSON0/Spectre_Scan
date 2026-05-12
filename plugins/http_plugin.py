import requests

def run(target, port):

    try:
        url = f"http://{target}:{port}"

        r = requests.get(url, timeout=3)

        return {
            "server": r.headers.get("Server"),
            "title": r.text[:100]
        }

    except:
        return None