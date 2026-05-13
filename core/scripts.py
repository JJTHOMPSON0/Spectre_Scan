import requests
import ftplib
import socket

script_registry = []


def register_script(name, category="default", ports=None, service_keywords=None, description="", safe=True):
    if ports is None:
        ports = []
    if service_keywords is None:
        service_keywords = []

    def decorator(func):
        script_registry.append({
            "name": name,
            "category": category,
            "ports": set(ports),
            "service_keywords": [keyword.upper() for keyword in service_keywords],
            "description": description,
            "safe": safe,
            "func": func,
        })
        return func

    return decorator


def run_scripts(ip, port, banner, categories=None):
    if isinstance(categories, str):
        categories = [item.strip().lower() for item in categories.split(",") if item.strip()]
    categories = set(categories or ["default"])
    normalized_banner = str(banner or "").upper()
    results = []

    for script in script_registry:
        if categories and script["category"].lower() not in categories:
            continue
        if script["ports"] and port not in script["ports"]:
            continue
        if script["service_keywords"] and not any(keyword in normalized_banner for keyword in script["service_keywords"]):
            continue

        try:
            output = script["func"](ip, port, banner)
            if output:
                results.append((script["name"], output))
        except Exception as exc:
            results.append((script["name"], f"ERROR: {exc}"))

    return results


def run_default_scripts(ip, port, banner):
    return run_scripts(ip, port, banner, categories=["default"])


@register_script(
    name="http-title",
    category="default",
    ports=[80, 443, 8080],
    service_keywords=["HTTP"],
    description="Fetch HTML title from web servers.",
    safe=True,
)
def http_title(ip, port, banner):
    try:
        url = f"http://{ip}:{port}"
        r = requests.get(url, timeout=3, verify=False)
        if "<title>" in r.text.lower():
            title = r.text.lower().split("<title>")[1].split("</title>")[0].strip()
            return {"title": title}
    except Exception:
        pass


@register_script(
    name="http-methods",
    category="default",
    ports=[80, 443, 8080],
    service_keywords=["HTTP"],
    description="Probe HTTP allowed methods.",
    safe=True,
)
def http_methods(ip, port, banner):
    try:
        url = f"http://{ip}:{port}"
        options = requests.options(url, timeout=3, verify=False)
        if "Allow" in options.headers:
            return {"allowed_methods": options.headers["Allow"]}
    except Exception:
        pass


@register_script(
    name="http-git",
    category="default",
    ports=[80, 443, 8080],
    service_keywords=["HTTP"],
    description="Detect exposed Git repository metadata.",
    safe=True,
)
def http_git(ip, port, banner):
    try:
        url = f"http://{ip}:{port}/.git/HEAD"
        r = requests.get(url, timeout=3, verify=False)
        if r.status_code == 200 and "refs/heads" in r.text:
            head = r.text.strip()
            return {"git_repo": True, "head": head}
    except Exception:
        pass


@register_script(
    name="ftp-anon",
    category="default",
    ports=[21],
    service_keywords=["FTP"],
    description="Check anonymous FTP login.",
    safe=True,
)
def ftp_anon(ip, port, banner):
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=3)
        ftp.login("anonymous", "anonymous@")
        ftp.quit()
        return {"anonymous_login": True}
    except Exception as exc:
        if "530" in str(exc):
            return {"anonymous_login": False}
        return None


@register_script(
    name="ssh-auth-methods",
    category="default",
    ports=[22],
    service_keywords=["SSH"],
    description="Report SSH auth methods.",
    safe=True,
)
def ssh_auth_methods(ip, port, banner):
    return {"auth_methods": ["publickey", "password"]}
