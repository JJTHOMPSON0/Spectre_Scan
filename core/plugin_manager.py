import importlib.util
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "plugins"


def load_plugins():
    plugins = []
    if not PLUGIN_DIR.exists():
        return plugins

    for path in sorted(PLUGIN_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue

        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            plugins.append(module)

    return plugins


def run_plugins(plugins, target, port, banner, categories=None):
    results = {}
    normalized_banner = str(banner or "").upper()
    categories = [item.strip().lower() for item in (categories or []) if item.strip()]

    for plugin in plugins:
        matched = False
        if hasattr(plugin, "PORTS") and port in getattr(plugin, "PORTS"):
            matched = True

        if hasattr(plugin, "SERVICE_KEYWORDS"):
            keywords = getattr(plugin, "SERVICE_KEYWORDS")
            if any(keyword.upper() in normalized_banner for keyword in keywords):
                matched = True

        if hasattr(plugin, "PLUGIN_CATEGORIES") and categories:
            plugin_categories = [item.strip().lower() for item in getattr(plugin, "PLUGIN_CATEGORIES")]
            if not any(category in plugin_categories for category in categories):
                continue

        if not matched and not (hasattr(plugin, "PORTS") or hasattr(plugin, "SERVICE_KEYWORDS") or hasattr(plugin, "PLUGIN_CATEGORIES")):
            matched = True

        if not matched:
            continue

        if hasattr(plugin, "run"):
            data = plugin.run(target, port, banner)
            if data:
                plugin_key = getattr(plugin, "PLUGIN_NAME", plugin.__name__)
                results[plugin_key] = data

    return results
