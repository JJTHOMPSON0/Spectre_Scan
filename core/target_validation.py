import ipaddress
import re

HOSTNAME_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\.?$"
)


def validate_target(target: str) -> bool:
    """Return True if the target is a valid IP address, CIDR, or hostname."""
    if not target or not isinstance(target, str):
        return False

    target = target.strip()
    if not target:
        return False

    # IPv4/IPv6 address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # CIDR notation (network)
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False

    # Avoid numeric dotted strings that are not valid IPs
    if target.replace('.', '').isdigit():
        return False

    # Hostname/domain name validation
    if HOSTNAME_REGEX.fullmatch(target):
        return True

    return False
