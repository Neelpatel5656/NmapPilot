"""NmapPilot — Target validation and DNS resolution."""

import re
import socket


def validate_target(target):
    """Validate and resolve a target (domain or IP).

    Returns
    -------
    dict
        Keys: original, ip, hostname, is_valid, error
    """
    result = {
        "original": target,
        "ip": None,
        "hostname": None,
        "is_valid": False,
        "error": None,
    }

    # Strip protocol prefixes, paths, and port
    target = re.sub(r'^https?://', '', target).strip().rstrip('/')
    target = target.split('/')[0]
    target = target.split(':')[0]

    result["original"] = target

    # Check if it's already an IP
    try:
        socket.inet_aton(target)
        result["ip"] = target
        result["is_valid"] = True
        try:
            result["hostname"] = socket.gethostbyaddr(target)[0]
        except socket.herror:
            result["hostname"] = target
        return result
    except socket.error:
        pass

    # Try to resolve as hostname
    try:
        ip = socket.gethostbyname(target)
        result["ip"] = ip
        result["hostname"] = target
        result["is_valid"] = True
    except socket.gaierror as e:
        result["error"] = f"Cannot resolve '{target}': {e}"

    return result
