"""NmapPilot — Nmap XML output parser."""

import os
import xml.etree.ElementTree as ET


# ═══════════════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════════════

def parse_nmap_xml(xml_path):
    """Parse nmap XML output into structured data.

    Returns
    -------
    dict
        Keys: hosts, scan_info, run_stats, raw_xml_path
    """
    result = {
        "hosts": [],
        "scan_info": {},
        "run_stats": {},
        "raw_xml_path": xml_path,
    }

    if not os.path.exists(xml_path):
        return result

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError:
        return result

    # Scan info
    result["scan_info"] = {
        "scanner": root.get("scanner", "nmap"),
        "args": root.get("args", ""),
        "start_time": root.get("startstr", ""),
        "version": root.get("version", ""),
    }

    # Run stats
    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            result["run_stats"]["elapsed"] = finished.get("elapsed", "0")
            result["run_stats"]["end_time"] = finished.get("timestr", "")
        hosts_stat = runstats.find("hosts")
        if hosts_stat is not None:
            result["run_stats"]["hosts_up"] = hosts_stat.get("up", "0")
            result["run_stats"]["hosts_down"] = hosts_stat.get("down", "0")
            result["run_stats"]["hosts_total"] = hosts_stat.get("total", "0")

    # Hosts
    for host_elem in root.findall("host"):
        result["hosts"].append(_parse_host(host_elem))

    return result


# ═══════════════════════════════════════════════════════════════════════
#  Internal helpers
# ═══════════════════════════════════════════════════════════════════════

def _parse_host(host_elem):
    """Parse a single <host> element."""
    host = {
        "status": "unknown",
        "addresses": [],
        "hostnames": [],
        "ports": [],
        "os_matches": [],
        "scripts": [],
        "uptime": None,
    }

    status = host_elem.find("status")
    if status is not None:
        host["status"] = status.get("state", "unknown")

    for addr in host_elem.findall("address"):
        host["addresses"].append({
            "addr": addr.get("addr", ""),
            "type": addr.get("addrtype", ""),
        })

    hostnames = host_elem.find("hostnames")
    if hostnames is not None:
        for hn in hostnames.findall("hostname"):
            host["hostnames"].append({
                "name": hn.get("name", ""),
                "type": hn.get("type", ""),
            })

    ports = host_elem.find("ports")
    if ports is not None:
        for port_elem in ports.findall("port"):
            host["ports"].append(_parse_port(port_elem))

    os_elem = host_elem.find("os")
    if os_elem is not None:
        for match in os_elem.findall("osmatch"):
            os_info = {
                "name": match.get("name", ""),
                "accuracy": match.get("accuracy", "0"),
                "os_classes": [],
            }
            for cls in match.findall("osclass"):
                os_info["os_classes"].append({
                    "type": cls.get("type", ""),
                    "vendor": cls.get("vendor", ""),
                    "os_family": cls.get("osfamily", ""),
                    "os_gen": cls.get("osgen", ""),
                    "accuracy": cls.get("accuracy", "0"),
                })
            host["os_matches"].append(os_info)

    hostscript = host_elem.find("hostscript")
    if hostscript is not None:
        for script in hostscript.findall("script"):
            host["scripts"].append({
                "id": script.get("id", ""),
                "output": script.get("output", ""),
            })

    uptime = host_elem.find("uptime")
    if uptime is not None:
        host["uptime"] = {
            "seconds": uptime.get("seconds", ""),
            "lastboot": uptime.get("lastboot", ""),
        }

    return host


def _parse_port(port_elem):
    """Parse a single <port> element."""
    port = {
        "port_id": port_elem.get("portid", ""),
        "protocol": port_elem.get("protocol", ""),
        "state": "unknown",
        "service": {},
        "scripts": [],
    }

    state = port_elem.find("state")
    if state is not None:
        port["state"] = state.get("state", "unknown")
        port["reason"] = state.get("reason", "")

    service = port_elem.find("service")
    if service is not None:
        port["service"] = {
            "name": service.get("name", ""),
            "product": service.get("product", ""),
            "version": service.get("version", ""),
            "extra_info": service.get("extrainfo", ""),
            "os_type": service.get("ostype", ""),
            "method": service.get("method", ""),
            "conf": service.get("conf", ""),
            "tunnel": service.get("tunnel", ""),
        }

    for script in port_elem.findall("script"):
        port["scripts"].append({
            "id": script.get("id", ""),
            "output": script.get("output", ""),
        })

    return port


# ═══════════════════════════════════════════════════════════════════════
#  Convenience extractors
# ═══════════════════════════════════════════════════════════════════════

def get_open_ports(hosts):
    """Extract unique open port numbers from parsed host data."""
    ports = []
    for host in hosts:
        for port in host.get("ports", []):
            if port.get("state") == "open":
                pid = port.get("port_id", "")
                if pid and pid not in ports:
                    ports.append(pid)
    return ports


def get_services(hosts):
    """Extract service dicts from parsed host data."""
    services = []
    for host in hosts:
        for port in host.get("ports", []):
            if port.get("state") == "open" and port.get("service"):
                svc = port["service"].copy()
                svc["port"] = port["port_id"]
                svc["protocol"] = port["protocol"]
                services.append(svc)
    return services


def get_service_string(service):
    """Build a searchable service string like 'Apache httpd 2.4.51'."""
    parts = []
    if service.get("product"):
        parts.append(service["product"])
    if service.get("version"):
        parts.append(service["version"])
    if not parts and service.get("name"):
        parts.append(service["name"])
    return " ".join(parts)
