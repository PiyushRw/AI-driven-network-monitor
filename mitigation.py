"""Blocks an offending IP via the OS firewall. Safe by default: dry-run, whitelist, validation."""
import ipaddress, platform, subprocess
import config


def _commands(ip):
    rule = f"DDoSMonitor-{ip}"
    os_name = platform.system()
    if os_name == "Windows":
        return [["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule}",
                 "dir=in", "action=block", f"remoteip={ip}"]]
    if os_name == "Linux":
        return [["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]]
    if os_name == "Darwin":   # macOS: needs a pf anchor loaded; shown for learning
        return [["pfctl", "-t", "ddos_block", "-T", "add", ip]]
    return []


def is_blockable(ip):
    try:
        a = ipaddress.ip_address(ip)          # validation also prevents command injection
    except ValueError:
        return False
    if a.is_loopback or a.is_multicast or a.is_unspecified or ip in config.WHITELIST:
        return False
    return True


def block(ip):
    """Return a human-readable result string."""
    if not is_blockable(ip):
        return f"refused: {ip} is whitelisted or invalid"
    cmds = _commands(ip)
    if config.DRY_RUN:
        return "DRY-RUN: " + " | ".join(" ".join(c) for c in cmds)
    for c in cmds:
        subprocess.run(c, check=False, capture_output=True, timeout=10)   # list args, no shell
    return f"blocked {ip}"


def unblock(ip):
    if not is_blockable(ip):
        return "refused"
    os_name = platform.system()
    cmd = {"Windows": ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=DDoSMonitor-{ip}"],
           "Linux": ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
           "Darwin": ["pfctl", "-t", "ddos_block", "-T", "delete", ip]}.get(os_name)
    if config.DRY_RUN or not cmd:
        return "DRY-RUN: " + " ".join(cmd or [])
    subprocess.run(cmd, check=False, capture_output=True, timeout=10)
    return f"unblocked {ip}"
