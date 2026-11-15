"""Turn a raw alert into plain answers: who, what, how, and what to do next.

The raw event is for machines (SIEM, log file). These sentences are for the
person who gets woken up by it, who may not know what an RDP cookie is.
"""

import ipaddress


def _who(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return f"An unknown source ({ip})."
    if addr.is_loopback:
        return "This computer itself (127.0.0.1). A program running on this machine used the bait."
    if addr.is_private or addr.is_link_local:
        return f"Another device on your own network, at {ip}."
    return f"An address on the internet, {ip}. Your listener is reachable from outside your network."


def short_who(ip):
    """A few words for a card title: where the attempt came from."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return f"an unknown source ({ip})"
    if addr.is_loopback:
        return "this computer"
    if addr.is_private or addr.is_link_local:
        return f"device {ip} on your network"
    return f"internet address {ip}"


def _how(ev):
    s, f, u = ev.get("service", ""), ev.get("bait_file") or "a bait file", ev.get("username")
    if ev.get("severity") != "high":
        if u:
            return f"Someone tried to log in to the listener as {u}, which is not one of your baits."
        return "Something connected to the listener without using a bait login. Often a network scanner."
    if s.startswith("log:"):
        return f"The username {u} from {f} was tried against a real system ({s[4:]})."
    if s == "dns":
        return f"Someone looked up the server name written in {f}, as if to connect to it."
    if s == "aws":
        return f"Someone called AWS with the access key stored in {f}."
    if s == "rdp":
        return f"Someone opened {f} and tried Remote Desktop as {u}."
    if s == "openvpn":
        return f"Someone used the VPN profile {f} to connect."
    if u and u.startswith("~"):
        return f"Someone opened the link in {f} (a QR scan or a bookmark click)."
    return f"Someone read {f}, copied the login {u} and tried it."


def _next(ev, ip):
    loop = ip in ("127.0.0.1", "::1", "localhost")
    if ev.get("demo"):
        return ["Nothing. This was the Lure demo playing an attacker on your own machine."]
    if ev.get("severity") != "high":
        return ["If you know a scanner or monitoring tool runs at that address, ignore it.",
                "If not, find which device has that address and what it was doing."]
    steps = []
    if loop:
        steps.append("If you just ran `lure test`, this is expected and safe to mark investigated.")
        steps.append("If not, check which programs are running on this computer and who is logged in.")
    else:
        steps.append(f"Find which device has the address {ip} (your router's device list shows it).")
        steps.append("Check that device for an intruder or a script you do not recognise.")
    steps.append("Change any real password kept in the same place as the bait.")
    if ev.get("retired"):
        steps.append("This bait was replaced earlier, so the credential was taken before the last rotation.")
    steps.append("Click Mark investigated when you are done.")
    return steps


def explain(ev):
    ip = (ev.get("source") or "?").rsplit(":", 1)[0]
    where = ev.get("location") or ev.get("planted_on")
    if ev.get("severity") == "high":
        what = f"The bait {ev.get('bait_file')}" + (f", planted in {where}." if where else ".")
    else:
        what = "No bait was used; only the listener was touched."
    return {"who": _who(ip), "what": what, "how": _how(ev), "next": _next(ev, ip)}
