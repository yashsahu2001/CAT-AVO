r"""CAT-AVO SOAR response actions.
  python soar.py status                      check the three connections
  python soar.py block   <attacker_ip> <userId>   revoke Keycloak sessions + block IP on RHEL and pfSense
  python soar.py unblock <attacker_ip>       remove both IP blocks
Passwords come from the environment (SOAR_KC_PW, SOAR_PF_PW, SOAR_RHEL_PW) or are asked once."""
import getpass, ipaddress, os, sys, time
import paramiko
import requests

KC = "http://192.168.100.20:8080"
REALM = "catavo"
PF_HOST, RHEL_HOST = "192.168.100.1", "192.168.100.20"
PROTECTED = {"192.168.100.1", "192.168.100.10", "192.168.100.20", "192.168.100.30", "192.168.100.70"}
_cache = {}


def secret(env, prompt):
    if env not in _cache:
        _cache[env] = os.environ.get(env) or getpass.getpass(prompt)
    return _cache[env]


def ssh_run(host, user, pw, cmd):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, password=pw, look_for_keys=False, allow_agent=False, timeout=10)
    try:
        _, o, e = c.exec_command(cmd, timeout=20)
        out, err = o.read().decode().strip(), e.read().decode().strip()
    finally:
        c.close()
    return (out + " " + err).strip()


def pf(cmd):
    return ssh_run(PF_HOST, "root", secret("SOAR_PF_PW", "pfSense root password: "), cmd)


def rhel(cmd):
    return ssh_run(RHEL_HOST, "soar", secret("SOAR_RHEL_PW", "RHEL soar password: "), cmd)


def kc_token():
    r = requests.post(f"{KC}/realms/master/protocol/openid-connect/token", timeout=10, data={
        "client_id": "admin-cli", "grant_type": "password", "username": "labadmin",
        "password": secret("SOAR_KC_PW", "Keycloak labadmin password: ")})
    r.raise_for_status()
    return r.json()["access_token"]


def revoke_sessions(user_id):
    r = requests.post(f"{KC}/admin/realms/{REALM}/users/{user_id}/logout", timeout=10,
                      headers={"Authorization": "Bearer " + kc_token()})
    return r.status_code == 204


def rule(ip):
    return f"rule family=\"ipv4\" source address=\"{ip}\" drop"


def block_rhel(ip):
    return "success" in rhel(f"sudo firewall-cmd --add-rich-rule='{rule(ip)}'")


def unblock_rhel(ip):
    return "success" in rhel(f"sudo firewall-cmd --remove-rich-rule='{rule(ip)}'")


def block_pfsense(ip):
    t = pf(f"pfctl -t blocked_ips -T add {ip}; pfctl -k {ip}")
    return "1/1 addresses added" in t or "0/1" in t


def unblock_pfsense(ip):
    return "1/1 addresses deleted" in pf(f"pfctl -t blocked_ips -T delete {ip}")


def check_ip(ip):
    ipaddress.ip_address(ip)
    if ip in PROTECTED:
        sys.exit(f"Refusing to block {ip}: it is lab infrastructure or the SOAR host.")


def respond(ip, user_id=None):
    """Full response. Returns per-action seconds (None = failed) and total."""
    check_ip(ip)
    t0 = time.perf_counter()
    res = {}
    steps = ([("keycloak_revoke", lambda: revoke_sessions(user_id))] if user_id else []) + [
        ("rhel_firewall", lambda: block_rhel(ip)), ("pfsense_block", lambda: block_pfsense(ip))]
    for name, fn in steps:
        s = time.perf_counter()
        try:
            ok = fn()
        except Exception as ex:
            print(f"  {name}: ERROR {ex}")
            ok = False
        res[name] = round(time.perf_counter() - s, 2) if ok else None
        print(f"  {name}: {'OK' if ok else 'FAILED'}  ({time.perf_counter() - t0:.2f}s since start)")
    res["total"] = round(time.perf_counter() - t0, 2)
    return res


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["status"]:
        print("keycloak admin token:", "OK" if kc_token() else "FAILED")
        print("pfSense blocked_ips :", pf("pfctl -t blocked_ips -T show") or "(empty)")
        print("RHEL rich rules     :", rhel("sudo firewall-cmd --list-rich-rules") or "(none)")
    elif a[:1] == ["block"] and len(a) == 3:
        print(respond(a[1], a[2]))
    elif a[:1] == ["unblock"] and len(a) == 2:
        check_ip(a[1])
        print("rhel:", unblock_rhel(a[1]), " pfsense:", unblock_pfsense(a[1]))
    else:
        print(__doc__)
