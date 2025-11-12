# file: hotel_camera_net_detector.py
#!/usr/bin/env python3
"""
Çat eğlence tarafından yapılmıştır 
"""
import socket, time, concurrent.futures, requests, sys
from urllib.parse import urlparse
from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange
import threading
import subprocess
import re

# CONFIG
COMMON_PORTS = [80, 554, 8000, 8080, 8554, 88, 9000]
KEYWORDS = [b"camera", b"ipc", b"onvif", b"rtsp", b"live", b"surveillance", b"dvr", b"hikvision", b"dahua", b"axis"]
CONFIDENT_THRESHOLD = 6
PROBABLE_THRESHOLD = 3

requests.packages.urllib3.disable_warnings()

# Get local interface IP
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# Generate /24 by default
def gen_subnet_ips(local_ip):
    parts = local_ip.split(".")
    base = ".".join(parts[:3])
    for i in range(1,255):
        yield f"{base}.{i}"

# SSDP
def ssdp_discover(timeout=2):
    MCAST_GRP = "239.255.255.250"
    MCAST_PORT = 1900
    msg = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        f'HOST: {MCAST_GRP}:{MCAST_PORT}',
        'MAN: "ssdp:discover"',
        'MX: 1',
        'ST: ssdp:all', '', ''
    ]).encode('utf-8')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(timeout)
    s.sendto(msg, (MCAST_GRP, MCAST_PORT))
    results = {}
    start = time.time()
    try:
        while time.time()-start < timeout:
            data, addr = s.recvfrom(65535)
            txt = data.decode(errors='ignore')
            results[addr[0]] = txt
    except socket.timeout:
        pass
    finally:
        s.close()
    return results

# mDNS (Zeroconf) listener to get local service names (often cameras advertise _http._tcp, _rtsp._tcp or vendor services)
mdns_services = {}
class MDNSListener:
    def remove_service(self, zc, type, name):
        pass
    def add_service(self, zc, type, name):
        info = zc.get_service_info(type, name)
        if info:
            host = socket.inet_ntoa(info.addresses[0]) if info.addresses else None
            mdns_services[host] = {"type": type, "name": name, "properties": info.properties if info else None}

# simple TCP port open check
def is_port_open(ip, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.close()
        return True
    except:
        return False

# http probe
def http_probe(ip, port, timeout=2.0):
    info = {"root_ok": False, "keywords": [], "onvif": None, "server": None}
    url = f"http://{ip}:{port}/"
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        info["root_ok"] = True
        headers = str(r.headers).lower().encode()
        body = r.text.lower().encode()
        for kw in KEYWORDS:
            if kw in headers or kw in body:
                info["keywords"].append(kw.decode())
        info["server"] = r.headers.get("Server")
        # onvif path check
        try:
            r2 = requests.get(f"http://{ip}:{port}/onvif/device_service", timeout=timeout, verify=False)
            if r2.status_code in (200,401,403) or b"onvif" in r2.text.lower().encode():
                info["onvif"] = {"status": r2.status_code}
        except:
            pass
    except:
        pass
    return info

# rtsp probe (OPTIONS)
def rtsp_probe(ip, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        req = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: detector/1.0\r\n\r\n"
        s.send(req.encode())
        data = s.recv(4096)
        s.close()
        if b"RTSP/1.0" in data:
            return True, data.decode(errors='ignore')
    except:
        pass
    return False, None

def score_findings(ip, ssdp_txt, mdns_info, port_findings):
    score = 0
    reasons = []
    if ssdp_txt:
        stxt = ssdp_txt.lower().encode()
        for k in KEYWORDS:
            if k in stxt:
                score += 2
                reasons.append("ssdp_keyword:"+k.decode())
                break
        if "location:" in ssdp_txt.lower():
            score += 1
            reasons.append("ssdp_location")
    if mdns_info:
        score += 2
        reasons.append("mdns_service")

    for pf in port_findings:
        score += 1
        reasons.append(f"open_port:{pf['port']}")
        if pf.get("rtsp_ok"):
            score += 3; reasons.append("rtsp_ok")
        if pf.get("http_keywords"):
            score += 2; reasons.append("http_keywords:"+",".join(pf["http_keywords"]))
        if pf.get("onvif"):
            score += 3; reasons.append("onvif")
    return score, reasons

def scan_ip(ip):
    findings = {"ip": ip, "ports": []}
    for port in COMMON_PORTS:
        if is_port_open(ip, port):
            pf = {"port": port}
            if port in (80,8000,8080,88,9000):
                info = http_probe(ip, port)
                pf["http_keywords"] = info.get("keywords")
                pf["onvif"] = info.get("onvif")
            if port in (554,8554):
                ok, banner = rtsp_probe(ip, port)
                pf["rtsp_ok"] = ok
                pf["rtsp_banner"] = banner
            findings["ports"].append(pf)
    return findings

def main():
    print("Sadece izinli ağlarda kullanın.")
    local_ip = get_local_ip()
    print("Local IP:", local_ip)

    # start mDNS browser in background
    zc = Zeroconf()
    listener = MDNSListener()
    browser = ServiceBrowser(zc, "_http._tcp.local.", listener)

    time.sleep(0.5)
    print("SSDP discovering...")
    ssdp = ssdp_discover(timeout=2)
    print(f"SSDP returned {len(ssdp)} responses.")

    # generate /24 targets
    targets = list(gen_subnet_ips(local_ip))
    print("Scanning subnet /24 (this can take a minute)...")

    found = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        futures = {ex.submit(scan_ip, ip): ip for ip in targets}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                res = fut.result()
                if res["ports"]:
                    found[ip] = res
                    print("[FOUND] ", ip, "ports:", [p["port"] for p in res["ports"]])
            except Exception as e:
                pass

    # analyze and score
    results = []
    for ip, r in found.items():
        ssdp_txt = ssdp.get(ip)
        mdns_info = mdns_services.get(ip)
        score, reasons = score_findings(ip, ssdp_txt, mdns_info, r["ports"])
        if score >= CONFIDENT_THRESHOLD:
            cat = "CONFIDENT"
        elif score >= PROBABLE_THRESHOLD:
            cat = "PROBABLE"
        else:
            cat = "POSSIBLE"
        results.append({"ip": ip, "score": score, "category": cat, "reasons": reasons, "ports": r["ports"]})
    # print summary
    for r in results:
        print(f"{r['category']}: {r['ip']} score={r['score']} reasons={r['reasons']}")

    zc.close()

if __name__ == "__main__":
    main()
