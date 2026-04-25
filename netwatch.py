from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict, deque
import requests
import time

# =========================
# CONFIG
# =========================

TIME_WINDOW = 10
PORT_SCAN_THRESHOLD = 10
FLOOD_THRESHOLD = 50

# Telegram config
TELEGRAM_TOKEN = "YOUR_BOT_TOKEN"
CHAT_ID = "YOUR_CHAT_ID"

# GeoIP API
GEO_API = "http://ip-api.com/json/"

# Suspicious ports
SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 53, 80, 110,
    139, 143, 443, 445, 3389,
    4444, 5555, 6667, 8080
}

# =========================
# DATA STORAGE
# =========================

traffic_log = defaultdict(lambda: {
    "count": 0,
    "ports": set(),
    "timestamps": deque()
})

geo_cache = {}
CACHE_TTL = 3600

# =========================
# TELEGRAM FUNCTION
# =========================

def send_telegram(msg):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": CHAT_ID, "text": msg})
    except:
        pass

# =========================
# GEOIP LOOKUP
# =========================

def get_geo(ip):
    now = time.time()

    if ip in geo_cache:
        data, ts = geo_cache[ip]
        if now - ts < CACHE_TTL:
            return data

    try:
        r = requests.get(GEO_API + ip, timeout=3)
        data = r.json()

        info = {
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("isp", "Unknown")
        }

        geo_cache[ip] = (info, now)
        return info

    except:
        return {"country": "?", "city": "?", "isp": "?"}

# =========================
# DETECTION
# =========================

def detect_port_scan(ip_data):
    if len(ip_data["ports"]) >= PORT_SCAN_THRESHOLD:
        return True, f"Port Scan ({len(ip_data['ports'])} ports)"
    return False, None


def detect_flood(ip_data):
    if len(ip_data["timestamps"]) < 2:
        return False, None

    duration = ip_data["timestamps"][-1] - ip_data["timestamps"][0]

    if duration <= TIME_WINDOW and ip_data["count"] >= FLOOD_THRESHOLD:
        return True, f"Flood ({ip_data['count']} packets/{TIME_WINDOW}s)"

    return False, None


# =========================
# PACKET HANDLER
# =========================

def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    now = time.time()

    ip_data = traffic_log[src_ip]
    ip_data["count"] += 1
    ip_data["timestamps"].append(now)

    port = None
    proto = ""

    if packet.haslayer(TCP):
        port = packet[TCP].dport
        proto = "TCP"
    elif packet.haslayer(UDP):
        port = packet[UDP].dport
        proto = "UDP"

    if port:
        ip_data["ports"].add(port)

    # =========================
    # LIVE OUTPUT
    # =========================
    print(f"[{proto}] {src_ip} -> {dst_ip} | port: {port}", flush=True)

    geo = get_geo(src_ip)

    # =========================
    # ALERT FUNCTION
    # =========================
    def alert(message):
        full_msg = f"""
🚨 ALERT
IP: {src_ip}
Country: {geo['country']}
City: {geo['city']}
ISP: {geo['isp']}
Reason: {message}
"""
        print(full_msg, flush=True)
        send_telegram(full_msg)

    # =========================
    # DETECTIONS
    # =========================

    if port and port in SUSPICIOUS_PORTS:
        alert(f"Suspicious Port {port}")

    scan, msg = detect_port_scan(ip_data)
    if scan:
        alert(msg)

    flood, msg = detect_flood(ip_data)
    if flood:
        alert(msg)

    # cleanup
    while ip_data["timestamps"] and now - ip_data["timestamps"][0] > TIME_WINDOW:
        ip_data["timestamps"].popleft()


# =========================
# START
# =========================

if __name__ == "__main__":
    print("STARTED\n")
    sniff(prn=process_packet, store=False)
