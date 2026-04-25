from scapy.all import sniff, IP, TCP, UDP, get_if_addr, conf
from collections import defaultdict, deque
import requests
import time
import socket

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

# Suspicious ports (commonly targeted)
SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 53, 80, 110,
    139, 143, 443, 445, 3389,
    4444, 5555, 6667, 8080
}

# =========================
# AUTO-DETECT SERVER IP
# =========================
def get_server_ips():
    """Get all IPs of this server to filter out our own traffic"""
    ips = set()
    try:
        # Get primary interface IP
        ips.add(get_if_addr(conf.iface))
        
        # Get all local IPs
        hostname = socket.gethostname()
        local_ips = socket.getaddrinfo(hostname, None)
        for ip_info in local_ips:
            ips.add(ip_info[4][0])
        
        # Add localhost
        ips.add('127.0.0.1')
        ips.add('::1')
    except:
        pass
    
    # Remove None values
    ips.discard(None)
    return ips

SERVER_IPS = get_server_ips()
print(f"🛡️  Monitoring for threats. Server IPs detected: {SERVER_IPS}\n")

# =========================
# DATA STORAGE
# =========================
# Track INCOMING threats by remote IP
incoming_threats = defaultdict(lambda: {
    "count": 0,
    "ports": set(),
    "timestamps": deque(),
    "syn_count": 0,  # Track SYN flood attempts
    "last_alert": 0   # Prevent alert spam
})

geo_cache = {}
CACHE_TTL = 3600
ALERT_COOLDOWN = 60  # Don't spam same IP alerts within 60s

# =========================
# TELEGRAM FUNCTION
# =========================
def send_telegram(msg):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": CHAT_ID, "text": msg}, timeout=5)
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
# DETECTION FUNCTIONS
# =========================
def detect_port_scan(threat_data):
    """Detect if an IP is scanning multiple ports"""
    if len(threat_data["ports"]) >= PORT_SCAN_THRESHOLD:
        return True, f"Port Scan ({len(threat_data['ports'])} ports)"
    return False, None

def detect_flood(threat_data):
    """Detect packet flood from single IP"""
    if len(threat_data["timestamps"]) < 2:
        return False, None
    
    duration = threat_data["timestamps"][-1] - threat_data["timestamps"][0]
    if duration <= TIME_WINDOW and threat_data["count"] >= FLOOD_THRESHOLD:
        return True, f"Flood ({threat_data['count']} packets/{TIME_WINDOW}s)"
    return False, None

def detect_syn_flood(threat_data):
    """Detect SYN flood attack"""
    if threat_data["syn_count"] >= 20:  # 20+ SYN packets in window
        return True, f"SYN Flood ({threat_data['syn_count']} SYN packets)"
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
    
    # =========================
    # FILTER: ONLY TRACK INCOMING TRAFFIC
    # =========================
    # Skip if destination is not our server
    if dst_ip not in SERVER_IPS:
        return
    
    # Skip if source is our server (outbound traffic)
    if src_ip in SERVER_IPS:
        return
    
    # Skip private/local IPs (adjust if you need to monitor LAN)
    if src_ip.startswith(('10.', '172.16.', '192.168.', '127.')):
        return
    
    # =========================
    # TRACK THE REMOTE IP
    # =========================
    threat_data = incoming_threats[src_ip]
    threat_data["count"] += 1
    threat_data["timestamps"].append(now)
    
    port = None
    proto = ""
    is_syn = False
    
    if packet.haslayer(TCP):
        port = packet[TCP].dport
        proto = "TCP"
        # Check for SYN flag (new connection attempt)
        if packet[TCP].flags & 0x02:  # SYN flag
            is_syn = True
            threat_data["syn_count"] += 1
    elif packet.haslayer(UDP):
        port = packet[UDP].dport
        proto = "UDP"
    
    if port:
        threat_data["ports"].add(port)
    
    # =========================
    # LIVE OUTPUT (INCOMING ONLY)
    # =========================
    syn_marker = " [SYN]" if is_syn else ""
    print(f"[{proto}] {src_ip} -> {dst_ip}:{port}{syn_marker}", flush=True)
    
    # =========================
    # ALERT FUNCTION
    # =========================
    def alert(message):
        # Prevent alert spam - only alert once per minute per IP
        if now - threat_data["last_alert"] < ALERT_COOLDOWN:
            return
        
        threat_data["last_alert"] = now
        geo = get_geo(src_ip)
        
        full_msg = f"""
🚨 THREAT DETECTED
IP: {src_ip}
Target: {dst_ip}:{port}
Country: {geo['country']}
City: {geo['city']}
ISP: {geo['isp']}
Reason: {message}
Packets: {threat_data['count']} in {TIME_WINDOW}s
Ports targeted: {len(threat_data['ports'])}
"""
        print(full_msg, flush=True)
        send_telegram(full_msg)
    
    # =========================
    # RUN DETECTIONS
    # =========================
    # 1. Suspicious port detection
    if port and port in SUSPICIOUS_PORTS and is_syn:
        alert(f"Connection attempt to suspicious port {port}")
    
    # 2. Port scan detection
    scan_detected, scan_msg = detect_port_scan(threat_data)
    if scan_detected:
        alert(scan_msg)
    
    # 3. SYN flood detection
    syn_flood, syn_msg = detect_syn_flood(threat_data)
    if syn_flood:
        alert(syn_msg)
    
    # 4. General packet flood detection
    flood_detected, flood_msg = detect_flood(threat_data)
    if flood_detected:
        alert(flood_msg)
    
    # =========================
    # CLEANUP OLD DATA
    # =========================
    while threat_data["timestamps"] and now - threat_data["timestamps"][0] > TIME_WINDOW:
        threat_data["timestamps"].popleft()
        if threat_data["count"] > 0:
            threat_data["count"] -= 1
        if threat_data["syn_count"] > 0:
            threat_data["syn_count"] -= 1

# =========================
# START
# =========================
if __name__ == "__main__":
    print("=" * 50)
    print("🛡️  NETWATCH IDS - INCOMING THREAT MONITOR")
    print("=" * 50)
    print(f"Time Window: {TIME_WINDOW}s")
    print(f"Port Scan Threshold: {PORT_SCAN_THRESHOLD} ports")
    print(f"Flood Threshold: {FLOOD_THRESHOLD} packets")
    print(f"Alert Cooldown: {ALERT_COOLDOWN}s")
    print("=" * 50)
    print()
    
    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping IDS...")
        print(f"Total unique IPs monitored: {len(incoming_threats)}")
