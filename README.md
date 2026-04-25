# NetWatch IDS 🔍

A lightweight, real-time network intrusion detection system (IDS) built with Python and Scapy. NetWatch monitors network traffic, detects suspicious activities, and sends instant alerts via Telegram.

## Features

- **Real-time Traffic Monitoring** - Captures and analyzes network packets as they flow
- **Port Scan Detection** - Identifies reconnaissance attempts across multiple ports
- **Flood Attack Detection** - Detects abnormal packet volumes in short time windows
- **Suspicious Port Monitoring** - Alerts on connections to commonly exploited ports
- **GeoIP Lookup** - Identifies the geographic location and ISP of suspicious IPs
- **Telegram Alerts** - Instant notifications delivered to your Telegram
- **Smart Caching** - Reduces API calls with built-in GeoIP cache
- **Lightweight** - Minimal dependencies, low resource usage

## Detection Capabilities

| Attack Type | Detection Method | Threshold |
|-------------|------------------|-----------|
| Port Scanning | Tracks unique ports accessed per IP | 10+ ports |
| Flood Attacks | Monitors packet rate per IP | 50+ packets/10s |
| Suspicious Access | Checks against known vulnerable ports | Instant alert |

### Monitored Ports
FTP (21), SSH (22), Telnet (23), SMTP (25), DNS (53), HTTP (80), POP3 (110), NetBIOS (139), IMAP (143), HTTPS (443), SMB (445), RDP (3389), Metasploit (4444), Bot C&C (5555), IRC (6667), HTTP-Alt (8080)

## Installation

### Prerequisites
- Python 3.7+
- Linux/Unix system (for packet sniffing)
- Root/sudo privileges (required for network monitoring)

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/salahalaya/netwatch-ids.git
cd netwatch-ids
```

2. **Install dependencies**
```bash
pip install scapy requests
```

Or use the requirements file:
```bash
pip install -r requirements.txt
```

3. **Configure Telegram Bot**
   - Create a bot via [@BotFather](https://t.me/botfather)
   - Get your Chat ID from [@userinfobot](https://t.me/userinfobot)
   - Update the configuration in the script:
   ```python
   TELEGRAM_TOKEN = "your_bot_token_here"
   CHAT_ID = "your_chat_id_here"
   ```

## Usage

### Basic Usage
```bash
sudo python3 netwatch.py
```

### Running in Background
```bash
sudo nohup python3 netwatch.py > netwatch.log 2>&1 &
```

### Monitoring Specific Interface
```bash
sudo python3 netwatch.py --interface eth0
```

### Stopping the Service
```bash
sudo pkill -f netwatch.py
```

### Viewing Logs
```bash
tail -f netwatch.log
```

## Configuration

Edit these variables in the script to customize behavior:

```python
TIME_WINDOW = 10              # Time window for flood detection (seconds)
PORT_SCAN_THRESHOLD = 10      # Number of ports to trigger scan alert
FLOOD_THRESHOLD = 50          # Packets per TIME_WINDOW to trigger flood alert
CACHE_TTL = 3600             # GeoIP cache duration (seconds)
```

### Advanced Configuration

You can also add custom suspicious ports:
```python
SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 53, 80, 110,
    139, 143, 443, 445, 3389,
    4444, 5555, 6667, 8080,
    # Add your custom ports here
    9090, 27017
}
```

## Sample Alert

When suspicious activity is detected, you'll receive a Telegram message like:

```
🚨 ALERT
IP: 192.168.1.100
Country: United States
City: San Francisco
ISP: Example ISP
Reason: Port Scan (15 ports)
```

## How It Works

1. **Packet Capture** - Scapy sniffs network packets in real-time
2. **Traffic Analysis** - Each packet is analyzed for source IP, destination, ports, and protocols
3. **Behavior Tracking** - Maintains sliding time windows of activity per IP address
4. **Pattern Detection** - Applies detection algorithms for port scans, floods, and suspicious ports
5. **GeoIP Enrichment** - Looks up geographic information for suspicious IPs
6. **Alert Dispatch** - Sends formatted alerts via Telegram API

## Architecture

```
┌─────────────┐
│   Network   │
│   Traffic   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Scapy     │
│  Sniffer    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Detection  │
│   Engine    │
│ - Port Scan │
│ - Flooding  │
│ - Sus Ports │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   GeoIP     │
│   Lookup    │
│  (Cached)   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Telegram   │
│   Alerts    │
└─────────────┘
```

## Performance

- **Memory Usage**: ~50-100 MB
- **CPU Usage**: 1-5% on average traffic
- **Network Overhead**: Minimal (read-only monitoring)
- **Alert Latency**: < 1 second

## Troubleshooting

### Permission Denied
```bash
# Ensure you're running with sudo
sudo python3 netwatch.py
```

### No Packets Captured
```bash
# Check available interfaces
ip link show

# Specify interface explicitly
sudo python3 netwatch.py --interface eth0
```

### Telegram Alerts Not Working
- Verify bot token is correct
- Confirm chat ID is accurate
- Check internet connectivity
- Test bot manually: send `/start` to your bot

### High False Positive Rate
Adjust thresholds in configuration:
```python
PORT_SCAN_THRESHOLD = 20      # Increase to reduce sensitivity
FLOOD_THRESHOLD = 100         # Increase for high-traffic networks
```

## Use Cases

- **Home Network Protection** - Monitor your home network for intrusions
- **Small Business Security** - Lightweight IDS for small offices
- **Educational Purposes** - Learn about network security and packet analysis
- **Honeypot Monitoring** - Track attacks on decoy systems
- **Security Research** - Analyze attack patterns and techniques

## Limitations

- Requires root privileges for packet capture
- May generate false positives in high-traffic environments
- GeoIP data depends on third-party API availability
- Not suitable as a standalone enterprise security solution
- Does not prevent attacks, only detects and alerts

## Security Considerations

⚠️ **Important**: 
- Keep your Telegram bot token **private**
- Never commit credentials to version control
- Use environment variables for sensitive data
- This is a detection tool, not prevention - implement proper firewall rules
- Regular updates recommended for security patches

## Best Practices

1. **Use Environment Variables** for sensitive configuration
2. **Rotate Logs** regularly to prevent disk space issues
3. **Monitor False Positives** and tune thresholds accordingly
4. **Combine with Firewall** for comprehensive protection
5. **Regular Testing** to ensure alerts are working
6. **Backup Configuration** before making changes

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Setup
```bash
git clone https://github.com/salahalaya/netwatch-ids.git
cd netwatch-ids
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Roadmap

- [ ] Email notification support
- [ ] Discord webhook integration
- [ ] Web dashboard for visualization
- [ ] Machine learning-based anomaly detection
- [ ] Support for custom detection rules (YAML config)
- [ ] Database logging (SQLite) for historical analysis
- [ ] Multi-interface monitoring
- [ ] Whitelist/blacklist IP management
- [ ] Automated blocking via iptables integration
- [ ] RESTful API for external integration
- [ ] Docker containerization
- [ ] Windows support via WinPcap

## File Structure

```
netwatch-ids/
├── netwatch.py           # Main script
├── README.md            # This file
├── requirements.txt     # Python dependencies
├── LICENSE             # MIT License
├── .gitignore          # Git ignore rules
└── examples/
    ├── config.example.py
    └── systemd/
        └── netwatch.service
```

## Deployment

### Systemd Service (Linux)

Create `/etc/systemd/system/netwatch.service`:
```ini
[Unit]
Description=NetWatch IDS Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netwatch-ids
ExecStart=/usr/bin/python3 /opt/netwatch-ids/netwatch.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable netwatch
sudo systemctl start netwatch
sudo systemctl status netwatch
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and authorized security monitoring purposes only. Always ensure you have permission to monitor network traffic. Unauthorized network monitoring may be illegal in your jurisdiction. The authors are not responsible for misuse of this software.

## Author

Created with ❤️ by the security community

Project Link: [https://github.com/salahalaya/netwatch-ids](https://github.com/salahalaya/netwatch-ids)

## Acknowledgments

- [Scapy](https://scapy.net/) - Powerful packet manipulation library
- [ip-api.com](http://ip-api.com/) - Free GeoIP lookup service
- [Telegram Bot API](https://core.telegram.org/bots/api) - Reliable alert delivery platform
- The open-source security community

## Support

- **Issues**: [GitHub Issues](https://github.com/salahalaya/netwatch-ids/issues)
- **Discussions**: [GitHub Discussions](https://github.com/salahalaya/netwatch-ids/discussions)
- **Email**: hello@salahalaya.tn

## Star History

If you find NetWatch IDS useful, please consider giving it a ⭐ on GitHub!

---

**Stay Secure! 🛡️**
