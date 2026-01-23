# Android Transparent Proxy Shell (tproxy.sh)

**tproxy.sh** — A powerful, modular shell script that sets up **transparent proxy** (primarily TPROXY, with REDIRECT fallback) on **rooted Android** devices.

Commonly used with proxy cores like Clash, Mihomo (Clash Meta), sing-box, V2Ray, Xray, Hysteria, etc.

## Main Features

- **Proxy Modes**: TPROXY (preferred, preserves source IP) + REDIRECT fallback (TCP mainly)
- **Per-app proxy**: Blacklist / whitelist mode via package name or UID (supports multi-user: `userId:package`)
- **Network interface control**: Independent proxy enable/disable for mobile data, Wi-Fi, hotspot (tether), USB tether, and custom interfaces
- **Hotspot MAC filtering**: Blacklist / whitelist mode for connected devices via source MAC address (when proxying hotspot)
- **Bypass China mainland IPs**: Auto-download CN IPv4/IPv6 lists (requires curl command)
- **IPv6 full support**: Optional IPv6 proxy (separate mark/table/rules/ip6tables), with bypass lists
- **DNS hijacking**: TPROXY or REDIRECT mode (custom local DNS port)
- **Kernel feature auto-check**: Validates TPROXY, ipset, owner match, mac match, etc.
- **Dry-run support**: Test configuration without applying changes (--dry-run)

## Requirements
- Rooted Android (Magisk / KernelSU / APatch etc.)
- `iptables` / `ip6tables` + `ip` command
- `curl` command (Download CN IPv4/IPv6 lists)
- Kernel modules/features:
  - `xt_TPROXY`, `xt_REDIRECT` (for modes)
  - `xt_owner` (per-app)
  - `xt_mac` (hotspot MAC filter)
  - `ip_set` + `xt_set` (China bypass)
  
    Android kernels lack some of these modules (especially xt_set, xt_mac, full IPv6 NAT/REDIRECT). Custom kernels are often required for full functionality.
- Proxy software listening on localhost with TPROXY support (e.g. sing-box tproxy inbound, xray dokodemo-door + sockopt tproxy)

## Installation

   ```bash
   wget https://raw.githubusercontent.com/CHIZI-0618/AndroidTProxyShell/main/tproxy.sh -O /data/adb/atp
   chmod 755 /data/adb/atp
   ```
> You can rename it to atp (or any name) for convenience — just adjust commands accordingly.

## Usage

### Quick start (most common case)

```bash
su -c "PROXY_TCP_PORT=7893 PROXY_UDP_PORT=7893 /data/adb/atp start"         # Change to your actual proxy inbound port (script default = 1536)
```

### Full Configuration Variables

You can change the configuration by modifying the environment variables below, or by directly editing `tproxy.sh`:

| Option                    | Default         | Description |
|---------------------------|-----------------|-------------|
| `CORE_USER_GROUP`         | `root:net_admin` | User and group under which the core runs (advanced users may change to a custom UID:GID; requires setcap support) |
| `PROXY_TCP_PORT` / `PROXY_UDP_PORT` | `1536` | Transparent proxy listening ports |
| `PROXY_MODE`              | `0`         | Proxy mode: 0 (auto: prefer TPROXY, fallback REDIRECT), 1 (force TPROXY), 2 (force REDIRECT)|
| `DNS_HIJACK_ENABLE`       | `1`            | DNS hijacking (0=disabled, 1=enable TPROXY, 2=enable REDIRECT; no change needed unless necessary) |
| `DNS_PORT`                | `1053`         | DNS listening port |
| `BYPASS_IPv4_LIST`        | `0.0.0.0/8 10.0.0.0/8 100.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32`              | Private/reserved/special-use IPv4 ranges to always bypass proxy (append your own public/local IPs if needed) |
| `BYPASS_IPv6_LIST`        | `::/128 ::1/128 ::ffff:0:0/96 100::/64 64:ff9b::/96 2001::/32 2001:10::/28 2001:20::/28 2001:db8::/32 2002::/16 fe80::/10 ff00::/8` | Private/reserved/special-use IPv6 ranges to always bypass proxy (append your own public/local IPs if needed) |
| `PROXY_IPv4_LIST` / `PROXY_IPv6_LIST`  | Empty | List of IPs that require a proxy |
| `MOBILE_INTERFACE`        | `rmnet_data+`  | Mobile data interface name |
| `WIFI_INTERFACE`          | `wlan0`        | WiFi interface name |
| `HOTSPOT_INTERFACE`       | `wlan2`        | Hotspot interface name |
| `USB_INTERFACE`           | `rndis+`       | USB tethering interface name |
| `OTHER_BYPASS_INTERFACES` | Empty          | Other interfaces that need to bypass the proxy, multiple ones can be separated by spaces |
| `OTHER_PROXY_INTERFACES` | Empty          | Other interfaces that require a proxy, multiple ones can be separated by spaces |
| `PROXY_MOBILE`            | `1`            | Whether to proxy mobile data traffic (1=proxy, 0=do not proxy; supports arbitrary combinations with other interfaces) |
| `PROXY_WIFI`              | `1`            | Whether to proxy WiFi traffic (1=proxy, 0=do not proxy; supports arbitrary combinations with other interfaces) |
| `PROXY_HOTSPOT`           | `0`            | Whether to proxy hotspot traffic (1=proxy, 0=do not proxy; supports arbitrary combinations; MAC filtering takes effect when enabled) |
| `PROXY_USB`               | `0`            | Whether to proxy USB tethering traffic (1=proxy, 0=do not proxy; supports arbitrary combinations with other interfaces) |
| `PROXY_TCP` / `PROXY_UDP` | `1` / `1`      | Whether to proxy TCP/UDP (1=proxy, 0=do not proxy) |
| `PROXY_IPV6`              | `0`            | Whether to proxy IPv6 (1=proxy, 0=disabled; in REDIRECT mode, the module automatically checks kernel support for `IP6_NF_NAT` and `IP6_NF_TARGET_REDIRECT`; if unsupported, IPv6 proxying will be ineffective) |
| `APP_PROXY_ENABLE`        | `0`            | Enable per-application proxying (1=enable) |
| `APP_PROXY_MODE`          | `blacklist`    | `blacklist` (bypass specified apps) or `whitelist` (proxy only specified apps) |
| `BYPASS_APPS_LIST` / `PROXY_APPS_LIST` | Empty | Application list, format: `"userId:package.name"` (multiple entries separated by spaces, e.g. `"0:com.android.systemui" "10:com.tencent.mm"`) |
| `BYPASS_CN_IP`            | `0`            | Whether to bypass Mainland China IPs (1=enable, 0=disable; requires kernel support for `ipset`; the module automatically checks support, and the feature will be disabled if unsupported; when enabled, the IP list is downloaded from the specified URL) |
| `CN_IP_URL` / `CN_IPV6_URL`       |  `https://raw.githubusercontent.com/Hackl0us/GeoIP2-CN/release/CN-ip-cidr.txt` / `https://ispip.clang.cn/all_cn_ipv6.txt`  | Download URL for the Mainland China IP list |
| `MAC_FILTER_ENABLE`       | `0`            | Enable MAC address filtering (1=enable, 0=disable; effective only in hotspot mode `PROXY_HOTSPOT=1`) |
| `MAC_PROXY_MODE`          | `blacklist`    | `blacklist` (bypass specified MACs) or `whitelist` (proxy only specified MACs) |
| `BYPASS_MACS_LIST` / `PROXY_MACS_LIST` | Empty | MAC address list (multiple entries separated by spaces, e.g. `"AA:BB:CC:DD:EE:FF" "11:22:33:44:55:66"`) |
| MARK_VALUE | 20 | Firewall mark for IPv4 routing rules |
| MARK_VALUE6 | 25 | Firewall mark for IPv6 routing rules |
| TABLE_ID | 2025 | Custom ip rule/route table number |
| DRY_RUN | 0 | Set to 1 for simulation mode (logs actions without applying) |

### Stop

```bash
su -c /data/adb/atp stop
```

### Show current status

```bash
su -c iptables -t mangle -vL
su -c iptables -t nat -nvL
```

## Typical proxy software configuration (example)
> Important: The proxy core must listen on the specified port (default 1536) with TPROXY support enabled, and usually needs to run as root or with cap_net_admin capability.

### sing-box example

```json
{
  "dns": {
    "servers": [
      {
        "tag": "ali",
        "type": "https",
        "server": "223.6.6.6"
      }
    ],
    "independent_cache": true,
    "strategy": "ipv4_only"
  },
  "inbounds": [
    {
      "type": "tproxy",
      "tag": "tproxy_in",
      "listen": "::",
      "listen_port": 1536
    }
  ],
  "route": {
    "default_domain_resolver": "ali",
    "rules": [
      {
        "action": "sniff"
      },
      {
        "type": "logical",
        "mode": "or",
        "rules": [
          {
            "port": 53
          },
          {
            "protocol": "dns"
          }
        ],
        "action": "hijack-dns"
      }
    ]
  }
}
```

### Clash Meta (mihomo) example inbound
```yaml
# Transparent proxy server port for Linux (TProxy TCP and TProxy UDP)
tproxy-port: 1536

proxies:
  - name: "DNS_Hijack"
    type: dns

rules:
  - DST-PORT,53,DNS_Hijack
```

### xray / v2ray example (dokodemo-door + tproxy)

```json
{
  "listen": "127.0.0.1",
  "port": 1536,
  "protocol": "dokodemo-door",
  "settings": {
    "network": "tcp,udp",
    "followRedirect": true
  },
  "streamSettings": {
    "sockopt": {
      "tproxy": "tproxy"
    }
  },
  "tag": "transparent-in"
}
```

## License

[GPL-3.0](LICENSE)

## Credits

- Original author: [CHIZI-0618](https://github.com/CHIZI-0618/)
- Repository: [https://github.com/CHIZI-0618/AndroidTProxyShell](https://github.com/CHIZI-0618/AndroidTProxyShell)

Star ⭐ this repo if it helps you!
