# Android Transparent Proxy Shell (tproxy.sh)

**tproxy.sh** — A powerful, modular shell script that sets up **transparent proxy** (primarily TPROXY, with REDIRECT fallback) on **rooted Android** devices.

Commonly used with proxy cores like Clash, Mihomo (Clash Meta), sing-box, V2Ray, Xray, Hysteria, etc.

## Main Features
- **Proxy Modes**: TPROXY (preferred, preserves original source IP/port) + REDIRECT fallback (**TCP-only** in practice)
- **Per-app proxy**: Blacklist / whitelist mode via package name or UID (supports multi-user: `userId:package` format)
- **Network interface control**: Independent proxy enable/disable for mobile data, Wi-Fi, hotspot (tether), USB tether, and custom interfaces (via `OTHER_PROXY_INTERFACES` / `OTHER_BYPASS_INTERFACES`)
- **Hotspot MAC filtering**: Blacklist / whitelist mode for connected hotspot clients via source MAC address (only effective when hotspot proxying is enabled)
- **Bypass China mainland IPs**: Auto-download & ipset-based bypass of CN IPv4/IPv6 lists (requires `curl` and kernel `ipset` support)
- **IPv6 full support**: Optional separate IPv6 proxy rules/mark/table (TPROXY preferred; REDIRECT very limited due to kernel NAT support requirements)
- **DNS hijacking**: TPROXY or REDIRECT mode to custom local DNS port (protects against leaks; special handling for IPv6 REDIRECT compatibility)
- **QUIC blocking**: Optional block of QUIC protocol (UDP port 443) via `BLOCK_QUIC=1` — can be global or only block non-CN destinations (when combined with `BYPASS_CN_IP=1` using ipset)
- **User-defined hooks**: Optional `pre_start_hook()` and `post_stop_hook()` functions in `tproxy.conf` — executed before starting proxy rules and after stopping cleanup (e.g. start/stop proxy core)
- **Kernel feature auto-check**: Validates required modules (`xt_TPROXY`, `xt_REDIRECT`, `xt_owner`, `xt_mac`, `ip_set`, etc.) at runtime
- **Dry-run support**: Test configuration without applying changes (`--dry-run` flag)
- **SKIP_CHECK_FEATURE** (advanced/optional): Force skip all kernel module/feature checks via `SKIP_CHECK_FEATURE=1`. Useful on custom/old kernels where `/proc/config.gz` is missing or checks fail incorrectly — **use with caution** as it may apply incompatible rules

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
   wget https://raw.githubusercontent.com/CHIZI-0618/AndroidTProxyShell/main/tproxy.sh -O /data/adb/atp && chmod 755 /data/adb/atp
   ```
> You can rename it to atp (or any name) for convenience — just adjust commands accordingly.

## Usage

### Configuration Loading Priority

1. **Environment variables** passed via command line (highest priority)
   e.g. `PROXY_TCP_PORT=7893 PROXY_UDP_PORT=7893 ./atp start`

2. **tproxy.conf** file in the directory specified by `-d / --dir` (or default script directory)
   If the file exists, it will be sourced automatically.

3. **Built-in defaults** in the script (lowest priority)

### Quick start (most common case)

```bash
# Basic start (uses script defaults + any tproxy.conf in script dir)
su -c "/data/adb/atp start"

# With custom config directory (recommended)
su -c "/data/adb/atp -d /data/adb/ start"

# Override port + enable QUIC block
su -c "PROXY_TCP_PORT=7893 PROXY_UDP_PORT=7893 BLOCK_QUIC=1 /data/adb/atp -d /data/adb start"
```
### Creating tproxy.conf (recommended)

Create `tproxy.conf` in your config directory (e.g. `/data/adb/tproxy.conf`):

```bash
# Example tproxy.conf
PROXY_TCP_PORT=7893
PROXY_UDP_PORT=7893
PROXY_MODE=1                # force TPROXY
DNS_HIJACK_ENABLE=1
DNS_PORT=1053
BLOCK_QUIC=1                # block QUIC
BYPASS_CN_IP=1
PROXY_IPV6=1
# Add any other variables you want to override
```

### Advanced: User Hooks (Optional)

You can define two optional hook functions in `tproxy.conf` (or directly in the script) to run custom code:

- `pre_start_hook()` — Executed **before** applying proxy rules (e.g. start your proxy core, check conditions)
- `post_stop_hook()` — Executed **after** all cleanup (e.g. stop/kill proxy core, additional logging)

These hooks are automatically called if defined. The script logs when they are executed or skipped.

Example in tproxy.conf:

```bash
pre_start_hook() {
    log Info "User pre-start: launching proxy core..."
    # Example: start proxy-binary
    su -c "busybox setuidgid $CORE_USER_GROUP /path/to/proxy-binary ..."
    sleep 3  # wait for core to be ready
}

post_stop_hook() {
    log Info "User post-stop: cleaning up..."
    # Example: kill proxy process
    pkill -f clash
}
```

**Notes**:
- Do **not** define functions with names that conflict with built-in script functions (e.g. `log`, `start_proxy`, `block_quic`, etc.), or it may break the script.
- Hooks run in the same shell environment, so they can access variables like `$PROXY_TCP_PORT`, `$CORE_USER`, etc.
- Use them to integrate proxy core startup/shutdown seamlessly.


### Full Configuration Variables

You can override any of these via environment variables, tproxy.conf, or by editing the script directly:

| Option                                 | Default                                                                                                                                                                                                       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `CORE_USER_GROUP`¹                     | `root:net_admin`                                                                                                                                                                                              | User and group under which the core runs (advanced users may change to a custom UID:GID; requires setcap support)                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `ROUTING_MARK`                         | Empty                                                                                                                                                                                                         | Optional firewall mark value (numeric, e.g. 99) used as fallback to bypass proxy core's own traffic when kernel lacks `xt_owner` support (NETFILTER_XT_MATCH_OWNER). If set and kernel supports `xt_mark` (NETFILTER_XT_MATCH_MARK), the script adds a rule `-m mark --mark $ROUTING_MARK -j ACCEPT` in the app chain. Many proxy cores (sing-box, mihomo, xray etc.) can mark their outbound traffic via config (e.g. "mark": 99 in outbound or streamSettings). Prevents traffic loops if UID/GID matching is unavailable. Leave empty if `xt_owner` works |
| `PROXY_TCP_PORT` / `PROXY_UDP_PORT`    | `1536`                                                                                                                                                                                                        | Transparent proxy listening ports                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `PROXY_MODE`                           | `0`                                                                                                                                                                                                           | Proxy mode: 0 (auto: prefer TPROXY, fallback REDIRECT), 1 (force TPROXY), 2 (force REDIRECT)                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `DNS_HIJACK_ENABLE`                    | `1`                                                                                                                                                                                                           | DNS hijacking (0=disabled, 1=enable TPROXY, 2=enable REDIRECT; no change needed unless necessary)                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `DNS_PORT`                             | `1053`                                                                                                                                                                                                        | DNS listening port                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `BYPASS_IPv4_LIST`                     | `0.0.0.0/8 10.0.0.0/8 100.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32` | Private/reserved/special-use IPv4 ranges to always bypass proxy (append your own public/local IPs if needed)                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `BYPASS_IPv6_LIST`                     | `::/128 ::1/128 ::ffff:0:0/96 100::/64 64:ff9b::/96 2001::/32 2001:10::/28 2001:20::/28 2001:db8::/32 2002::/16 fe80::/10 ff00::/8`                                                                           | Private/reserved/special-use IPv6 ranges to always bypass proxy (append your own public/local IPs if needed)                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `PROXY_IPv4_LIST` / `PROXY_IPv6_LIST`  | Empty                                                                                                                                                                                                         | List of IPs that require a proxy                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `MOBILE_INTERFACE`                     | `rmnet_data+`                                                                                                                                                                                                 | Mobile data interface name                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `WIFI_INTERFACE`                       | `wlan0`                                                                                                                                                                                                       | WiFi interface name                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `HOTSPOT_INTERFACE`                    | `wlan2`                                                                                                                                                                                                       | Hotspot interface name                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `USB_INTERFACE`                        | `rndis+`                                                                                                                                                                                                      | USB tethering interface name                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `OTHER_BYPASS_INTERFACES`              | Empty                                                                                                                                                                                                         | Other interfaces that need to bypass the proxy, multiple ones can be separated by spaces                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `OTHER_PROXY_INTERFACES`               | Empty                                                                                                                                                                                                         | Other interfaces that require a proxy, multiple ones can be separated by spaces                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `PROXY_MOBILE`                         | `1`                                                                                                                                                                                                           | Whether to proxy mobile data traffic (1=proxy, 0=do not proxy; supports arbitrary combinations with other interfaces)                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `PROXY_WIFI`                           | `1`                                                                                                                                                                                                           | Whether to proxy WiFi traffic (1=proxy, 0=do not proxy; supports arbitrary combinations with other interfaces)                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `PROXY_HOTSPOT`                        | `0`                                                                                                                                                                                                           | Whether to proxy hotspot traffic (1=proxy, 0=do not proxy; supports arbitrary combinations; MAC filtering takes effect when enabled)                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `PROXY_USB`                            | `0`                                                                                                                                                                                                           | Whether to proxy USB tethering traffic (1=proxy, 0=do not proxy; supports arbitrary combinations with other interfaces)                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `PROXY_TCP` / `PROXY_UDP`              | `1` / `1`                                                                                                                                                                                                     | Whether to proxy TCP/UDP (1=proxy, 0=do not proxy)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `PROXY_IPV6`                           | `0`                                                                                                                                                                                                           | Whether to proxy IPv6 (1=proxy, 0=disabled; in REDIRECT mode, the module automatically checks kernel support for `IP6_NF_NAT` and `IP6_NF_TARGET_REDIRECT`; if unsupported, IPv6 proxying will be ineffective)                                                                                                                                                                                                                                                                                                                                               |
| `APP_PROXY_ENABLE`                     | `0`                                                                                                                                                                                                           | Enable per-application proxying (1=enable)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `APP_PROXY_MODE`                       | `blacklist`                                                                                                                                                                                                   | `blacklist` (bypass specified apps) or `whitelist` (proxy only specified apps)                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `BYPASS_APPS_LIST` / `PROXY_APPS_LIST` | Empty                                                                                                                                                                                                         | Application list, format: `"userId:package.name"` (multiple entries separated by spaces, e.g. `"0:com.android.systemui" "10:com.tencent.mm"`)                                                                                                                                                                                                                                                                                                                                                                                                                |
| `BYPASS_CN_IP`                         | `0`                                                                                                                                                                                                           | Whether to bypass Mainland China IPs (1=enable, 0=disable; requires kernel support for `ipset`; the module automatically checks support, and the feature will be disabled if unsupported; when enabled, the IP list is downloaded from the specified URL)                                                                                                                                                                                                                                                                                                    |
| `BLOCK_QUIC`                           | `0`                                                                                                                                                                                                           | Whether to block QUIC traffic (UDP 443). 0=allow, 1=block. When `BYPASS_CN_IP=1`, only blocks non-CN destinations (using cnip/cnip6 ipset); otherwise blocks globally. Recommended with `BYPASS_CN_IP=1` for users in China                                                                                                                                                                                                                                                                                                                                  |
| `CN_IP_URL` / `CN_IPV6_URL`            | `https://raw.githubusercontent.com/Hackl0us/GeoIP2-CN/release/CN-ip-cidr.txt` / `https://ispip.clang.cn/all_cn_ipv6.txt`                                                                                      | Download URL for the Mainland China IP list                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `MAC_FILTER_ENABLE`                    | `0`                                                                                                                                                                                                           | Enable MAC address filtering (1=enable, 0=disable; effective only in hotspot mode `PROXY_HOTSPOT=1`)                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `MAC_PROXY_MODE`                       | `blacklist`                                                                                                                                                                                                   | `blacklist` (bypass specified MACs) or `whitelist` (proxy only specified MACs)                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `BYPASS_MACS_LIST` / `PROXY_MACS_LIST` | Empty                                                                                                                                                                                                         | MAC address list (multiple entries separated by spaces, e.g. `"AA:BB:CC:DD:EE:FF" "11:22:33:44:55:66"`)                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `MARK_VALUE`                           | `20`                                                                                                                                                                                                          | Firewall mark for IPv4 routing rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `MARK_VALUE6`                          | `25`                                                                                                                                                                                                          | Firewall mark for IPv6 routing rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `TABLE_ID`                             | `2025`                                                                                                                                                                                                        | Custom ip rule/route table number                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `DRY_RUN`                              | `0`                                                                                                                                                                                                           | Set to 1 for simulation mode (logs actions without applying)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
  
¹ **CORE_USER_GROUP** — This value is used by the script to exclude/bypass the proxy core's own traffic (via owner match rules), preventing loops. It should match the actual user:group under which your proxy core (sing-box, mihomo, etc.) is running. See **[Typical proxy software configuration (example)](#typical-proxy-software-configuration-example)** section below for important notes on how to launch the core on Android with the correct user/group.

### Stop

```bash
su -c "/data/adb/atp stop"
# or with custom config dir
su -c "/data/adb/atp -d /data/adb stop"
```

### Show current status

```bash
su -c iptables -t mangle -vL
su -c iptables -t nat -nvL
su -c ip rule show
su -c ip route show table all | grep 2025   # adjust if you changed TABLE_ID
```

## Typical proxy software configuration (example)
> Important: The proxy core must listen on the specified port (default 1536) with TPROXY support enabled, and usually needs to run as root or with cap_net_admin capability.
  
On Android, to start the core matching your `CORE_USER_GROUP`:

- **Using busybox setuidgid** (good for dropping to a specific user:group after su):
  ```bash
  su -c "busybox setuidgid $CORE_USER_GROUP /path/to/proxy-binary ..."
  ```

- **For non-root users** (custom UID:GID): First grant capabilities to the binary (once, as root):
  ```bash
  su -c "setcap cap_net_admin,cap_net_bind_service,cap_net_raw+eip /path/to/proxy-binary"
  ```
  Then launch with setuidgid (or su -u <uid> -g <gid>):
  ```bash
  su -c "busybox setuidgid $CORE_USER_GROUP /path/to/proxy-binary ..."
  ```

- **Alternative with capsh** (temporary ambient capabilities):
  ```bash
  su -c "capsh --caps='cap_net_admin,cap_net_bind_service,cap_net_raw+eip' --addamb='cap_net_admin,cap_net_bind_service,cap_net_raw' --secbits=1 -- -c '/path/to/proxy-binary ...'"
  ```

Required capabilities typically include: `cap_net_admin` (routing/tproxy), `cap_net_bind_service` (low ports), `cap_net_raw` (raw sockets if needed). Test with `getcap /path/to/binary`.

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

### Clash example inbound
```yaml
# Transparent proxy server port for Linux (TProxy TCP and TProxy UDP)
tproxy-port: 1536

# Ensure the `dns.listen` value matches `DNS_PORT` in the config, and set `DNS_HIJACK_ENABLE` to `2`
dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/15
  fake-ip-filter:
    - "*"
    - "+.lan"
    - "+.local"
    - "+.market.xiaomi.com"
    - "localhost.ptlogin2.qq.com"
  nameserver:
    - https://120.53.53.53/dns-query
    - https://223.5.5.5/dns-query
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
