# DNS AdBlock

A Pi-hole-style DNS ad-blocker for ESP32-C3, ESP8266 D1 Mini, and Raspberry Pi Pico W. No PSRAM required.

## How It Works

The device runs a DNS server on port 53 that intercepts all DNS queries from clients on your network. Instead of loading entire domain strings into RAM (which requires expensive PSRAM), it stores blocked domains as sorted 40-bit FNV-1a hashes directly in flash memory.

### Boot Sequence

1. Mount LittleFS filesystem from flash
2. Load `blocklist.bin` (sorted hash table) and build a 4096-entry index for fast lookups
3. Load custom blocked domains, banned client IPs, and update config from LittleFS files
4. Attempt WiFi connection using saved credentials (EEPROM/LittleFS); fall back to captive portal if none exist
5. Start UDP listener on port 53 (DNS), HTTP server on port 80 (dashboard), and mDNS for `.local` discovery

### DNS Query Processing

```
Client sends DNS query (UDP port 53)
  |
  v
Parse DNS packet: extract domain name + query type
  |
  v
Check if client IP is banned -> block immediately
  |
  v
For each domain level (e.g., ads.example.com -> example.com):
  Compute 40-bit FNV-1a hash
  |
  v
Check custom domain list (linear scan, small list)
  |
  v
Check direct-mapped RAM cache (256 slots)
  |
  v
Binary search the 4096-entry flash index to find the segment
  |
  v
Read up to 256 hashes from flash for that segment
  |
  v
Linear scan within segment for exact match
  |
  v
Match found? -> Build DNS response with 0.0.0.0 (sinkhole)
No match?    -> Forward query to upstream DNS (e.g., 9.9.9.9), relay reply back
```

### Why 40-Bit Hashes

| Domains | Flash used | Collisions | RAM needed |
|---------|-----------|------------|------------|
| 141k | 0.67 MB | 0 | ~50 KB |
| 250k | 1.2 MB | ~0 | ~50 KB |
| 537k | 2.6 MB | ~1 | ~50 KB |

Collisions follow the birthday bound. At 141k domains you get zero collisions; at 537k about one domain gets accidentally over-blocked. Dropping to 32 bits saves 20% flash but costs ~7 collisions at 250k domains. Going to 64 bits wastes 3 bytes per entry solving a problem that doesn't exist.

### Flash Index Structure

The full sorted hash list lives in flash. A 4096-entry index (20 KB) samples evenly-spaced hashes from the list. On lookup, binary search on the index narrows to a segment of at most 256 hashes, then a single flash read fetches that segment. This gives O(log N) index search + O(1) flash reads per query instead of scanning the whole list.

### Memory Budget

- **~20 KB**: flash index (4096 entries x 5 bytes)
- **~1.5 KB**: RAM cache (256 slots x 6 bytes)
- **~1.5 KB**: range buffer for flash reads
- **~1.5 KB**: UDP packet buffer
- **~10 KB**: client tracking table (96 devices)
- **~15 KB**: custom domains, banned IPs, misc state
- **Total: ~50 KB RAM** regardless of blocklist size

### Client Tracking

Each unique client IP gets an entry with MAC address (resolved via ARP table), block/allow counters, last-seen timestamp, and ban status. Clients can be banned from the dashboard to block all their DNS queries.

### WiFi Provisioning

If no WiFi credentials are saved, the device starts an open access point named `AdBlock-XXXX` and runs a captive portal DNS server (all queries resolve to the device). A web form lets you pick a scanned SSID and enter a password. Credentials are saved to EEPROM (ESP8266) or LittleFS (Pico W) or NVS (ESP32-C3) and survive reboots. Holding BOOT at power-on clears saved credentials.

## Supported Boards

| Board | PlatformIO env | Arduino sketch | Notes |
|---|---|---|---|
| ESP32-C3 | `esp32-c3` | `Arduino/adblock_esp32c3/adblock_esp32c3.ino` | Primary target, OTA + NVS |
| ESP8266 D1 Mini | `esp8266-d1-mini` | `Arduino/adblock_esp8266/adblock_esp8266.ino` | EEPROM instead of NVS, no temperature sensor |
| Raspberry Pi Pico W | `pico-w` | `Arduino/adblock_picow/adblock_picow.ino` | LittleFS WiFi creds, no OTA firmware upload |

## Project Structure

```
PlatformIO/
  esp32-c3/          - ESP32-C3 PlatformIO project
  esp8266-d1-mini/   - ESP8266 D1 Mini PlatformIO project
  pico-w/            - Pico W PlatformIO project
Arduino/
  adblock_esp32c3/   - ESP32-C3 Arduino IDE sketch
  adblock_esp8266/   - ESP8266 Arduino IDE sketch
  adblock_picow/     - Pico W Arduino IDE sketch
tools/               - build_blocklist.py
webflasher/          - Browser-based USB flasher (index.html)
data/                - Blocklist output
hardware/            - Enclosure STL files
```

## Build & Flash (PlatformIO)

```bash
Edit PlatformIO/<board>/src/secrets.h with your credentials
python3 tools/build_blocklist.py data/blocklist.bin
cd PlatformIO/<board>
pio run -t upload
pio run -t uploadfs
```

## Build & Flash (Arduino IDE)

1. Open the `.ino` file from `Arduino/<board>/`
2. Install required board core and libraries
3. Copy `page.h` and `secrets.h` into the sketch folder
4. Upload `data/blocklist.bin` via LittleFS upload plugin
5. Compile and upload

## Web Flasher

Open `webflasher/index.html` in Chrome or Edge. Select your board, pick the compiled `.bin` file, and click Flash. Uses Web Serial API for direct browser-to-USB flashing. Pico W requires `.uf2` via picotool instead.

## WiFi Setup

If the device cannot connect, it starts an open access point with a captive portal. Join it from a phone, select your network, enter the password. To reset: hold BOOT button at power-on (ESP32-C3/ESP8266) or use the dashboard Forget WiFi button.

## Dashboard

Access at `http://adblock.local` (or `http://c3adblock.local` for ESP32-C3). Features:

- Per-client block/allow stats
- Ban/unban clients by IP
- Add/remove custom blocked domains
- Upload new blocklist over WiFi
- Remote auto-update from URL on schedule
- Firmware OTA update (ESP32-C3 and ESP8266 only)
- Pause/resume blocking

## Security

All state-changing endpoints require HTTP Basic Auth (`WEB_USER`/`WEB_PASS` from `secrets.h`) plus a CSRF header (`X-Requested-With: adblock`). Change default credentials before deploying. The WiFi setup portal AP is open by design during initial configuration.

## Blocklist Generation

```bash
python3 tools/build_blocklist.py data/blocklist.bin [SOURCE ...]
```

Accepts hosts files, plain domain lists, and AdGuard/Adblock rules. A blocked domain also blocks subdomains.

## Testing

```bash
dig @<device-ip> doubleclick.net   # -> 0.0.0.0  (blocked)
dig @<device-ip> github.com        # -> real IP  (forwarded)
```

## License

MIT
