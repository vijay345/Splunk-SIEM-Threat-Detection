# 🔍 Splunk SIEM Threat Detection Dashboard

> **Real-world SSH brute force attack simulation, live detection, and visualisation using Splunk Enterprise SIEM — mapped to MITRE ATT&CK T1110.**

---

## 📌 Overview

This project demonstrates a fully operational Security Information and Event Management (SIEM) lab built with Splunk Enterprise. A brute force attack is simulated from a Kali Linux attacker VM against an Ubuntu Server target, with all attack telemetry ingested, detected, and visualised in real time inside Splunk dashboards.

The lab covers:
- Setting up Splunk Enterprise on Ubuntu Server as the SIEM platform
- Configuring log ingestion from SSH auth logs and syslog
- Simulating a real SSH brute force attack from Kali Linux
- Writing SPL (Search Processing Language) detection queries
- Building live dashboards showing attacker IPs, timelines, and attack summaries
- Mapping detections to MITRE ATT&CK framework

---

## 🧱 Lab Environment

| Component        | Details                                      |
|-----------------|----------------------------------------------|
| SIEM Platform   | Splunk Enterprise 10.2.1 (Free License)      |
| SIEM Host       | Ubuntu 22.04 Server VM (VirtualBox)          |
| Attacker        | Kali Linux VM (VirtualBox)                   |
| Network         | Host-only adapter (isolated lab network)     |
| SIEM Host IP    | 192.168.20.20                                |
| Attacker IP     | 192.168.20.11                                |
| Log Sources     | /var/log/auth.log, /var/log/syslog           |
| Attack Tool     | Custom Bash loop + Python log generator      |

---

## 🗺️ Architecture Diagram

```
┌─────────────────────────┐        SSH Port 22         ┌──────────────────────────┐
│   Kali Linux Attacker   │ ────────────────────────►  │   Ubuntu SIEM Server     │
│   IP: 192.168.20.11     │   30+ failed login attempts │   IP: 192.168.20.20      │
│                         │ ◄────────────────────────   │   Splunk on port 8000    │
└─────────────────────────┘   Auth failure responses    └──────────┬───────────────┘
                                                                   │
                                                      ┌────────────▼────────────────┐
                                                      │   /var/log/auth.log         │
                                                      │   Monitored by Splunk       │
                                                      └────────────┬────────────────┘
                                                                   │
                                                      ┌────────────▼────────────────┐
                                                      │   Splunk Indexer            │
                                                      │   index=main                │
                                                      │   sourcetype=linux_secure   │
                                                      └────────────┬────────────────┘
                                                                   │
                                                      ┌────────────▼────────────────┐
                                                      │   SPL Detection Queries     │
                                                      │   - Top Attacker IPs        │
                                                      │   - Attack Timeline         │
                                                      │   - Attack Summary          │
                                                      └────────────┬────────────────┘
                                                                   │
                                                      ┌────────────▼────────────────┐
                                                      │   Splunk Dashboard          │
                                                      │   SSH Brute Force Detection │
                                                      │   Real-time visualisation   │
                                                      └─────────────────────────────┘
```

---

## 🚨 Attack Simulation

### Step 1 — Start SSH server on Ubuntu
```bash
sudo apt install -y openssh-server
sudo systemctl start ssh
sudo systemctl enable ssh
```

### Step 2 — Run brute force from Kali
```bash
for i in {1..30}; do
  ssh fakeuser@192.168.20.20 -o StrictHostKeyChecking=no -o ConnectTimeout=3 2>/dev/null
done
```

### Step 3 — Or use the Python log generator
```bash
python3 log_generator.py --target 192.168.20.20 --count 50
```

---

## 🔍 Detection — SPL Queries

### Query 1 — Top Attacker IPs
```spl
index=main "Failed password"
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "for (invalid user )?(?P<username>\S+) from"
| stats count as Attempts by src_ip username
| sort -Attempts
```

### Query 2 — Attack Timeline
```spl
index=main "Failed password"
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| timechart count as Failed_Logins
```

### Query 3 — Attack Summary
```spl
index=main "Failed password"
| stats count as Total_Attacks,
        dc(src_ip) as Unique_IPs,
        dc(username) as Unique_Usernames
```

### Query 4 — Targeted Usernames
```spl
index=main "Failed password"
| rex field=_raw "invalid user (?P<username>\w+)"
| stats count by username
| sort -count
```

### Query 5 — Recent Failed Logins (Last 15 min)
```spl
index=main "Failed password" earliest=-15m
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time src_ip _raw
| sort -_time
```

---

## 📊 Dashboards Built

| Dashboard | Description |
|-----------|-------------|
| Top Attacker IPs | Table showing attacker IP, targeted username, and attempt count |
| Attack Timeline | Line chart showing failed login spikes over time |
| Attack Summary | Single-row stats: total attacks, unique IPs, unique usernames |

---

## 🔍 Findings

| Indicator              | Value                              |
|-----------------------|------------------------------------|
| Attack type           | SSH Brute Force (T1110.001)        |
| Attacker IP           | 192.168.20.11 (Kali Linux)         |
| Target IP             | 192.168.20.20 (Ubuntu Server)      |
| Targeted username     | fakeuser                           |
| Total failed attempts | 61                                 |
| Attack duration       | < 60 seconds                       |
| Detection time        | Real-time via Splunk               |
| MITRE ATT&CK          | T1110 – Brute Force                |

---

## 📸 Screenshots

### 🔴 Live Attack Detection in Splunk
> Splunk detecting 61 failed SSH login attempts from attacker IP in real time.

<img width="1947" height="97" alt="top_attacker_ips" src="https://github.com/user-attachments/assets/541616a7-510e-4311-9e65-a0e5fa7de686" />

---

### 📈 Attack Timeline — Spike Visualisation
> The sharp spike on the timeline shows the exact moment the brute force attack occurred.

<img width="1937" height="285" alt="attack_timeline" src="https://github.com/user-attachments/assets/7f2737c4-fb42-43b1-9d21-6949507d69c4" />

---

### 📊 Full Dashboard Overview
> Complete SSH Brute Force Detection dashboard with all panels.

<img width="2035" height="832" alt="Splunk Dashboard" src="https://github.com/user-attachments/assets/add3d928-8b42-47d5-b516-ef1294268b52" />

---

### 🖥️ Raw Auth Log Evidence
> Failed password entries in /var/log/auth.log confirming the attack source.

<img width="815" height="370" alt="auth_log_evidence" src="https://github.com/user-attachments/assets/0dfe5aba-153f-41a6-9ade-e50d89663f75" />

---

## ⚙️ Splunk Setup

### Install Splunk on Ubuntu
```bash
# Download
wget -O splunk.deb "https://download.splunk.com/products/splunk/releases/10.2.1/linux/splunk-10.2.1-linux-amd64.deb"

# Install
sudo dpkg -i splunk.deb

# Start with admin password
sudo /opt/splunk/bin/splunk start --accept-license --answer-yes \
  --no-prompt --seed-passwd Admin1234! --run-as-root

# Enable on boot
sudo /opt/splunk/bin/splunk enable boot-start --run-as-root
```

### Configure Log Monitoring
```bash
# Monitor SSH auth log
sudo /opt/splunk/bin/splunk add monitor /var/log/auth.log \
  -index main -sourcetype linux_secure --run-as-root

# Monitor syslog
sudo /opt/splunk/bin/splunk add monitor /var/log/syslog \
  -index main -sourcetype syslog --run-as-root
```

### Access Splunk Web UI
```
URL:      http://127.0.0.1:8000
Username: admin
Password: Admin1234!
```

---

## 🛡️ Mitigation & Hardening

| Action | Command |
|--------|---------|
| Ban attacker IP | `sudo fail2ban-client set sshd banip 192.168.20.11` |
| Disable password auth | `PasswordAuthentication no` in sshd_config |
| Use key-based auth | `ssh-keygen && ssh-copy-id user@host` |
| Change SSH port | `Port 2222` in sshd_config |
| Set login attempt limit | `MaxAuthTries 3` in sshd_config |
| Enable Fail2Ban | `sudo systemctl enable fail2ban` |

---

## 🧠 Lessons Learned

1. **SIEM ingestion lag** — Splunk picks up log changes within seconds but requires correct sourcetype configuration to parse fields properly.
2. **Field extraction in SPL** — Splunk's automatic field extraction doesn't always work for custom log formats; manual `rex` commands are essential for accurate detection.
3. **Attack bursts are obvious** — A brute force attack creates an unmistakable spike on a timeline chart. In a real SOC, this would trigger an immediate alert.
4. **Network segmentation matters** — The two-VM setup mirrors real enterprise architecture (attacker outside, SIEM inside). Getting the VMs to communicate required correct VirtualBox network adapter configuration.
5. **Splunk Free License limits** — The free version indexes up to 500MB/day which is more than sufficient for lab work and personal portfolio projects.

---

## 🔗 References

- [MITRE ATT&CK T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Splunk SPL Documentation](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [Splunk Enterprise Download](https://www.splunk.com/en_us/download/splunk-enterprise.html)
- [OpenSSH Security Guide](https://www.ssh.com/academy/ssh/sshd_config)

---

## 📂 Project Structure

```
Splunk-SIEM-Threat-Detection/
├── README.md                        # This file
├── log_generator.py                 # Python attack log simulator
├── splunk_queries/
│   ├── top_attacker_ips.spl         # Query 1 — Attacker IP detection
│   ├── attack_timeline.spl          # Query 2 — Timeline visualisation
│   ├── attack_summary.spl           # Query 3 — Summary stats
│   ├── targeted_usernames.spl       # Query 4 — Username analysis
│   └── recent_failed_logins.spl     # Query 5 — Real-time monitoring
└── screenshots/
    ├── top_attacker_ips.png
    ├── attack_timeline.png
    ├── full_dashboard.png
    └── auth_log_evidence.png
```

---

*Built as part of a cybersecurity portfolio. All simulations performed in an isolated VirtualBox lab environment on machines I own and control.*
