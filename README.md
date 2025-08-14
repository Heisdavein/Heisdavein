**ABOUT ME**


I’m **Clinton Kehinde**  an aspiring SOC Analyst with a strong foundation in cybersecurity and a relentless passion for self-learning. I hold the ISC² Certified in Cybersecurity (CC) credential and have completed the Cisco Networking Academy Junior Cybersecurity Analyst learning path.

My focus areas include threat detection, incident response, vulnerability assessment, and SIEM monitoring, all honed through a dedicated home lab where I replicate and respond to real-world attack scenarios.

Every project I take on is both a skill-building exercise and a practical demonstration of my commitment to the craft. I approach security operations with precision, curiosity, and the drive to stay ahead of emerging threats. For me, cybersecurity isn’t just a profession in progress ,it’s a passion I live out daily.



**Quick stats**

  **Role:** Aspiring SOC Analyst / Incident Responder
  
  **Learning path:** ISC2 Certified in cybersecurity Certification,Cisco Networking Academy(Junior Soc Analyst path) self-directed labs, Self Learning
  
  **Focus areas:** SIEM monitoring, threat detection, IR playbooks, vulnerability assessment
  
  **Tools I use:** Elastic Stack (Elasticsearch, Logstash, Kibana), Wazuh, Suricata, Zeek, Splunk (trial), Windows/Linux endpoints, Metasploit, Nmap, OpenVAS, Burp Suite, Python
  
  Lab:** Home lab with virtualized Windows and Linux hosts, a dedicated SIEM node, and simulated attacker host(s)



 Repository layout

```
/ (root)
│ README.md                      <- This file
├── lab-setup/                    <- Scripts & guides to reproduce my home lab
│   ├── terraform/                <- (optional) infra as code snippets
│   ├── docker-compose.yml        <- quick local deployment
│   └── notes.md                  <- hardware & VM specs
├── siem/                         <- SIEM configurations & dashboards
│   ├── elastic/                  <- Elasticsearch ingest pipelines + Kibana dashboards
│   ├── wazuh/                    <- Wazuh rules & decoders
│   └── splunk/                   <- sample searches & saved searches (if applicable)
├── detection-rules/              <- YARA, Suricata, Sigma rules, Zeek scripts
├── incident-response/            <- IR playbooks & evidence collection scripts
├── vuln-assessments/             <- Scan reports, writeups, remediation notes
├── scripts/                      <- Python & Bash scripts used in projects
├── demos/                        <- Recorded demos, README for each demo
└── docs/                         <- Helpful references, templates, CV, cover letter
```

-

Projects (highlighted)

 1) **SIEM Monitoring** — Home ELK Stack (Elastic + Wazuh)

Goal: Centralize logs, parse Windows/Linux logs, detect suspicious behaviors, and visualize alerts.

What I built:

 Dockerized Elastic Stack (Elasticsearch, Logstash, Kibana) and Wazuh manager for endpoint telemetry.
 Ingest pipelines for Windows event logs and Linux syslog; Wazuh decoders + rules customized for lab environment.
 Kibana dashboards for authentication anomalies, process execution, network connections, and high-risk alerts.
 Example detections implemented as Sigma rules and converted to Elasticsearch queries.

What to review: `siem/elastic/` and `siem/wazuh/` directories for config, pipelines, dashboards, and rule examples.



 2) **Threat Detection** — Network + Host-based Detections

Goal: Implement layered detection sensors to catch post-exploitation and lateral movement.

 Sensors used: Suricata (IDS), Zeek (network visibility), Wazuh (endpoint detection), and custom log parsers.

 Example detections included:

 Suricata rule to detect suspicious SMB traffic and potential data exfil.
 Zeek script to flag uncommon DNS over HTTP patterns and suspicious domain generation algorithm (DGA)-like behavior.
 Wazuh rule for unusual PowerShell invocation with encoded commands.

Files: `detection-rules/` contains the rules and brief test notes.



 3) **Incident Response Playbooks & Runbooks**

Goal: Document repeatable steps for triage, containment, eradication, and recovery for common incidents.

Included playbooks:

 Host compromise (Windows) — collection commands (artifact list), triage checklist, containment steps.
 Phishing suspected — triage emails, user guidance, IOC extraction, and escalation steps.
 Ransomware suspected — isolation guidelines, forensic snapshot steps, and communication checklist.

Automation: `incident-response/scripts/collect_artifacts.py` (Python) to gather basic host artifacts (process list, network connections, event logs) for triage. Always run from an isolated forensic host.



 4) **Vulnerability Assessment & Remediation**

Goal: Scan lab hosts, interpret results, and document remediation steps.

Tools & outputs:** Nmap for discovery, OpenVAS/Greenbone for full vulnerability scans, and Burp Suite for web app checks.

 Example reports with prioritized CVEs, recommended patches, and mitigation steps live in `vuln-assessments/`.



 Examples & snippets (short)

 Sample Sigma rule (Windows PowerShell suspicious)

```yaml
title: Suspicious PowerShell EncodedCommand
id: 12345678-90ab-cdef-1234-567890abcdef
status: experimental
description: Detects PowerShell use of -EncodedCommand which is commonly used by attackers to run obfuscated payloads.
logsource:
  product: windows
  service: powershell
detection:
  selection:
    CommandLine|contains: '-EncodedCommand'
  condition: selection
level: high
```

 Sample Suricata rule (suspicious SMB transfer)

```
alert tcp any any -> any 445 (msg:"SMB potential exfil over SMB"; flow:to_server,established; content:"\xFFSMB"; sid:1000001; rev:1;)
```

 Quick Python artifact collection (excerpt)

```python
# incident-response/scripts/collect_artifacts.py (excerpt)
import subprocess, json

def run(cmd):
    return subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')

artifacts = {
    'pslist': run('powershell -Command "Get-Process | ConvertTo-Json"'),
    'netstat': run('netstat -ano'),
}
print(json.dumps(artifacts)[:1000])
```

> Full scripts are in `/incident-response/scripts/` with safer I/O handling and output packaging.



 How I test detections (reproducible steps)

1. Spin up two lab VMs: `attacker` (Kali/Ubuntu) and `victim` (Windows 10/Windows Server).
2. Generate benign baseline activity for 24 hours (normal user behavior, scheduled tasks, web browsing).
3. Run simulated threat actions using `metasploit`, `powershell` one-liners, and custom scripts to trigger rules.
4. Validate alerts appear in Kibana/Wazuh and iterate on rules to tune false positives.



Skills & tools (practical level)

Log Analysis: Windows Event Logs, syslog, JSON logs in ELK, Splunk SPL basics
  Network Monitoring:** Suricata, Zeek, Wireshark
  Endpoint Monitoring:** Wazuh, OSQuery, Sysmon configurations
  Vulnerability Scanning:** Nmap, OpenVAS, Nessus (trial), Burp Suite
  Scripting & Automation:** Python (requests, pandas, argparse), Bash, PowerShell
  Forensics & IR: FTK Imager (conceptually), Volatility (memory analysis basics), artifact collection



 How to use this repo

1. Read `lab-setup/notes.md` to reproduce my home lab environment.
2. Browse `siem/` for dashboards and pipelines. Import the Kibana objects into your Kibana to visualize.
3. Review `detection-rules/` to see sample rules and unit test notes.
4. Try the incident-response scripts in an isolated safe environment.


 Career documents

I keep a concise CV and a role-specific cover letter in `docs/` that highlights SOC entry-level skills, projects I completed, and links to demo videos.



Contact & collaboration

 Email:Clintonolorunfemikehinde@gmail.com
 
 LinkedIn:https://www.linkedin.com/in/clinton-kehinde-9a5789316?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app


 Notes & ethics

All scripts and playbooks were developed for defensive research in my home lab. Do not run attack or exploitation code against systems you do not own or have explicit permission to test.



 Next steps I’m working on

 Convert Sigma detections into Splunk and Wazuh-compatible rules automatically.
 Improve OSQuery-based endpoint telemetry and integrate into my SIEM for richer host context.
 Document a multi-day purple-team exercise and publish a write-up.


