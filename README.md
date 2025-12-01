🛡️ HTB Writeups + SOC Analyst Perspective

This repository contains my Hack The Box (HTB) machine walkthroughs written with a dual approach:

Offensive perspective – how I exploited the machine step-by-step

Defensive (SOC Analyst) perspective – how the same attack would look in a real environment, how to detect it, respond to it, and prevent it.

Each writeup includes:

🔹 1. Attack Narrative

A clear, structured walkthrough: enumeration, exploitation, privilege escalation, post-exploitation, and final flags.

🔹 2. Incident Story (SOC Style)

A real-world style incident summary explaining:

What happened (attack chain)

How it happened (initial access → execution → persistence → exfiltration, if any)

Which MITRE ATT&CK techniques were used

What logs and artifacts a SOC team would observe

Possible Indicators of Compromise (IOCs)

🔹 3. Detection Engineering

Detailed notes on:

Relevant Windows / Linux event logs

Sigma rule ideas

Sysmon log mappings

Wazuh detection paths

Alerts expected at each stage

Endpoint and network telemetry to monitor

🔹 4. DFIR Analysis

Where applicable, each writeup includes DFIR artifacts such as:

Prefetch

Shimcache / Amcache

Registry hives (USRCLASS.DAT, NTUSER.DAT, SYSTEM, SOFTWARE, SAM)

Browser forensics

Jump Lists, LNK files

SRUM, Event Logs, $MFT, $J, and Shellbags

🔹 5. Prevention & Hardening

Practical and vendor-agnostic steps for preventing and mitigating the attack, including:

Hardening

Network segmentation

Endpoint protection

AD security

Logging configurations

Recommended monitoring queries
