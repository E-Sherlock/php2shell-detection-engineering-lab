# 🛡️ PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — Detection Engineering & Triage Suite

> **Production-grade detection rules (Sigma & Wazuh XML) and forensic triage playbooks to detect pre-authentication RCE and post-exploitation behavior targeting core PHP engines.**

---

## 📌 Executive Summary

**PHP2Shell** consists of two critical memory-safety vulnerabilities in the core PHP engine ([CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618) and [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)). Because these flaws trigger during PHP's internal request parsing and out-of-memory (OOM) fatal-error handling (`longjmp()`), pre-authentication RCE occurs **before application-level security code ever executes**.

While patch management is the primary remediation, network and endpoint detection engines must capture the immediate post-exploitation phase: **web worker daemons spawning interactive shells or persistence mechanisms.**

This repository provides an enterprise detection engineering pipeline mapping adversary TTPs to **MITRE ATT&CK** with zero-day detection capabilities using vendor-agnostic **Sigma** rules and native **Wazuh XML decoders/rules**.

---

## 🏗️ Technical Architecture & Telemetry Pipeline

```text
[ Attacker Payload ] 
       │
       ▼
[ Web Daemon (php-fpm / apache2 / nginx) ]
       │ ──► Triggers OOM Memory Corruption / Stale Memory State
       ▼
[ Pre-Auth RCE ] ──► Spawns Shell Binary (/bin/bash, /bin/sh, python3)
       │
       ▼
[ Linux Auditd / Sysmon for Linux ] ──► Captures Process Execution (EXECVE)
       │
       ▼
[ Wazuh Manager / SIEM Pipeline ] ──► Custom Decoders & Rules ──► 🚨 LEVEL 12 ALERT