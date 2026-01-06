# Forensic Analysis of a Simulated Enterprise Compromise Using Splunk and BOTS v3

**Module Code:** COMP5002  
**Module Title:** Security Operations & Incident Management  
**Assessment:** Coursework 2 – Incident Analysis  
**Academic Year:** 2025/26

---

## Abstract

This coursework analyses a simulated enterprise breach using Splunk Enterprise and the BOTS v3 dataset, documenting the investigative process from initial detection through to containment recommendations. The investigation follows a structured incident response approach aligned with established frameworks such as NIST SP 800-61, focusing on the identification, analysis, and reconstruction of a multi-stage cyberattack across cloud, Windows, and Linux environments.

Through Splunk queries and log correlation, I traced the attack from OneDrive file delivery through phishing email delivery, malware execution, account creation, and reconnaissance activity. Endpoint telemetry from Sysmon and Osquery was leveraged to identify malware execution, credential exposure, unauthorised user creation, privilege escalation, and persistence mechanisms on compromised systems.

The findings demonstrate how effective log correlation enables Security Operations Centre (SOC) analysts to reconstruct complex attacks and assess their impact. The report highlights key security gaps, including weaknesses in email security controls, credential handling, and account monitoring, and concludes with practical recommendations to improve detection, response, and overall organisational resilience against similar threats.

---

## Table of Contents

- [Section 1: Introduction](#section-1-introduction)
  - [1.1 SOC Context and Background](#11-soc-context-and-background)
  - [1.2 Objectives of the Investigation](#12-objectives-of-the-investigation)
  - [1.3 Scope and Assumptions](#13-scope-and-assumptions)
- [Section 2: SOC Roles & Incident Handling Reflection](#section-2-soc-roles--incident-handling-reflection)
- [Section 3: Environment Setup and Methodology](#section-3-environment-setup-and-methodology)
- [Section 4: Log Sources and Detection Mechanisms](#section-4-log-sources-and-detection-mechanisms)
- [Section 5: Attack Analysis and Timeline Reconstruction](#section-5-attack-analysis-and-timeline-reconstruction)
- [Section 6: Recovery Actions, Business Impact & Lessons Learned](#section-6-recovery-actions-business-impact--lessons-learned)
- [References](#references)

---

## Section 1: Introduction

### 1.1 SOC Context and Background

Security Operations Centres (SOCs) teams continuously monitor enterprise systems and cloud platforms for signs of compromise. In hybrid environments, this requires correlating logs from diverse sources to detect multi-stage attacks. With the increasing complexity of hybrid infrastructures and the rise of sophisticated cyber threats, SOC analysts must be capable of correlating diverse log sources to detect, investigate, and respond to security incidents in a timely and structured manner.

The Boss of the SOC version 3 (BOTSv3) dataset, developed by Splunk, simulates a realistic multi-stage cyber intrusion within a fictitious organisation named Frothly, a brewing company operating both on-premises and cloud-based infrastructure. The dataset contains a wide range of log sources, including email traffic, endpoint telemetry, authentication logs, and cloud service activity from platforms such as Microsoft Office 365 and Linux hosts.

This assessment uses BOTSv3 as a practical case study to emulate the responsibilities of a SOC analyst conducting an end-to-end incident investigation using Splunk Enterprise and Search Processing Language (SPL).

### 1.2 Objectives of the Investigation

The primary objective of this investigation is to analyse email-related and endpoint-related security events within the BOTSv3 dataset in order to:

- Identify the initial attack vector used to compromise Frothly's environment
- Trace attacker activity across cloud services, Windows endpoints, and Linux systems
- Detect evidence of malware execution, privilege escalation, persistence mechanisms, and reconnaissance
- Demonstrate the use of Splunk SPL queries to support forensic findings
- Reflect on SOC practices, detection capabilities, and incident handling strategies

The investigation follows a structured, evidence-based approach consistent with industry SOC workflows and the cyber kill chain methodology [1].

### 1.3 Scope and Assumptions

#### Scope

This analysis focuses on:

- Email-based threats, including malicious attachments and macro-enabled documents
- Cloud activity related to Microsoft OneDrive file uploads
- Endpoint activity on both Windows and Linux systems, including process execution, user creation, and network behaviour
- Relevant log sources indexed within the botsv3 index in Splunk

The investigation is limited to the 300-level guided questions provided as part of the coursework and does not attempt to exhaustively analyse all data contained within the BOTSv3 dataset.

#### Assumptions

The following assumptions apply:

- All logs within the BOTSv3 dataset are complete, accurate, and time-synchronised
- Alerts and events observed reflect attacker activity rather than system misconfiguration
- The Frothly environment represents a typical small-to-medium enterprise SOC deployment

---

## Section 2: SOC Roles & Incident Handling Reflection

### 2.1 SOC Tier Responsibilities

A typical SOC operates using a tiered model, where responsibilities are distributed across different analyst levels:

- **Tier 1 (SOC Analyst – Monitoring & Triage)**: Responsible for monitoring alerts, validating suspicious activity, and escalating confirmed incidents
- **Tier 2 (Incident Responder)**: Conducts deeper investigation, correlates logs across multiple sources, and identifies root cause and attack progression
- **Tier 3 (Threat Hunter / SOC Engineer)**: Focuses on advanced analysis, detection engineering, threat intelligence enrichment, and long-term defensive improvements

Within the BOTSv3 exercise, the analyst effectively assumes responsibilities spanning Tier 1 and Tier 2, including alert triage, forensic analysis, and incident reconstruction using Splunk.

### 2.2 Incident Handling Lifecycle in BOTSv3

My investigation approach maps to the NIST SP 800-61 incident response lifecycle, moving through detection, analysis, containment planning, and lessons learned [2]. Although BOTSv3 is a simulated environment, the events observed can be clearly mapped to the key stages of the incident response lifecycle.

#### Prevention

The prevention phase is not directly implemented within the BOTSv3 scenario, as the dataset focuses on post-incident investigation rather than proactive controls. However, several weaknesses are evident from the logs analysed, including the successful delivery of a macro-enabled malicious email attachment and the ability for attackers to create privileged user accounts without immediate detection.

#### Detection

Detection is achieved primarily through log analysis within Splunk. Multiple data sources contribute to identifying suspicious activity, including:

- Email security logs that flag malicious macro-enabled attachments
- Endpoint telemetry from Sysmon and Osquery
- Windows Security Event Logs showing unauthorised user account creation

#### Response

Response activities include identifying compromised endpoints, tracing attacker movement across systems, investigating suspicious processes, and correlating evidence from multiple log sources to confirm malicious behaviour.

#### Recovery

While BOTSv3 does not simulate remediation directly, potential recovery actions include removing malicious user accounts, resetting compromised credentials, and strengthening detection rules.

### 2.3 Reflection on SOC Effectiveness

Analysis of the BOTSv3 scenario showed that effective SOC operations depend heavily on access to diverse, well-integrated log sources spanning email, endpoint, and authentication systems. The exercise reinforces the need for strong email security controls, continuous monitoring of privileged account creation, and behaviour-based detection mechanisms.

---

## Section 3: Environment Setup and Methodology

### 3.1 Lab Environment Overview

The investigation was conducted on an Ubuntu Linux virtual machine running on VMware [3]. A local installation of Splunk Enterprise was used to replicate a realistic SOC investigation environment.

![VMware running Ubuntu](images/figure-01-vmware-ubuntu.png)
*Figure 1: VMware running Ubuntu*

### 3.2 Splunk Enterprise Installation on Ubuntu

Splunk Enterprise was installed using the official Linux installation package [4].

![Terminal Download Command](images/figure-02-terminal-download.png)
*Figure 2: Terminal showing download command*

The Splunk web interface was accessed via localhost on port 8000:

![Splunk on Port 8000](images/figure-03-splunk-port-8000.png)
*Figure 3: Splunk running on port 8000*

![Splunk Dashboard](images/figure-04-splunk-dashboard.png)
*Figure 4: Splunk Dashboard*

### 3.3 Loading and Verifying the BOTSv3 Dataset

The BOTSv3 dataset [5] was downloaded from GitHub and loaded into Splunk:

![BOTSv3 Download](images/figure-05-botsv3-github.png)
*Figure 5: BOTSv3 dataset download from GitHub*

The total number of indexed events reached **2,083,056**, confirming successful data ingestion:

![BOTSv3 Interface](images/figure-06-splunk-botsv3-interface.png)
*Figure 6: Splunk web interface showing BOTSv3 dataset*

---

## Section 4: Log Sources and Detection Mechanisms Used in the Investigation

### 4.1 Office 365 and OneDrive Activity Logging

Microsoft Office 365 generates detailed audit logs for user actions across its services. Within Splunk, Office 365 audit data is indexed using the sourcetype: `ms:o365:management`

Relevant fields include:
- `Workload` – identifies the Office 365 service
- `Operation` – describes the action performed
- `UserAgent` – identifies the client software
- `src_ip` – source IP address
- `object` – the file or resource involved

### 4.2 SMTP Email Traffic and Malicious Attachment Detection

Email traffic is captured using Splunk Stream under sourcetype: `stream:smtp`

SMTP logs contain:
- Email subject and sender information
- Attachment metadata
- Malware alert indicators
- Encoded attachment content

### 4.3 Sysmon Endpoint Telemetry (Windows Hosts)

Sysmon [6] provides enhanced visibility into endpoint activity. Data is indexed under: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

Key event types include:
- Process creation events (EventCode 1)
- Hash values (MD5, SHA1, SHA256)
- Command-line arguments
- Parent-child process relationships

### 4.4 Linux Authentication and Command Execution Logging

Osquery [7] provides structured telemetry for Linux systems, capturing:
- User creation and privilege changes
- Executed commands
- Processes listening on suspicious ports

### 4.5 Importance of Log Correlation

Knowledge of logging capabilities helped me validate evidence reliability, spot visibility gaps, and confidently link observed events to attacker actions rather than misconfigurations.

---

## Section 5: Attack Analysis and Timeline Reconstruction

### 5.1 Initial Access: Malicious File Delivery via OneDrive

The attack began with the upload of a malicious .lnk file to Microsoft OneDrive.

**Splunk Query:**
```spl
index=botsv3 sourcetype=ms:o365:management Workload=OneDrive Operation=FileUploaded
| rename UserId AS user ClientIP AS src_ip SourceFileName AS object
| table _time UserAgent user src_ip Operation object
| sort + _time
```

![OneDrive Upload Event](images/figure-07-onedrive-upload.png)
*Figure 7: OneDrive file upload event with suspicious user agent*

The suspicious user agent indicated use of a non-standard Linux browser, suggesting attacker-controlled infrastructure.

### 5.2 Payload Delivery: Phishing Email with Macro-Enabled Attachment

Email telemetry under `stream:smtp` revealed delivery of a malicious Excel file.

**Splunk Query:**
```spl
index=botsv3 sourcetype=stream:smtp *alert*
```

![SMTP Security Alerts](images/figure-08-smtp-alerts.png)
*Figure 8: Filtered SMTP events containing security alerts*

Base64-decoded content revealed:
- **Original Filename:** `Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm`
- **Malware Family:** W97M.Empstage

### 5.3 Execution: Embedded Malware and Process Launch

Sysmon logs showed macro execution triggered the malicious payload.

**Splunk Query:**
```spl
index=botsv3 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational *xlsm*
| sort by +_time
```

**Executed File:** `HxTsr.exe`

At this stage, the victim likely enabled macros, triggering execution of the embedded payload.

### 5.4 Linux Persistence: User Creation and Credential Discovery

Osquery logs revealed creation of a privileged Linux user.

**Splunk Query:**
```spl
index=botsv3 host=hoth (adduser OR useradd) sourcetype="osquery:results"
```

**Created User:** `tomcat7`  
**Password (plaintext):** `ilovedavidverve`  
**Privileges:** UID 0 (root)

The Osquery logs captured the password in plaintext due to poor attacker OPSEC.

### 5.5 Privilege Escalation and Persistence: User Creation (Windows)

Windows Security logs showed creation of an administrative account.

**Splunk Query:**
```spl
index=botsv3 source=wineventlog:security EventCode=4720
```

**Created User:** `svcvnc`  
**Groups Added:** Users, Administrators

### 5.6 Internal Reconnaissance: Group Membership

**Splunk Query:**
```spl
index=botsv3 sourcetype=wineventlog:security svcvnc EventCode=4732
```

The `svcvnc` account was added to the Administrators group, granting full system control.

### 5.7 Internal Reconnaissance: "Leet" Port Activity

I searched Osquery logs for processes bound to port 1337 (a "leet" port commonly used by attackers).

**Splunk Query:**
```spl
index=botsv3 1337 sourcetype=*osquery:results* "columns.port"=1337
```

**Process ID:** 14356  
**Timestamp:** Mon Aug 20 11:55:34 2018

### 5.8 Malicious File Hash Identification

Sysmon logs revealed execution of a network scanning tool.

**File:** `hdoor.exe`  
**MD5 Hash:** `586EF56F4D8963DD546163AC31C865D7`

### 5.9 Attack Timeline Reconstruction

| Stage | Description |
|-------|-------------|
| Initial Access | Malicious link uploaded to OneDrive |
| Delivery | Phishing email with macro-enabled Excel attachment |
| Execution | Embedded malware executed on endpoint |
| Persistence | Privileged user accounts created (Windows & Linux) |
| Reconnaissance | Network scanning and backdoor activity observed |

---

## Section 6: Recovery Actions, Business Impact & Lessons Learned

### 6.1 Recovery and Containment Actions

Following detection, containment should begin immediately:
- Isolate compromised hosts from the network
- Remove unauthorized accounts (`svcvnc`, `tomcat7`)
- Reset compromised credentials
- Block malicious hashes across security controls
- Tighten Office macro execution policies

### 6.2 Business and Operational Impact

Had this incident not been detected, potential impacts include:
- Data breaches and unauthorized access
- Service disruption
- Reputational damage
- Regulatory compliance issues

### 6.3 Lessons Learned and Security Improvements

Key improvements include:
- Enforcing least-privilege policies
- Expanding endpoint monitoring coverage (Sysmon, Osquery)
- Strengthening macro and application execution controls
- Training staff to recognize phishing attempts

---

## References

1. Hutchins, E. M., Cloppert, M. J., & Amin, R. M. (2011). *Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains*. Lockheed Martin Corporation.

2. Cichonski, P., Millar, T., Grance, T., & Scarfone, K. (2012). *Computer Security Incident Handling Guide*. NIST Special Publication 800-61 Rev. 2.

3. VMware. (2024). *VMware Workstation Pro Documentation*.

4. Splunk Inc. (2024). *Splunk Enterprise Documentation*. https://docs.splunk.com/Documentation

5. Splunk Inc. (2018). *Boss of the SOC Version 3 (BOTS v3) Dataset*. GitHub Repository. https://github.com/splunk/botsv3

6. Microsoft. (2024). *Sysmon - System Monitor*. Microsoft Sysinternals Documentation.

7. Kolide. (2024). *Osquery Documentation: About Osquery*.

---

## SPL Queries Used

All Splunk queries used in this investigation are available in the [`queries/`](queries/) directory.

---

## Author

**Student Name:** Onyebuchi Godrick Okonkwo  
**Module:** COMP5002 - Security Operations & Incident Management  
**Academic Year:** 2025/26

---

## License

This project is submitted as coursework for academic assessment.
