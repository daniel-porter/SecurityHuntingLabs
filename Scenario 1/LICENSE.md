
---

## **3. `security-hunt-lab.md` (Detailed Lab Documentation)**
```markdown
# Security Hunting Lab: Incident Response & Threat Detection

## **1. Lab Objective**
This lab is designed to **identify and analyze brute-force attacks** on exposed virtual machines.

## **2. MITRE ATT&CK Mapping**
| Tactic | Technique | Sub-technique |
|--------|----------|--------------|
| **Reconnaissance (TA0043)** | Gather Victim Network Information (T1590) | IP Addresses (T1590.005) |
| **Credential Access (TA0006)** | Brute Force (T1110) | Password Guessing (T1110.001) |
| **Defense Evasion (TA0005)** | Valid Accounts (T1078) | - |
| **Persistence (TA0003)** | No specific persistence observed | - |

## **3. Investigation Scope**
- **Target:** `windows-target-1`
- **Timeframe:** **Last 30 days**
- **Key Focus Areas:**
  - Identifying **publicly exposed VMs**.
  - Detecting **brute-force login attempts**.
  - Analyzing **failed vs. successful logins**.
  - Checking for **anomalous logins**.

## **4. Incident Findings**
### **1. Windows-target-1 was exposed to the internet**
```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
