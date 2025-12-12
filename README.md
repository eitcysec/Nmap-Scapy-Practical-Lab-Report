# Nmap-Scapy-Practical-Lab-Report
This report documents the reproduction of all Nmap and Scapy exercises from the ParoSecurity practical class.

# Nmap & Scapy Practical Lab Report

## Objective

This report documents the reproduction of all Nmap and Scapy exercises
from the ParoSecurity practical class.

## Environment Setup

-   **Kali Linux VM**
-   **Network Range:** 10.10.10.0/24
-   **Target Machine:** 10.10.10.17; 10.10.10.10
-   **Tools:** Nmap, Scapy, tcpdump, Wireshark

------------------------------------------------------------------------

# NMAP LAB

## 1. Host Discovery Scan

    nmap -sn 10.10.10.0/24

**Purpose:** Identifies live hosts on the network.
<img width="675" height="419" alt="Screenshot 2025-12-11 194156" src="https://github.com/user-attachments/assets/2c358310-ed18-4fd3-a8db-0fc48d77776a" />


------------------------------------------------------------------------

## 2. OS Detection Scan

    sudo nmap -O 10.10.10.17

**Purpose:** Fingerprints the operating system of the target.

------------------------------------------------------------------------

## 3. Port/Service/Version Scan + OS + Scripts

    nmap -p21 -sV -A -T4 10.10.10.17

**Purpose:** Checks port 21, identifies service version, OS info,
traceroute, and runs default scripts.

------------------------------------------------------------------------

## 4. SMB Port Scan

    nmap -A p139, p445 10.10.10.17

------------------------------------------------------------------------

## 5. SMB Share Enumeration

    nmap --script smb-enum-shares.nse -p445 10.10.10.10

------------------------------------------------------------------------

## 6. Access SMB Share

    smbclient //10.10.10.10/print$ -N

Type **exit** to leave the SMB shell.

------------------------------------------------------------------------

# NETWORK BASELINE COMMANDS

    ifconfig
    ip route
    cat /etc/resolv.conf

------------------------------------------------------------------------

# PACKET CAPTURE (tcpdump + Wireshark)

### Start Capture

    sudo tcpdump -i eth0 -s 0 -w ladies.pcap

Stop with: **CTRL + C**

### Verify capture file

    ls ladies.pcap
    wireshark

------------------------------------------------------------------------

# SCAPY LAB

    sudo su
    scapy

## 1. Sniff All Traffic

    sniff()

Open a new terminal and run:

    ping google.com

Stop sniffing with **CTRL + C**

    paro = _
    paro.summary()

------------------------------------------------------------------------

## 2. Sniff Traffic on Interface

    sniff(iface="br-internal")

Generate traffic by opening a browser and visiting:

    10.10.10.17

Stop, then:

    paro2 = _
    paro2.summary()

------------------------------------------------------------------------

## 3. Capture Specific Traffic (ICMP)

    sniff(iface="br-internal", filter="icmp", count=5)

In another terminal:

    ping 10.10.10.17

Stop, then:

    paro3 = _
    paro3.summary()
    paro3[3]

------------------------------------------------------------------------

# Notes

Add screenshots of your terminal output and Wireshark captures inside
your repository.

