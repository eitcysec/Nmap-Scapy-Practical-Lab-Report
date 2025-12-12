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
<img width="681" height="412" alt="Screenshot 2025-12-11 194347" src="https://github.com/user-attachments/assets/3af108c7-7125-4606-9f89-d6cb2b48f036" />

<img width="856" height="226" alt="Screenshot 2025-12-11 194408" src="https://github.com/user-attachments/assets/05ddb741-0396-495a-a638-f127a8b56b4e" />



------------------------------------------------------------------------

## 3. Port/Service/Version Scan + OS + Scripts

    nmap -p21 -sV -A -T4 10.10.10.17

**Purpose:** Checks port 21, identifies service version, OS info,
traceroute, and runs default scripts.

<img width="925" height="414" alt="Screenshot 2025-12-11 194628" src="https://github.com/user-attachments/assets/95aa6ef5-5ea3-4eab-ac22-45d856f14398" />


------------------------------------------------------------------------

## 4. SMB Port Scan

    nmap -A p139, p445 10.10.10.17

    <img width="919" height="426" alt="Screenshot 2025-12-11 194807" src="https://github.com/user-attachments/assets/b3ffd65d-91e1-4afb-94a7-f9554c64f39e" />

<img width="925" height="414" alt="Screenshot 2025-12-11 194628" src="https://github.com/user-attachments/assets/72be7920-6f43-4bd4-a249-ed0d97da55d5" />


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

    <img width="797" height="426" alt="Screenshot 2025-12-11 195708" src="https://github.com/user-attachments/assets/156f7fd4-81bb-47fb-839b-d819a56797ac" />

    ip route

    <img width="844" height="371" alt="Screenshot 2025-12-11 200005" src="https://github.com/user-attachments/assets/ca71a577-ca52-4303-a05f-89a2db2055ae" />

    cat /etc/resolv.conf

    <img width="703" height="336" alt="Screenshot 2025-12-11 200057" src="https://github.com/user-attachments/assets/86f5d4a0-d21d-49f4-82c9-1ae864194df5" />


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

