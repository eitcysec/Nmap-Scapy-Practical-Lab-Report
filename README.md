# Nmap-Scapy-Practical-Lab-Report
This report documents the reproduction of all Nmap and Scapy exercises from the ParoSecurity practical class.

# Nmap & Scapy Practical Lab Report

## Objective

This report documents the reproduction of all Nmap and Scapy exercises
from the ParoSecurity practical class.

## Environment Setup

-   **Kali Linux VM**
-   **Network Range:** 10.6.6.0/24
-   **Target Machine:** 10.6.6.23
-   **Tools:** Nmap, Scapy, tcpdump, Wireshark

------------------------------------------------------------------------

# NMAP LAB

## 1. Host Discovery Scan

    nmap -sn 10.6.6.0/24

**Purpose:** Identifies live hosts on the network.

<img width="437" height="275" alt="image" src="https://github.com/user-attachments/assets/9fd5aabb-4bda-4646-beb2-b73921300158" />




------------------------------------------------------------------------

## 2. OS Detection Scan

    sudo nmap -O 10.6.6.23

**Purpose:** Fingerprints the operating system of the target.

<img width="465" height="299" alt="image" src="https://github.com/user-attachments/assets/d6722da9-b24a-43ce-a688-a81bd3593743" />




------------------------------------------------------------------------

## 3. Port/Service/Version Scan + OS + Scripts

    nmap -p21 -sV -A -T4 10.6.6.23

**Purpose:** Checks port 21, identifies service version, OS info,
traceroute, and runs default scripts.


<img width="602" height="404" alt="image" src="https://github.com/user-attachments/assets/da4186e4-1c9b-46ba-a0f2-129754bc18d4" />


------------------------------------------------------------------------

## 4. SMB Port Scan

    nmap -A p139, p445 10.6.6.23

<img width="599" height="409" alt="image" src="https://github.com/user-attachments/assets/523cc53e-b510-45af-8681-adde77cb5b9b" />




------------------------------------------------------------------------

## 5. SMB Share Enumeration

    nmap --script smb-enum-shares.nse -p445 10.6.6.23

<img width="684" height="362" alt="image" src="https://github.com/user-attachments/assets/8f0481a1-db90-467a-a7b2-041aba435566" />

    

------------------------------------------------------------------------

## 6. Access SMB Share

    smbclient //10.6.6.23/print$

<img width="679" height="239" alt="image" src="https://github.com/user-attachments/assets/ddb81f22-dc76-4331-b85c-9df6ee21861b" />


Type **exit** to leave the SMB shell.

------------------------------------------------------------------------

# NETWORK BASELINE COMMANDS

    ifconfig

<img width="565" height="407" alt="image" src="https://github.com/user-attachments/assets/cfcf2c25-ed6b-4c14-9791-ba27592c4d95" />


    ip route

<img width="607" height="239" alt="image" src="https://github.com/user-attachments/assets/562f866c-a62a-4c1a-a147-1bbd2f1f98a8" />




    cat /etc/resolv.conf


<img width="477" height="289" alt="image" src="https://github.com/user-attachments/assets/a15ed2c0-84a5-4b85-9cb1-605eaeabdc18" />



------------------------------------------------------------------------

# PACKET CAPTURE (tcpdump + Wireshark)

### Start Capture

    sudo tcpdump -i eth0 -s 0 -w ladies.pcap
    
<img width="513" height="246" alt="image" src="https://github.com/user-attachments/assets/22bfe5c2-7786-42ce-b4d3-c2380bf1a1cd" />



Stop with: **CTRL + C**



### Verify capture file

    ls ladies.pcap

<img width="389" height="212" alt="image" src="https://github.com/user-attachments/assets/5ea4b92c-58df-44cb-ac69-fe2ad09ac2a6" />


    wireshark

<img width="671" height="443" alt="image" src="https://github.com/user-attachments/assets/b3b60b9e-1a02-4253-9e27-cff8910d7a9d" />

------------------------------------------------------------------------

# SCAPY LAB

    sudo su
    scapy

<img width="413" height="407" alt="image" src="https://github.com/user-attachments/assets/262dc816-2ae4-4ac6-bd60-13ea9b785784" />


## 1. Sniff All Traffic

    sniff()

Open a new terminal and run:

    ping google.com


<img width="826" height="436" alt="image" src="https://github.com/user-attachments/assets/c54ab6ff-b350-4e2d-9efe-f94ebe9e6af0" />



Stop sniffing with **CTRL + C**

    paro = _
    paro.summary()


<img width="769" height="393" alt="image" src="https://github.com/user-attachments/assets/ec2f5329-4f5d-4002-9c21-39fed80b7be9" />

------------------------------------------------------------------------

## 2. Sniff Traffic on Interface

    sniff(iface="br-internal")

Generate traffic by opening a browser and visiting:

    www.cisco.com

<img width="836" height="441" alt="image" src="https://github.com/user-attachments/assets/07a8a50e-fb6f-4a8b-9eeb-825e976a9b2b" />


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


