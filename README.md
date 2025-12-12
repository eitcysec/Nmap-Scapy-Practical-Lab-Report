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

<img width="709" height="419" alt="image" src="https://github.com/user-attachments/assets/408a2bbc-ea1e-4e63-a0e0-5169269c5da8" />


    ip route
<img width="812" height="398" alt="image" src="https://github.com/user-attachments/assets/a2314ba0-b855-4d08-8257-1cc40d6078e2" />


    cat /etc/resolv.conf

<img width="809" height="370" alt="image" src="https://github.com/user-attachments/assets/4313b71f-7a0e-4d7e-bbb2-6c3938ae2291" />



------------------------------------------------------------------------

# PACKET CAPTURE (tcpdump + Wireshark)

### Start Capture

    sudo tcpdump -i eth0 -s 0 -w ladies.pcap

<img width="602" height="317" alt="image" src="https://github.com/user-attachments/assets/e55b9d5f-85fd-49bd-b527-8ffd6ff7e515" />


Stop with: **CTRL + C**

<img width="575" height="338" alt="image" src="https://github.com/user-attachments/assets/601475cc-a6d1-4264-aff6-a13d7e256557" />


### Verify capture file

    ls ladies.pcap
    <img width="431" height="274" alt="image" src="https://github.com/user-attachments/assets/edd40f8b-d543-476c-9517-02cf7d30cb6a" />

    wireshark
<img width="875" height="404" alt="image" src="https://github.com/user-attachments/assets/91391fa0-4353-41b2-88b0-b83e902ccd21" />


------------------------------------------------------------------------

# SCAPY LAB

    sudo su
    scapy

<img width="859" height="401" alt="image" src="https://github.com/user-attachments/assets/682e7f7f-cc53-4ecf-ab6e-beb9de191078" />


## 1. Sniff All Traffic

    sniff()

Open a new terminal and run:

    ping google.com

<img width="949" height="379" alt="image" src="https://github.com/user-attachments/assets/d17114d4-9dec-4a9a-9893-3d7d5f020107" />

Stop sniffing with **CTRL + C**

    paro = _
    paro.summary()


<img width="954" height="401" alt="image" src="https://github.com/user-attachments/assets/cf566bd6-5a72-4136-87bc-1f7db27246e1" />

------------------------------------------------------------------------

## 2. Sniff Traffic on Interface

    sniff(iface="br-internal")

Generate traffic by opening a browser and visiting:

    www.cisco.com

Stop, then:

    paro2 = _
    paro2.summary()

<img width="797" height="414" alt="image" src="https://github.com/user-attachments/assets/e7162445-2ed9-4a2b-bfa1-e7533b45146a" />


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


