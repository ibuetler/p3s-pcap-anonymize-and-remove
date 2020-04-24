# Introduction
This python3 exercise is about anonymizing a pcap file. 

## Learn how to ...
 - work with pcap files
 - anonymize packages in the pcap file 
 - remove packages in the pcap file

## Tasks for tls.pcap

Two pcap files are given for this tutorial. We will first start with the file tls.pcap.

### Theory about Scapy

Scapy is library used for interacting with the packets on the network. It has several functionalities through which it is possible to forge and manipulate the packet. Through scapy module it would be also possible to create network tools like ARP Spoofer, Network Scanner, packet dumpers etc. For this tasks only the packet manipulating aspects are needed.

To get all network packets of our file, the function rdpcap("path") from Scapy can be used. This function takes the path of the file and returns all packets as a scapy list.

``` python

import scapy.all as scapy

packets = scapy.rdpcap('../tls.pcap')

```

This now offers the possibility to iterate over the list with a for-loop and inspect each packet individually.

```python
for packet in packets:
# do something
```
To view the structure of a packet on the console, this cannot be done classically with the print() function on the console. If the print function is used, the packet will only be showed as a sequence of hexadecimal numbers on the console. But a Scapy Packet offers a show() function. This function allows a packet to be output as a readable and structured string. For example, the first packet can be output as follows:

```python
print(packets[0].show())
```

This will result in the following picture on the console:

```
###[ Ethernet ]### 
  dst       = 00:50:56:bd:78:d4
  src       = 00:00:00:00:00:00
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 6
     tos       = 0x0
     len       = 36
     id        = 0
     flags     = 
     frag      = 0
     ttl       = 1
     proto     = igmp
     chksum    = 0x3ad3
     src       = 10.0.0.0
     dst       = 224.0.0.1
     \options   \
      |###[ IP Option Router Alert ]### 
      |  copy_flag = 1
      |  optclass  = control
      |  option    = router_alert
      |  length    = 4
      |  alert     = router_shall_examine_packet
###[ Raw ]### 
        load      = '\x11\x01\xeb\xfe\x00\x00\x00\x00\x03\x00\x00\x00'
###[ Padding ]### 
           load      = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

```

This allows to see exactly the properties of the packet. For each layer, the attributes can be seen and also how they can be accessed. If someone wants to access the MAC address of the receiver, this can be done in these two options:

```python
packets[0]["Ethernet"].dst

packets[0][0].dst
```

The output of the packages in readable format can be very useful for future tasks, if someone wants to see exactly how the properties of the packages are mapped in Scapy. 

### Task 1: Anonymize C&C username and password

Todo

### Task 2: Replace IP Addresses

In this task the real IP address of the packets shall be anonymized. The prefixes of the IP addresses are to be replaced as follows:

* 192.168.100 should go to 10.0.100
* 192.168.200 should go to 10.0.200
* 80.254.178 should go to 11.0.178

In Wireshark the starting position of the file looks as follows:

![IP2](/media/challenge/png/Tls_initial_state.png)

The result should look like this:

### Task 3: Anonymize SMPT

### Task 4: PCAP in between START and END

