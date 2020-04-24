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


### Task 1: Anonymize C&C username and password

Todo

### Task 2: Replace IP Addresses

### Task 3: Anonymize SMPT

### Task 4: PCAP in between START and END

