# Introduction
This python3 exercise is about anonymizing a pcap file. 

## Learn how to ...
 - work with pcap files
 - anonymize packets in the pcap file 
 - remove packets in the pcap file

## Preparation

### Step 1: Download Pcap-files
Please download the two Pcap-files from `RESOURCES` to /home/hacker/Downloads

### Step 2
Please run the following commands (e.g. Hacking-Lab LiveCD) and set up your python3 environment.

```
mkdir -p /opt/git
cd /opt/git
git clone https://github.com/ibuetler/p3s-pcap-anonymize-and-remove.git
cd /opt/git/p3s-pcap-anonymize-and-remove
pipenv --python 3 sync
pipenv --python 3 shell
```

## Tasks for tls.pcap

Two pcap files are given for this tutorial. We will first start with the file tls.pcap.

### Theory about Scapy

Scapy is a library used for interacting with the packets on the network. It has several functionalities through which it is possible to forge and manipulate the packet. Through scapy module it would be also possible to create network tools like ARP Spoofer, Network Scanner, packet dumpers etc. For these tasks only the packet manipulating aspects are needed.

To get all network packets of our file, the function rdpcap("path") from Scapy can be used. This function takes the path of the file and returns all packets as a scapy list.

``` python

import scapy.all as scapy

packets = scapy.rdpcap('../tls.pcap')

```

This now offers the possibility to iterate over the list with a for-loop and inspect each packet individually.

```python
import scapy.all as scapy

packets = scapy.rdpcap('../tls.pcap')

for packet in packets:
# do something
```
To view the structure of a packet on the console, this cannot be done classically with the print() function on the console. If the print function is used, the packet will only be shown as a sequence of hexadecimal numbers on the console. But a Scapy Packet offers a show() function. This function allows a packet to be output as a readable and structured string. For example, the first packet can be output as follows:

```python
import scapy.all as scapy

packets = scapy.rdpcap('../tls.pcap')

packets[0].show()
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

This allows us to see exactly the properties of the packet. For each layer, the attributes can be seen and also how they can be accessed. If someone wants to access the MAC address of the receiver, this can be done in these two options:

```python
import scapy.all as scapy

packets = scapy.rdpcap('../tls.pcap')

packets[0]["Ethernet"].dst

packets[0][0].dst
```

The output of the packages in readable format can be very useful for future tasks if someone wants to see exactly how the properties of the packages are mapped in Scapy. 

### Task 1: Replace IP Addresses

In this task the real IP address of the packets shall be anonymized. The prefixes of the IP addresses are to be replaced as follows:

* 192.168.100 should go to 10.0.100
* 192.168.200 should go to 10.0.200
* 80.254.178 should go to 11.0.178

In Wireshark the starting position of the file looks as follows:

![IP2](/media/challenge/png/Tls_intial_state.png)

The result should look like this:

![IP2](/media/challenge/png/Tls_IP_result.png)

To achieve this result, it is necessary to be able to access the destination address and origin address for each packet. With Scapy this can be achieved as follows: 

```python
import scapy.all as scapy
packets = scapy.rdpcap('../tls.pcap')

for pck in packets:
   ip_src = pck[1].src
   ip_dst = pck[1].dst
```
With the [1] indexing the IP layer will be accessed of the packet. Another other possible way to acces the IP layer would be ["Ip"] istead of [1].

However, there is something else to consider and that is that not every packet has an IP address. If a packet is accessed without an IP address, an attribute error is thrown. This can be caught as follows:

```python
import scapy.all as scapy
packets = scapy.rdpcap('../tls.pcap')

for pck in packets:
    try:
       ip_src = pck[1].src
       ip_dst = pck[1].dst
    except AttributeError:
       continue
```
The last thing needed to solve this task is how to overwrite an IP address and how to overwrite the PCAP file. The IP can be overwritten with the assignment operator for each packet. To overwrite the file Scapy offers a function called wrpcap("path", list of packets). The first parameter is the path where the file should be created. If a path of an existing file is provided, the file will be overwritten. The second parameter is the list of packets the file should contain. In our example this would look like this:

```python
import scapy.all as scapy
packets = scapy.rdpcap('../tls.pcap')

for pck in packets:
    try:
       ip_src = pck[1].src
       ip_dst = pck[1].dst
       new_ip = '10.0.100.0'
       pck[1].src = new_ip
       pck[1].dst = new_ip
     except AttributeError:
       continue
       
scapy.wrpcap('../tls.pcap', packets)
```
**Task:** Now iterate over all packets in the tls.pcap file and overwrite all IP addresses prefixes as defined at the beginning.

### Task 2: Anonymize SMPT

In this Task the real sender and recipient of the e-mail communication with the SMPT protocol should be anonymized. The sender and recipient should be made anonymous as follows:

* sender goes to: ```sender@myserver.com```
* recipient goes to: ```recipient@remoteserver.com```

At the beginning the tls.pcap looks like this for smtp entries:

![smtp_start](/media/challenge/png/smtp_start.png)

After the task it should like this:

![smtp_result](/media/challenge/png/smtp_result.png)

Unfortunately the smtp protocol is not directly mapped in Scapy.  For example, if the package with the number 248 is printed to the console, the following structure appears:

```
###[ Ethernet ]### 
  dst       = 00:0c:29:c0:6d:3d
  src       = 00:0d:60:8a:cf:03
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 93
     id        = 1400
     flags     = DF
     frag      = 0
     ttl       = 128
     proto     = tcp
     chksum    = 0x68e4
     src       = 192.168.200.44
     dst       = 80.254.178.107
     \options   \
###[ TCP ]### 
        sport     = hpvmmcontrol
        dport     = smtp
        seq       = 3857969882
        ack       = 2467352891
        dataofs   = 5
        reserved  = 0
        flags     = PA
        window    = 63905
        chksum    = 0x2db6
        urgptr    = 0
        options   = []
###[ Raw ]### 
           load      = 'MAIL FROM:<johann.katrizi@glocken-emil.ch> SIZE=473\r\n'
```
To check whether a packet has used an smtp protocol, the standard ports of smtp must be checked. A packet sent through the smtp protocol will have used one of the following ports: 25,465,587,2525

To access the port of a packet in Scapy, index with ["TCP"] and access the dport attribute. This example shows how the packets are checked to see if they used the smtp protocol:

```python
import scapy.all as scapy
packets = scapy.rdpcap('../tls.pcap')

for p in packets:
    try:
        if p["TCP"].dport == 25 or p["TCP"].dport == 465 or p["TCP"].dport == 587 or p["TCP"].dport == 2525:
        #do something
    except (AttributeError, IndexError) as e:
        continue
```
Since not every packet in the file has a TCP port, two exceptions can occur. An IndexError if indexing with ["TCP"] is not possible and an AttributeError if the dport attribute is not present. 

The sender and receiver of a packet is in the payload of the packet. This can be accessed on TCP level with the .load attribute. Note that this is returned as byte type. The load must therefore be converted into a string in order to execute operations on it. The following example shows this:

```python
import scapy.all as scapy
packets = scapy.rdpcap('../tls.pcap')

for p in packets:
    try:
        if p["TCP"].dport == 25 or p["TCP"].dport == 465 or p["TCP"].dport == 587 or p["TCP"].dport == 2525:
            tcp_load = str(p["TCP"].load)
    except (AttributeError, IndexError) as e:
        continue
```
It is best to first output the load to the console to see how it is structured. In our file a packet containing the sender starts with "MAIL FROM: <...> and a packet containing the receiver with "RCPT TO:<...>. A packet can also be structured in IMF format. In a payload in IMF format, the recipient and sender are contained in one packet. For example, the packet with the number 257 is in IMF format. These begin with "from: ..." where the sender follows and contain the substring "TO:.." where the receiver follows.

To solve this task, you can for example, after checking whether the port has been used, make three checks whether the respective strings are contained in the payload. Then replace sender and receiver as defined at the beginning. 


### Task 3: PCAP in between START and END

In this task, the goal is to remove all packets from the file between a specific start and end date. The following dates should be used as start and end dates:

```python
start = '2011-11-10 12:43:04'
end = '2011-11-10 12:43:48'
```

To solve this the dates need to be made comparable. This can be done by converting the String into a date object. Python offers the time library for this. In this library there is a function called strptime(string, format) which takes a string and a format to parse the string as a date object. Illustrated by this code:

```python
import time

start = '2011-11-10 12:43:04'
end = '2011-11-10 12:43:48'

start_time_object = time.strptime(start,'%Y-%m-%d %H:%M:%S')
end_time_object = time.strptime(end,'%Y-%m-%d %H:%M:%S')

```

For further information here is a documentation for the time library: https://docs.python.org/3/library/time.html. In short the format for parsing the String takes certain directives which start with a % character. For Example %Y stands for year.

A possible way to solve the task is to create a new list and iterate over the packets and if there is one between the dates it will be put into the list. If you use Scapy to access the date of a packet, it is given in seconds from January 1, 1970, 00:00:00 at UTC. This can be converted with the time library in a date format. The library provides a function called localtime which converts the seconds in a date. Illustrated by this code:

```python
import scapy.all as scapy

packets = scapy.rdpcap('../tls.pcap')

for p in packets:
    local_time = time.localtime(int(p.time))

```

**Task:** Reduce the tls.pcap file to all packets which are between the two dates at the beginning.

## Tasks for apt1.pcapng

For the next few tasks the file apt1.pcapng will be used.

### Task1: Anonymize MAC Address

In this task the goal is to anonymize all occurrences of the MAC address 00:50:56:bd:78:d4. The MAC should be changed from 00:50:56:bd:78:d4 to 00:40:32:00:00:a0.

At the beginning, an entry of the MAC address for example looks like this in Wireshark:

![MAC_start](/media/challenge/png/MAC_beginning.png)

And here the result after anonymizing the MAC Address:

![MAC_result](/media/challenge/png/MAC_result.png)

This task can be solved again with Scapy. First the file is read with the rdpcap function. The MAC address can either occure as the source or destination address. To access the Ethernet layer and obtain the MAC address, the following procedure can be used (Here the first packet is accessed):

```python
import scapy.all as scapy

packets = scapy.rdpcap('../apt1.pcapng')
src_MAC = packet[0]['Ethernet'].src
dst_MAC = packet[0]['Ethernet'].dst
```

**Task:** Iterate over all packets and check if the source or destination MAC Address matches the MAC from above. If so, change it like stated above. 


### Task 2: Anonymize DNS Tunnel

There are several DNS packets in this file, each resolving the .dtt.csnc.ch domain. In this task the goal is to anonymize these domains. All dtt.csnc.ch should be replaced to dtt.example.com.

At the beginning an entry for the apt1.pcapng looks like this:

![DNS_start](/media/challenge/png/DNS_start.png)

After the task the dns should be anonymized like this:

![DNS_solution](/media/challenge/png/DNS_Solution.png)

First, we will have a look at the structure of a DNS packet in Scapy. For example, packet number eight is a DNS packet. If we output this to the console, the following structure will be shown:

```python
###[ Ethernet ]### 
  dst       = 00:0c:29:fa:8b:6e
  src       = 00:50:56:bd:78:d4
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 68
     id        = 48832
     flags     = 
     frag      = 0
     ttl       = 128
     proto     = udp
     chksum    = 0x67f6
     src       = 192.168.201.140
     dst       = 192.168.201.20
     \options   \
###[ UDP ]### 
        sport     = 26317
        dport     = domain
        len       = 48
        chksum    = 0x8ac5
###[ DNS ]### 
           id        = 259
           qr        = 0
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 0
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 0
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]### 
            |  qname     = 'akoegmcjm0.dtt.csnc.ch.'
            |  qtype     = TXT
            |  qclass    = IN
           an        = None
           ns        = None
           ar        = None

```
As you can see above, our searched domain is in the attribute qname and this should be changed. However, it is possible that a DNS packet has not only a DNS Question Record but also a DNS Resource Record. For example, packet number nine has a Resource Record. In Scapy the packet looks as follows:


```python
###[ Ethernet ]### 
  dst       = 00:50:56:bd:78:d4
  src       = 00:0c:29:fa:8b:6e
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 83
     id        = 16876
     flags     = 
     frag      = 0
     ttl       = 128
     proto     = udp
     chksum    = 0xe4bb
     src       = 192.168.201.20
     dst       = 192.168.201.140
     \options   \
###[ UDP ]### 
        sport     = domain
        dport     = 26317
        len       = 63
        chksum    = 0x17a4
###[ DNS ]### 
           id        = 259
           qr        = 1
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 1
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 1
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]### 
            |  qname     = 'akoegmcjm0.dtt.csnc.ch.'
            |  qtype     = TXT
            |  qclass    = IN
           \an        \
            |###[ DNS Resource Record ]### 
            |  rrname    = 'akoegmcjm0.dtt.csnc.ch.'
            |  type      = TXT
            |  rclass    = IN
            |  ttl       = 0
            |  rdlen     = None
            |  rdata     = [b'a0']
           ns        = None
           ar        = None

```

For our task we need to change the qname of the DNS Question Record and if there is a DNS Resource Record in the packet the rrname must be changed as well.


At first we want to iterate over all packets and check if they have a DNS layer. For this, the layer must be specially imported from Scapy with "from scapy.layers.dns import DNS". Afterwards it is possible to call the hasLayer function on a Scapy packet. Here is an example of how to check each packet if it used the DNS layer:

```python
import scapy.all as scapy
from scapy.layers.dns import DNS

packets = scapy.rdpcap('../apt1.pcapng')
for packet in packets:
    if packet.haslayer(DNS):
      #do something
```
Next, we would like to access the two attributes we are looking for. Each DNS packet has a DNS Question Record and this can be easily indexed with ["DNS Question Record"]. Afterwards, we can access the attribute qname. But since not every packet has a DNS resource record, it must be accessed with a try and catch block, because if the resource record is not present, an IndexError is thrown. Here is an example where the two attributes are accesed:

```python
import scapy.all as scapy
from scapy.layers.dns import DNS

packets = scapy.rdpcap('../apt1.pcapng')
for packet in packets:
    if packet.haslayer(DNS):
       qname = packet["DNS"]["DNS Question Record"].qname
    try:
       rrname = new_packet["DNS"]["DNS Resource Record"].rrname
    except (IndexError, AttributeError):
       continue
```
Now one could assume that the qname can simply be overwritten with an assignment like this:

```python
packet["DNS"]["DNS Question Record"].qname = "new.domain.com"
```

If someone would do this for every packet, it will be shown as "Malformed DNS Packet" in Wireshark. To work around this problem, the cheksum (TCP and IP), the IP length field and the UDP length field must be recalculated for each packet a record is DNS Record is changed. 

These three fields can be recalculated as follows. First they will be deleted from the respective package and then the __class__ method will be called. The deleted fields are automatically recalculated by this method. Here is an example that illustrates this:

```python
import scapy.all as scapy
from scapy.layers.dns import DNS

packets = scapy.rdpcap('../apt1.pcapng')
del packet[0]['UDP'].chksum
del packet[0]['IP'].chksum
del packet[0]['IP'].len
del packet[0]['UDP'].len
packet[0].__class__(bytes(packet[0]))
```
There is another obstacle to bypass Wireshark's malformed DNS packet message: the old packet has to be deleted and the new one inserted at this point. Here is an example how the packet number 8 is anonymized:

```python
import scapy.all as scapy
from scapy.layers.dns import DNS

new_DNS = 'dtt.example.com'

packets = scapy.rdpcap('../apt1.pcapng')
new_packet = packet[7]
initial_time = packet[7].time
del new_packet['UDP'].chksum
del new_packet['IP'].len
del new_packet['UDP'].len
packet_prefix = str(new_packet["DNS"]["DNS Question Record"].qname).partition('dtt')[0]
new_packet["DNS"]["DNS Question Record"].qname = bytes((packet_prefix + new_DNS).encode())
new_packet = new_packet.__class__(bytes(new_packet))
new_packet.time = initial_time
 
packets.pop(7)
packets.insert(7, new_packet)

```

In the above code the following has been done: First the cheksum, IP length and UDP length from the new packet is deleted. Then the prefix is extracted from the domain and assembled with our desired domain.The domain is now anonymized as desired at the beginning of the task. In the initial_time variable is the time of the beginning packet assigned. Otherwise, the packet would have the current time when it is recreated. Afterwards, the element at position 7 is deleted with the pop function and our new packet is inserted with the insert function.

You can now proceed as follows: You iterate over all packages and create a variable that always remembers the current index. If the packet has a DNS layer, a new packet is created and anonymized. Afterwards this packet is stored in a dictionary with the index of the original packet as key and the new packet as value. At the end you iterate over the dictionary and delete the packet at this index of the intial list of packets and insert the new packet.

**Task anonymize all DNS packet as stated at the beginning**

### Task 3: Anonymize Windows Protocol

In the apt1.pcapng is some Windows (SMB) Protocol. The Windows Domain is set to hacking-lab.com and the goal of this task is to anonymize every occurence of this domain. The hacking-lab.com domain should be set to windowsdomain.com.

For example the packet with the number 11960 has an occurence of this domain:

![smb_start](/media/challenge/png/smb_start.png)

Our goal now is to change the AttributeValue shown in the image to windowsdomain.com. Unfortunately this cannot be solved nicely with Scapy. Currently, Scapy does not yet offer support for the LDAP protocol. That means there is no way for us to load the LDAP protocol with the load_layer function of Scapy. But the domain can still be made anonymous.

If the packet with the number 11960 is output on the console with the Show() function, the following picture results:

```
###[ Ethernet ]### 
  dst       = 00:50:56:bd:78:d4
  src       = 00:0c:29:fa:8b:6e
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 991
     id        = 28601
     flags     = DF
     frag      = 0
     ttl       = 128
     proto     = tcp
     chksum    = 0x736d
     src       = 192.168.201.20
     dst       = 192.168.201.140
     \options   \
###[ TCP ]### 
        sport     = ldap
        dport     = 15478
        seq       = 2502885695
        ack       = 449137945
        dataofs   = 5
        reserved  = 0
        flags     = PA
        window    = 64240
        chksum    = 0xa008
        urgptr    = 0
        options   = []
###[ Raw ]### 
           load      = '.840.113556.1.4.1341\x04\x171.2.840.113556.1.4.2026\x04\x171.2.840.113556.1.4.2064\x04\x171.2.840.113556.1.4.2065\x04\x171.2.840.113556.1.4.20660\x84\x00\x00\x00"\x04\x14supportedLDAPVersion1\x84\x00\x00\x00\x06\x04\x013\x04\x0120\x84\x00\x00\x01\x0f\x04\x15supportedLDAPPolicies1\x84\x00\x00\x00\xf2\x04\x0eMaxPoolThreads\x04\x0fMaxDatagramRecv\x04\x10MaxReceiveBuffer\x04\x0fInitRecvTimeout\x04\x0eMaxConnections\x04\x0fMaxConnIdleTime\x04\x0bMaxPageSize\x04\x10MaxQueryDuration\x04\x10MaxTempTableSize\x04\x10MaxResultSetSize\x04\rMinResultSets\x04\x14MaxResultSetsPerConn\x04\x16MaxNotificationPerConn\x04\x0bMaxValRange0\x84\x00\x00\x00I\x04\x17supportedSASLMechanisms1\x84\x00\x00\x00*\x04\x06GSSAPI\x04\nGSS-SPNEGO\x04\x08EXTERNAL\x04\nDIGEST-MD50\x84\x00\x00\x00-\x04\x0bdnsHostName1\x84\x00\x00\x00\x1a\x04\x18hlad.vdi.hacking-lab.com0\x84\x00\x00\x00F\x04\x0fldapServiceName1\x84\x00\x00\x00/\x04-vdi.hacking-lab.com:hlad$@VDI.HACKING-LAB.COM0\x84\x00\x00\x00x\x04\nserverName1\x84\x00\x00\x00f\x04dCN=HLAD,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=vdi,DC=hacking-lab,DC=com0\x84\x00\x00\x00\x99\x04\x15supportedCapabilities1\x84\x00\x00\x00|\x04\x161.2.840.113556.1.4.800\x04\x171.2.840.113556.1.4.1670\x04\x171.2.840.113556.1.4.1791\x04\x171.2.840.113556.1.4.1935\x04\x171.2.840.113556.1.4.20800\x84\x00\x00\x00\x11\x02\x02\x0f\x91e\x84\x00\x00\x00\x07\n\x01\x00\x04\x00\x04\x00'

```

As you can see, our desired data can still be read out in the Load. Our goal is to parse this byte format into a string and replace all occurrences of hacking-lab with windowsdomain. The load of the packet can be accessed and parsed in a string as follows:

```python
import scapy.all as scapy
packets = scapy.rdpcap('../apt1.pcapng')
load = packets[11960]['Raw'].load
str_load = str(load)
```
Now, the replace member function of the string class can be used. This Function takes two strings as parameters and replaces every occurence of the first string with the second string.

In the load of the packet, the hacking-lab domain can occur in lower case or upper case. Here is an example of how to replace the hacking-lab domain in the load above:

```python
packets = scapy.rdpcap('../apt1.pcapng')
load = packets[11960]['Raw'].load
str_load = str(load)
str_load = str_load.replace('hacking-lab', 'windowsdomain')
str_load = str_load.replace('HACKING-LAB', 'WINDOWSDOMAIN')
```

If the new load now just would be assigned as follow:

```python
packets[11960]['Raw'].load = str_load
```

The same problem as in the DNS tunnel task would occur. In Wireshark, the packet would be marked as malformed. To work around this problem, the IP checksum, the TCP checksum and the IP length must be recalculated. 

```python
packets = scapy.rdpcap('../apt1.pcapng')
new_packet = packets[11960]
time_initial = new_packet.time
load = new_packet['Raw'].load
str_load = str(load)
str_load = str_load.replace('hacking-lab', 'windowsdomain')
str_load = str_load.replace('HACKING-LAB', 'WINDOWSDOMAIN')
del new_packet['IP'].chksum
del new_packet['TCP'].chksum
del new_packet['IP'].len
new_packet['Raw'].load = str_load
new_packet = new_packet.__class__(bytes(new_packet))
new_packet.time = time_initial

```

In the above code, as with the DNS tunnel task, the fields were first deleted and then a new packet was created with the __class__ function. This ensures that the fields will be recalculated. Additionally the timestamp must be cached at the beginning, otherwise the current time would be inserted.

Now everything needs to be automated. For this we iterate over all packets and check if the LDAP Protocol was used. This can be done by checking if the port 389 was used in the TCP source or destination port. This code illustrates this:

```python
import scapy.all as scapy
from scapy.layers.inet import TCP

packets = scapy.rdpcap('../apt1.pcapng')
for packet in packets:
   if packet.haslayer(TCP):
        if packet["TCP"].dport == 389 or packet["TCP"].sport == 389:
            try:
             new_packet = packet
             time_initial = packet.time
             load = new_packet['Raw'].load
             str_load = str(load)
             if 'hacking-lab' in str_load or 'HACKING-LAB' in str_load:
              #more code
             except IndexError:
                continue
```

In the above code the IndexError must be catched because not every LDAP packet has a ['Raw'] field. 

Like in the previous task with the DNS Tunnel, every packet that will be altered has to be deleted from the initial list and inserted again. It is recommended to create a dictionary again with the position of the packet as key and the new packet as value. Afterwards you can iterate over the dictionary and delete the packages with the pop function and insert the new one with the insert function.

**Task** Iterate over the packets and replace for every packet that has an occurence of the hackinglab domain in the LDAP Protocol, the domain with windowsdomain.

### Task 4: Replace IP Addresses

In this task the real IP address of the packets shall be anonymized. Like in the Task for the tls.pcap file.The prefixes of the IP addresses are to be replaced as follows:

* 192.168.201 should go to 10.0.201
* 192.168.200 should go to 10.0.200

This task can be solved with the same procedure as from the task for the tls.pcap file. 
