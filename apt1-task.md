# APT1-Task
* Beschreibung von vier (4) Aufgaben mit der Datei `apt1.pcapng`

## Task 1: Anonymize C&C username and password
* There is tls (encrypted) traffic in tls.pcap
* The private key to open the encrypted file is available `tls.pem`
* please anonymize the user and the password in the C&C communication

```
getCommand=true&user=WxTrFk&pass=secure&serial=wxpUID33125523% 
```

![DNS](./DNS.png)

## Task 2: Anonymize DNS Tunnel
* There is a dns tunnel running in the pcap
* the domain is set to <random>.dtt.csnc.ch
* please replace dtt.csnc.ch with dtt.example.com

![DNS](./DNS.png)


## Task 3: Anonymize Windows Protocol 
* there is some Windows (SMB) Protocol in the pcap
* the Windows Domain is set to `hacking-lab.com`  and several other `*.vdi.hacking-lab.com `domains
* please anonymize Windows Domain in pcap
* replace Windows Domain with `windowsdomain.com`

![SMB](./SMB-DC-Packages.png)


## Task 4: Replace IP Addresses
* we want to hide the real ip in our pcap
* please replace the prefix of the ip with something else
* 192.168.201 should go to 10.0.201
* 192.168.200 should go to 10.0.200

![STAT](./STAT.png)

