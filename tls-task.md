# TLS-Task
* Beschreibung von vier (3) Aufgaben mit der Datei `tls.pcap`

## Task 1: Replace IP Addresses
* we want to hide the real ip in our pcap
* please replace the prefix of the ip with something else
* 192.168.100 should go to 10.0.100
* 192.168.200 should go to 10.0.200
* 80.254.178 should go to 11.0.178


![IP2](/media/challenge/png/IP2.png)


## Task 2: Anonymize SMPT
* we want to hide the real seander and recipient of the e-mail communication
* please replace the sender and recipient
* sender goes to: `sender@myserver.com` 
* recipient goes to: `recipient@remoteserver.com`

![SMTP](/media/challenge/png/SMTP.png)


## Task 3: PCAP in between START and END
* limit pcap to certain `start` and `end`
* start = `2011-11-10 12:43:04`
* end = `2011-11-10 12:43:48`


