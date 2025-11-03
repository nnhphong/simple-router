# Test cases run

## Test case 1
**Description**: The router must successfully route packets between the Internet and the application servers.

**How to**: From client, we will use command ```wget``` to get the default content of the server
```sh
mininet> client wget 192.168.2.2
--2025-11-03 03:40:58--  http://192.168.2.2/
Connecting to 192.168.2.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 161 [text/html]
Saving to: 'index.html.3'

index.html.3        100%[===================>]     161  --.-KB/s    in 0s      

2025-11-03 03:40:59 (14.1 MB/s) - 'index.html.3' saved [161/161]

mininet> client cat index.html.3
<html>
<head><title> This is Server1 </title></head>
<body>
Congratulations! <br/>
Your router successfully route your packets to server1. <br/>
</body>
</html>
mininet> 
mininet> client wget 172.64.3.10
--2025-11-03 03:41:46--  http://172.64.3.10/
Connecting to 172.64.3.10:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 161 [text/html]
Saving to: 'index.html.4'

index.html.4        100%[===================>]     161  --.-KB/s    in 0s      

2025-11-03 03:41:47 (10.0 MB/s) - 'index.html.4' saved [161/161]

mininet> wget cat index.html.4
*** Unknown command: wget cat index.html.4
mininet> client cat index.html.4
<html>
<head><title> This is Server2 </title></head>
<body>
Congratulations! <br/>
Your router successfully route your packets to server2. <br/>
</body>
</html>
mininet> 
```

## Test case 2
**Description**: The router must correctly handle ARP requests and replies.

**How to**: First clear the client's ARP cache, start ```tcpdump``` on the client side to capture what sent and get sent. Then ping to one of the router's interface. Now what it does is that it has to broadcast an ARP request to the router, and the router has to reply with its interface MAC address. After that, the router has to ask for the client's MAC address to send the ICMP echo back. 

```
mininet> client tcpdump -w wocao.pcap &
mininet> client arp -d 10.0.1.1
tcpdump: listening on client-eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
mininet> client ping -c 1 10.0.1.1
PING 10.0.1.1 (10.0.1.1) 56(84) bytes of data.
64 bytes from 10.0.1.1: icmp_seq=1 ttl=255 time=161 ms

--- 10.0.1.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 161.411/161.411/161.411/0.000 ms
mininet> client pkill tcpdump
6 packets captured
6 packets received by filter
0 packets dropped by kernel
mininet> client tcpdump -r wocao.pcap
reading from file wocao.pcap, link-type EN10MB (Ethernet)
04:04:00.722868 ARP, Request who-has 10.0.1.1 tell 10.0.1.100, length 28
04:04:00.773840 ARP, Reply 10.0.1.1 is-at 36:6f:c6:44:2f:8d (oui Unknown), length 28
04:04:00.773870 IP 10.0.1.100 > 10.0.1.1: ICMP echo request, id 2761, seq 1, length 64
04:04:00.818006 ARP, Request who-has 10.0.1.100 (Broadcast) tell 10.0.1.1, length 28
04:04:00.818030 ARP, Reply 10.0.1.100 is-at a2:78:12:5a:fe:05 (oui Unknown), length 28
04:04:00.884224 IP 10.0.1.1 > 10.0.1.100: ICMP echo reply, id 2761, seq 1, length 64
mininet> 
```
As the ping was able to executed sucessfully, this show that the router can be able to process ARP request/reply correctly.

## Test case 3
**Description**: The router must correctly handle traceroutes through it (where it is not the end host) and to it (where it is the end host).

**How to**: Start ```traceroute``` to different router's interfaces and different servers.
```
mininet> client traceroute 192.168.2.1
traceroute to 192.168.2.1 (192.168.2.1), 30 hops max, 60 byte packets
 1  10.0.1.1 (10.0.1.1)  41.302 ms  54.334 ms  54.371 ms
mininet> client traceroute 172.64.3.1 
traceroute to 172.64.3.1 (172.64.3.1), 30 hops max, 60 byte packets
 1  10.0.1.1 (10.0.1.1)  112.144 ms  111.574 ms  110.790 ms
mininet> client traceroute 10.0.1.1  
traceroute to 10.0.1.1 (10.0.1.1), 30 hops max, 60 byte packets
 1  10.0.1.1 (10.0.1.1)  139.469 ms  139.431 ms  139.434 ms
mininet> 
mininet> 
mininet> client traceroute 172.64.3.10
traceroute to 172.64.3.10 (172.64.3.10), 30 hops max, 60 byte packets
 1  10.0.1.1 (10.0.1.1)  47.030 ms  91.260 ms  50.083 ms
 2  * * *
 3  * * *
 4  * 172.64.3.10 (172.64.3.10)  216.110 ms  216.064 ms
mininet> client traceroute 192.168.2.2
traceroute to 192.168.2.2 (192.168.2.2), 30 hops max, 60 byte packets
 1  10.0.1.1 (10.0.1.1)  16.555 ms  19.204 ms  60.806 ms
 2  * * *
 3  * * *
 4  192.168.2.2 (192.168.2.2)  186.853 ms *  186.781 ms
```

## Test case 4
**Description**: The router must respond correctly to ICMP echo requests on any interfaces.

**How to**: ping to all interfaces
```
mininet> client ping -c 1 10.0.1.1 
PING 10.0.1.1 (10.0.1.1) 56(84) bytes of data.
64 bytes from 10.0.1.1: icmp_seq=1 ttl=255 time=41.4 ms

--- 10.0.1.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 41.444/41.444/41.444/0.000 ms
mininet> client ping -c 1 192.168.2.1
PING 192.168.2.1 (192.168.2.1) 56(84) bytes of data.
64 bytes from 192.168.2.1: icmp_seq=1 ttl=255 time=37.9 ms

--- 192.168.2.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 37.861/37.861/37.861/0.000 ms
mininet> client ping -c 1 172.64.3.1 
PING 172.64.3.1 (172.64.3.1) 56(84) bytes of data.
64 bytes from 172.64.3.1: icmp_seq=1 ttl=255 time=97.8 ms

--- 172.64.3.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 97.786/97.786/97.786/0.000 ms
mininet> 
```

## Test case 5
**Description**: The router must handle TCP/UDP packets sent to one of its interfaces. In this case the router should respond with an ICMP port unreachable.

**How to**: Start ```tcpdump``` on client side. Then send raw UDP packet by echoing to ```/dev/udp/<host>/<port>```
```sh
mininet> client tcpdump -w wocao.pcap &
mininet> client echo "hi" > /dev/udp/10.0.1.1/420
tcpdump: listening on client-eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
mininet> client pkill tcpdump
4 packets captured
4 packets received by filter
0 packets dropped by kernel
mininet> client tcpdump -r wocao.pcap
reading from file wocao.pcap, link-type EN10MB (Ethernet)
04:29:23.594439 IP 10.0.1.100.45293 > 10.0.1.1.420: UDP, length 3
04:29:23.598455 ARP, Request who-has 10.0.1.100 (Broadcast) tell 10.0.1.1, length 28
04:29:23.598475 ARP, Reply 10.0.1.100 is-at a2:78:12:5a:fe:05 (oui Unknown), length 28
04:29:23.642137 IP 10.0.1.1 > 10.0.1.100: ICMP 10.0.1.1 udp port 420 unreachable, length 36
```

Similarly we can also do that for TCP packet
```sh
mininet> client tcpdump -w wocao.pcap &
mininet> client echo "hi" > /dev/tcp/192.168.2.1/80
tcpdump: listening on client-eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
bash: connect: Connection refused
bash: /dev/tcp/192.168.2.1/80: Connection refused
mininet> client pkill tcpdump
6 packets captured
6 packets received by filter
0 packets dropped by kernel
mininet> client tcpdump -r wocao.pcap
reading from file wocao.pcap, link-type EN10MB (Ethernet)
04:38:21.212763 IP 10.0.1.100.42834 > 192.168.2.1.http: Flags [S], seq 2423483979, win 64240, options [mss 1460,sackOK,TS val 981189619 ecr 0,nop,wscale 7], length 0
04:38:21.225071 ARP, Request who-has 10.0.1.100 (Broadcast) tell 10.0.1.1, length 28
04:38:21.225100 ARP, Reply 10.0.1.100 is-at a2:78:12:5a:fe:05 (oui Unknown), length 28
04:38:21.270109 IP 10.0.1.1 > 10.0.1.100: ICMP 192.168.2.1 tcp port http unreachable, length 36
04:38:26.553815 ARP, Request who-has 10.0.1.1 tell 10.0.1.100, length 28
04:38:26.595760 ARP, Reply 10.0.1.1 is-at 36:6f:c6:44:2f:8d (oui Unknown), length 28
mininet> 
```

As the result, the router both responded with ```udp port 420 unreachable``` and ```tcp port http unreachable``` accordingly to different router interfaces.

## Test case 6
**Description**: The router must maintain an ARP cache whose entries are invalidated after a timeout period (timeouts should be on the order of 15 seconds).

**How to**: Start ```tcpdump``` on the server side to capture all ARP request/respond. From the client side ping to the server, then wait for 15s, ping again and observe the captured traffic.
```sh
mininet> server1 tcpdump -w wocao.pcap & 
mininet> client ping -c 1 192.168.2.2
PING 192.168.2.2 (192.168.2.2) 56(84) bytes of data.
64 bytes from 192.168.2.2: icmp_seq=1 ttl=63 time=219 ms

--- 192.168.2.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 219.003/219.003/219.003/0.000 ms
mininet> client ping -c 1 192.168.2.2
PING 192.168.2.2 (192.168.2.2) 56(84) bytes of data.
64 bytes from 192.168.2.2: icmp_seq=1 ttl=63 time=54.2 ms

--- 192.168.2.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 54.182/54.182/54.182/0.000 ms
mininet> client ping -c 1 192.168.2.2
PING 192.168.2.2 (192.168.2.2) 56(84) bytes of data.
64 bytes from 192.168.2.2: icmp_seq=1 ttl=63 time=204 ms

--- 192.168.2.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 203.522/203.522/203.522/0.000 ms
mininet> server1 pkill tcpdump
tcpdump: listening on server1-eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
12 packets captured
12 packets received by filter
0 packets dropped by kernel
mininet> server1 tcpdump -r wocao.pcap
reading from file wocao.pcap, link-type EN10MB (Ethernet)
04:47:03.278211 ARP, Request who-has 192.168.2.2 (Broadcast) tell 192.168.2.1, length 28
04:47:03.278245 ARP, Reply 192.168.2.2 is-at ae:15:fc:27:5b:a1 (oui Unknown), length 28
04:47:03.323014 IP 10.0.1.100 > 192.168.2.2: ICMP echo request, id 2891, seq 1, length 64
04:47:03.323073 IP 192.168.2.2 > 10.0.1.100: ICMP echo reply, id 2891, seq 1, length 64
04:47:08.792849 ARP, Request who-has 192.168.2.1 tell 192.168.2.2, length 28
04:47:08.802201 ARP, Reply 192.168.2.1 is-at 4e:04:c5:3a:7e:7d (oui Unknown), length 28
04:47:10.070583 IP 10.0.1.100 > 192.168.2.2: ICMP echo request, id 2893, seq 1, length 64
04:47:10.070624 IP 192.168.2.2 > 10.0.1.100: ICMP echo reply, id 2893, seq 1, length 64
04:47:23.412338 ARP, Request who-has 192.168.2.2 (Broadcast) tell 192.168.2.1, length 28
04:47:23.412358 ARP, Reply 192.168.2.2 is-at ae:15:fc:27:5b:a1 (oui Unknown), length 28
04:47:23.457071 IP 10.0.1.100 > 192.168.2.2: ICMP echo request, id 2895, seq 1, length 64
04:47:23.457136 IP 192.168.2.2 > 10.0.1.100: ICMP echo reply, id 2895, seq 1, length 64
```

The result tell us that in the first ping at time ```04:47:03``` we sent out our first ARP request for host ```192.168.2.2```, then we send our first ICMP echo. The second ICMP echo was sent out at ```04:47:10```, which is 7 seconds later and the router does not need to ask for ARP request again as now it is still valid in the entries. However, at ```4:47:23```, which is around 20 seconds after the first ping, the ARP now was invalid so the router sent the second ARP request again.

## Test case 7
**Description**: If a host does not respond to 5 ARP requests, the queued packet is dropped and an ICMP host unreachable message is sent back to the source of the queued packet.

**How to**:

1. Update the routing table
```sh
10.0.1.100  10.0.1.100  255.255.255.255 eth3
192.168.2.2 192.168.2.0 255.255.255.0 eth1
172.64.3.10  172.64.3.10  255.255.255.255 eth2
```

This change means every packet that has destination IP ```192.168.2.x``` will be matched and be forwarded to ```192.168.2.0```. 

2. From mininet's terminal, start ```tcpdump``` in the background from ```server1``` side, and ping to ```192.168.2.3```. The reason why is because ```server1``` with IP ```192.168.2.2``` lies in the subnet ```192.168.2.0/24``` with interface ```eth1``` facing. So when the client is trying to ping ```192.168.2.x```, it has to be forwarded to the gateway ```192.168.2.0```, which does not exists. And as our gateway will need to know ```192.168.2.0```'s MAC address, they will broadcast ARP requests 5 times in that subnet before giving up and sending back the ICMP error. ```tcpdump``` from ```server1``` will be able to capture them all.
```sh
mininet> server1 tcpdump -i client-eth0 -w wocao.pcap &
mininet> client ping -c 1 192.168.2.2
PING 192.168.2.2 (192.168.2.2) 56(84) bytes of data.
From 192.168.2.1 icmp_seq=1 Destination Host Unreachable

--- 192.168.2.2 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms
mininet> server1 tcpdump -r wocao.pcap
reading from file wocao.pcap, link-type EN10MB (Ethernet)
03:03:18.705330 ARP, Request who-has 192.168.2.0 (Broadcast) tell 192.168.2.1, length 28
03:03:20.393624 ARP, Request who-has 192.168.2.0 (Broadcast) tell 192.168.2.1, length 28
03:03:22.393786 ARP, Request who-has 192.168.2.0 (Broadcast) tell 192.168.2.1, length 28
03:03:24.394599 ARP, Request who-has 192.168.2.0 (Broadcast) tell 192.168.2.1, length 28
03:03:26.395131 ARP, Request who-has 192.168.2.0 (Broadcast) tell 192.168.2.1, length 28
```
You will find exactly 5 ARP requests in the captured ```.pcap``` file, with ICMP error ```Destination Host Unreachable``` from the client ping.

## Test case 8
**Description**: The router must not needlessly drop packets (for example when waiting for an ARP reply)

**How to**: Start the router fresh new, so there is no MAC address stored in the router's ARP cache. We can simply start pinging any server, we can break out by pressing ```Cltr+C``` anytime and still observe that we have ```0%``` packet loss. 

```bash
mininet> client ping 192.168.2.2
PING 192.168.2.2 (192.168.2.2) 56(84) bytes of data.
64 bytes from 192.168.2.2: icmp_seq=1 ttl=63 time=305 ms
64 bytes from 192.168.2.2: icmp_seq=2 ttl=63 time=77.2 ms
64 bytes from 192.168.2.2: icmp_seq=3 ttl=63 time=50.2 ms
64 bytes from 192.168.2.2: icmp_seq=4 ttl=63 time=73.2 ms
64 bytes from 192.168.2.2: icmp_seq=5 ttl=63 time=94.1 ms
64 bytes from 192.168.2.2: icmp_seq=6 ttl=63 time=64.4 ms
64 bytes from 192.168.2.2: icmp_seq=7 ttl=63 time=52.5 ms
64 bytes from 192.168.2.2: icmp_seq=8 ttl=63 time=71.3 ms
64 bytes from 192.168.2.2: icmp_seq=9 ttl=63 time=91.3 ms
64 bytes from 192.168.2.2: icmp_seq=10 ttl=63 time=62.4 ms

--- 192.168.2.2 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 9000ms
rtt min/avg/max/mdev = 50.213/94.176/305.216/71.670 ms
mininet> client ping 172.64.3.10
PING 172.64.3.10 (172.64.3.10) 56(84) bytes of data.
64 bytes from 172.64.3.10: icmp_seq=1 ttl=63 time=218 ms
64 bytes from 172.64.3.10: icmp_seq=2 ttl=63 time=87.3 ms
64 bytes from 172.64.3.10: icmp_seq=3 ttl=63 time=59.3 ms
64 bytes from 172.64.3.10: icmp_seq=4 ttl=63 time=78.3 ms
64 bytes from 172.64.3.10: icmp_seq=5 ttl=63 time=48.6 ms
64 bytes from 172.64.3.10: icmp_seq=6 ttl=63 time=65.3 ms
64 bytes from 172.64.3.10: icmp_seq=7 ttl=63 time=51.7 ms
64 bytes from 172.64.3.10: icmp_seq=8 ttl=63 time=72.4 ms
^C
--- 172.64.3.10 ping statistics ---
8 packets transmitted, 8 received, 0% packet loss, time 7009ms
rtt min/avg/max/mdev = 48.598/85.085/217.750/51.613 ms

```

## Test case 9
**Description**: The router must enforce guarantees on timeouts–that is, if an ARP request is not responded to within a fixed period of time, the ICMP host unreachable message is generated even if no more packets arrive at the router.

Test case 7 clearly show us how to achieve this. After the first and only ICMP ping, there is no more packets arrive at the router, and all ARP requests is not responded. Therefore, around ~5 seconds, ICMP host unreachable message is generated.