
## Objective: 
1. The goal of this assignment is to implement the low-level operations of the Internet protocol stack. 
2. This program takes a URL on the command line, downloads the associated web page or file, and saves it to the current directory.
3. This program is responsible for building the ethernet, IP and TCP headers in each packet.

## Contributors: 
* Raghunath Reddy Arava 
* Saurav Shaw

### PREREQUISITE: 

The program should be executed as a root user otherwise socket will not be created. The following two command must be run before running this program with sudo user. 1. sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP 2. sudo ethtool -K gro off

### How to run the program: 

This project on Raw sockets Crawler has a total of four files: 1. rawhttpget: This file has all the python code related to the raw socket sending and receiving the data from the server to and forth updating the sequence number and acknowledge number. 2. Makefile: this file is used to set some rules for the rawhttpget file. One should run the Make file before running any command. The command for running this program is: "sudo python3 ./rawhttpget [URL] [interface_name]" where [URL] is the command line argument of the URL that will be used in the program to download the content (URL must be only of type HTTP). if the URL is invalid or not given then the program will exit. where[interface_name] must be the local machine interface name depends on the user running the program.

### High-Level approach: 
1. The first thing that I understood when I read the requirements is that I need to create two sockets one for the receiver of raw type IPPROTO_TCP and another for the sender raw socket IPPROTO_RAW. 
2. For these raw sockets the header must be built from the scratch and firstly IP header must be built than the TCP header, after that both TCP and IP header must be contacted to make a packet that can be used to send to the server. 
3. Using the struct pack method we could able easily handle the packing of header bytes as per the header length requirements of the TCP and IP. 
4. To receive data from the server TCP handshake must be done which is to send the SYN flag packet, then read for the SYN/ACK flag once we get it, send the ACK flag which will complete the three-way handshake. 
5. After completion of the handshake, we have to send the GET HTTP request in form of packets to the server for the given URL, so again using the TCP and IP header preparation method built the packet to send the HTTP request with ACK flag. 
6. Once the GET request is sent to the server, it will reply with an ACK flag and the payload that server wants to send (i.e the contents of the file). 
7. Time out is implemented so that if any packet takes more than 1 minute then it will be retransmitted, if the time exceeds 3 minutes then it will print an error and exit out of the program. 
8. There might be many requests in chunks coming from the server, so tracking the order of sequence number and rearranging is done and also the final response is written to the file. 9. Finally, when the server sends the FIN flag packet to the client, then the client will send FIN/ACK to teardown the connection.

### How we implemented Ethernet functionality: 

1. For Ethernet frames, firstly we need to broadcast an ARP request to the gateway ip address of the router and then router will give the response as an ARP reply where the mac address of the router will be available. 
2. Once we get the mac address the ethernet frames needs to be created every time before sending the packets to the server by enabling AF_PACKET.

### Challenges your faced for ARP (Ethernet frames): 

1. The header length needs to be adjusted inorder to include the tcp and ip headers with ethernet frames. 
2. We were unable to recive the of the ARP reply using socket recv() method and with AF_PACKET. 
3. Setting the Ethernet frames with TCP and IP combined is difficult.

### Challenges faced during development: 

1. Building the TCP and IP headers is one of the biggest challenges. 
2. Calculating the correct checksum and validating the checksum. 
3. Implementing the time out to retransmit and exit the program. 
4. Debugging through Wireshark is very difficult. 
5. Files like 10 MB and 50 MB are difficult to evaluate because a lot of request are sent back and forth 
6. Handling a combination of bytes strings and number is difficult. 
7. Challenge faced while figuring out which value needs to be included in the header of TCP and IP and which are not to be included.

### Who worked on which part of the Project: 

#### Raghunath Reddy Arava: 
1. TCP header creation with all the required fields needed for it to be successfully sent to the server. 
2. Handled the TCP unwrap of the header to check if it is a valid request or not. 
3. Created the HTTP GET request string, which is used to send the GET HTTP request packet, that will give the file content. 
4. Handled the checking of whether the port number of the request is intended for the client port or not. 
5. Implemented the Three Way Handshake. 
6. Creating the file for downloading the data from the server. 
7. Tear down the connection after the last FIN packet is received by a client, FIN/ACK will be sent to initiate tear down process. 
8. Remove the HTTP headers from the response of the server. 
9. Broadcasting the ARP request is handled. 
10. Ethernet frames are appended with TCP and IP headers.

#### Saurav Shaw:
1. IP header creation with all the required fields needed for it to be successfully sent to the server.
2. Handled the IP unwrap of the header to check if it is a valid request or not.
3. Handled the ACK packet creation after the GET request is sent to the server.
4. Handled the checking of whether the Ip address of the request is intended for the client or not.
5. Time-out functionality for the 1-minute retransmission and 3 minuted exit.
6. When file text data is being received from the server then the ACK flag must be verified and congestion control needs to be set up.
7. Close all the resources and exit the program.
8. Name the file based on the URL parsing, either index.html or URL file path.
9. The ARP reply is handled.

### Testing: 
Tested the program using several different URLs 
1. sudo python3 ./rawhttpget [URL] 
2. sudo python3 ./rawhttpget http://david.choffness.com 
3. sudo python3 ./rawhttpget http://david.choffnes.com/classes/cs4700fa16/project3.php 
4. sudo python3 ./rawhttpget http://david.choffnes.com/classes/cs4700fa16/2MB.log 
5. sudo python3 ./rawhttpget http://david.choffnes.com/classes/cs4700fa16/10MB.log 
6. sudo python3 ./rawhttpget http://david.choffnes.com/classes/cs4700fa16/50MB.log
