#!/usr/bin/env python3

import socket
import sys
from urllib.parse import urlparse
from random import randint
from utils import *
import time
import subprocess
import binascii

### Gets the ip address of the the local machine.
def get_local_machine_ip_address():
    dummy_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dummy_udp_socket.connect(('8.8.8.8', 1))
    local_ip_addr = dummy_udp_socket.getsockname()[0]
    dummy_udp_socket.close()
    return local_ip_addr

### Gets the mac addresss of the machine.
def get_local_machine_mac_address(send_socket_ethernet):
    return send_socket_ethernet.getsockname()[4]

### Broadcast the arp request to find the mac addresss of the router.
def broadcast_arp_request_to_get_mac_address(interface_name ,client_ip_address):
    ### Gateway Ip address that needs to be requested to get mac addresss.
    gateway_address = subprocess.check_output("echo $(/sbin/ip route | awk '/default/ {print $3}')", shell=True)
    gateway_address = gateway_address.decode("utf-8").rstrip("\n")
    ## send socket for ethernet.
    send_socket_ethernet = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.SOCK_RAW)
    send_socket_ethernet.bind((interface_name,socket.SOCK_RAW))
    ## mac address
    client_mac = get_local_machine_mac_address(send_socket_ethernet)
    broadcast_mac = binascii.unhexlify('ff:ff:ff:ff:ff:ff'.replace(':', ''))
    ## Packing the Ethernet headers using client and server mac address with arp protocol.
    arp_protocol = 0x0806 
    ## packing for the ethernet section
    ethernet_arp_header = pack("!6s6sH", broadcast_mac, client_mac, arp_protocol)

    # ARP header fields
    hw_type = 1  
    ptype = 0x0800
    hw_addr_len = 6
    protocol_length = 4
    operation = 1 
    client_address = socket.inet_aton(client_ip_address)
    server_address = socket.inet_aton(gateway_address)
    ## packing for the ARP headers section
    arp_hdr = pack("!HHBBH6s4s6s4s", hw_type, ptype, hw_addr_len, protocol_length, operation, client_mac, client_address, broadcast_mac, server_address)

    ### adding the padding because of the minimum size constraint.
    if len(arp_hdr) < 46:
        arp_hdr += b"\x00"*(46 - len(arp_hdr))
    
    ### final packet that contains ethernet header and arp headers.
    arp_packet = ethernet_arp_header + arp_hdr

    ## sending the arp_packets multiple times.
    for i in range(2):
        send_socket_ethernet.send(arp_packet)
    # send_socket_ethernet.close()

    return client_mac, gateway_address

## Main method which is used to start the program.
def main():
    ## Information related to server and login.
    url = ""
    ## parsing the system arguments to find the username and password.
    interface_name = ""
    if sys.argv and len(sys.argv) > 1:
        if sys.argv[1]:
            url = sys.argv[1]
        if sys.argv[2]:
            interface_name = sys.argv[2]
    else:
        print("Please enter the URL and interface name!")
        sys.exit()

    #######################################################################
        ## Parse the given url
    #########################################################################
    url_fields = urlparse(url)
    file_path_address = ""
    server_name = ""
    url_scheme = ""
    ## getting the schema and path of the URL.
    if len(url_fields) > 1 and url_fields[0] and url_fields[1]:
        if url_fields[0]:
            url_scheme = url_fields[0]
        if url_fields[1]:
            server_name = url_fields[1]
    else:
        print("Please enter valid URL")
        sys.exit()
        
    ## path for the file.
    if url_fields[2]:
        file_path_address = url_fields[2]

    ## only allow http type request.
    if(url_scheme != "http"):
        print("Only http is supported")
        sys.exit()
    
    # Intital details setup.
    server_ip_address = socket.gethostbyname(server_name)
    client_ip_address = get_local_machine_ip_address()
    client_addr = socket.inet_aton(client_ip_address)
    server_addr = socket.inet_aton(server_ip_address)
    source_port = random.randint(1024, 65535)
    # interface_name = "ens33"
    ## starting sequence number is random.
    seq_number = random.randint(0, 2 ** 32 - 1)
    ack_number = 0
    seq_offset = 0
    ack_offset = 0
    time_out = 60
    cwnd = 1
    last_ack_time = time.time()
    mss = 16
 
    # #######################################################################
    #     ## Broadcasting inorder to get router mac address.
    # #########################################################################
    print("Broadcasting started")

    ## socket for receving the broadcast message.
    arp_receiver_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.htons(0x0806))
    source_mac_addr, gateway_address = broadcast_arp_request_to_get_mac_address(interface_name, client_ip_address)
   
    #### Read the respose after sending the ARP packet.
    while True:
        header_info = arp_receiver_socket.recv(2048)
        # header_info = header_info[0]
        if len(header_info) < 14:
            continue

        ## unpacking the ethernet header
        eth_header = unpack('!6s6sH' , header_info[:14])
        res_dest_mac = eth_header[0]
        res_src_mac = eth_header[1]
        res_protocol = eth_header[2]
        ## checking if the response is arp and the mac address match.
        if res_protocol == 0x0806 and res_dest_mac == source_mac_addr:
            ## Arp header unpacking.
            arp_header = header_info[14:42]
            arp_header_contents = unpack("!HHBBH6s4s6s4s", arp_header)
            response_addr = socket.inet_ntoa(arp_header_contents[6]) 
            ## check if the ip address match with gateway ip.
            if response_addr == gateway_address:                                  
                break

    ## routers destination address.
    destination_mac_addr = res_src_mac
    arp_receiver_socket.close()
    print("Broad Casting ended")

    #######################################################################
        ## Create sockets for send and receive.
    #########################################################################
    sender_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    ### Binding the current interface
    sender_socket.bind((interface_name,socket.SOCK_RAW))

    ## Handle sending the packet based on the updated sequence number and ack number using socket send and ethernet frames.
    def handle_send_packet(client_ip_address, server_ip_address, data, seq_number, ack_number, flag, source_port, seq_new_offset=0):
        tcp_plus_ip_header = create_raw_socket_packet(client_ip_address, server_ip_address, data, seq_number, ack_number, flag, source_port)
        ip_protocol = 0x0800
         ## packing for the ethernet section
        ethernet_header = pack("!6s6sH", destination_mac_addr, source_mac_addr, ip_protocol)
        pack_sent_to_server = ethernet_header +  tcp_plus_ip_header
        sender_socket.send(pack_sent_to_server)  

    ### Send the SYN flag to the server
    def send_syn_packet():
        handle_send_packet(client_ip_address, server_ip_address, "", seq_number, ack_number, 0x02, source_port)
        
    ### Send the ACK flag to the server
    def send_ack_packet():
        handle_send_packet(client_ip_address, server_ip_address, "", seq_number, ack_number, 0x10, source_port)

    #######################################################################
        ## Create TCP three way handshake
    #########################################################################
    #### Step1. Sending the SYN flag packet to the server.
    send_syn_packet()
    syn_ack_flag = False
    minutes = 3
    ## step 2 check for SYN/ACK
    ### wait for 3 minutes before exiting the program.
    while(minutes > 0):
        time_of_begin = time.time()
        current_time = time.time()
        ## wait for 1 minute i,e time out to retransmit.
        while current_time - time_of_begin <= time_out:
            try:
                ## receive the data after sending the SYN packet.
                header_packet = receiver_socket.recv(65535)
                tcp_header_fields, tcp_data, mss = parse_header_packet(header_packet, client_addr, server_addr, source_port)
                ## check if the received headers has SYN/ACK or not.
                if (is_flag_syn_Ack(tcp_header_fields[5]) == True):
                    syn_ack_flag = True
                    break
            except ValueError:
                pass
            current_time = time.time()

        ### if the syn/ack is not yet received then retransmit the syn packet. 
        if syn_ack_flag == False:
            send_syn_packet()
        else:
            break
        minutes = minutes-1
    ## exit if 3 minutes exceed
    if minutes == 0:
        print("3 minutes exceded so exiting the program")
        sys.exit()
    ack_value_from_server = tcp_header_fields[3]
    ## checking for sequence and ack number.
    if syn_ack_flag == True and seq_number + 1 == ack_value_from_server:
        seq_number, ack_number = change_seq_ack_num(tcp_header_fields)
        ## Step 3. send ack to complete the handshake.
        send_ack_packet()
        print("Tcp hand shake completed!")


    ### send the ack and fin packet used for the tear down process.
    def ack_the_fin_flag():
        print("closed the connection")
        handle_send_packet(client_ip_address, server_ip_address, "", seq_number + seq_offset, ack_number + ack_offset + 1, 0x011, source_port)
   
   #######################################################################
        ## Calling the get http request for the given url.
   #########################################################################
    get_request_data = prepare_get_http_request(url, server_name, url_scheme)
    seq_offset += len(get_request_data)

    ##### sending the GET HTTP request to the server.
    handle_send_packet(client_ip_address, server_ip_address, get_request_data, seq_number, ack_number, 0x18, source_port)

    #######################################################################
        ## Create a new file as per the given URL
    #########################################################################
    new_file_pointer = create_new_file(url, file_path_address)

    #######################################################################
        # perform congestion control and request packets in order based on the get call.
    #########################################################################
    def check_for_timeout(last_ack_time):
        max_time_out = 3 * time_out
        last_ack_diff = time.time() - last_ack_time
        if max_time_out < last_ack_diff:
            print("3 minutes exceeded so closing the connection!")
            sys.exit()
    
    ## after sending the GET HTTP request to the server we need to listen to the server and send ack's back.
    is_data_written = False
    finshed_flag = False
    slow_start_flag = True
    mss = 512
    seq = 1
    start_slow_threshold = 800
    seq_new_offset = 0
    while True:
        time_of_begin = time.time()
        current_time = time_of_begin
        time_diff = current_time - time_of_begin
        ## wait for 1 minute before sending the packet again time out(60)
        while time_out > current_time - time_of_begin:
            try:
                ## recieve the data from the socket and parse the header and check if it is valid or not.
                header_packet = receiver_socket.recv(65535)
                tcp_header_fields, tcp_response,_ = parse_header_packet(header_packet, client_addr, server_addr, source_port)
                break
            except ValueError:
                current_time = time.time()
                continue
        # tcp_header_fields, tcp_response, current_time = parse_more_packets(time_of_begin, current_time)

        ## if there is a longer time out close the connection (tear down).
        check_for_timeout(last_ack_time)
        ## performing time out and setting cwnd=1
        time_differenece = current_time - time_of_begin
        if (time_differenece + time_out < time_differenece):
            cwnd = 1
            slow_start_flag = True
        if cwnd > start_slow_threshold:
            slow_start_flag = False
            cwnd = min(cwnd, 999) + 1

        ## checking if the sequence number and ack numbers match the upcoming receiver seq and ack numbers or not.
        updated_seq_num = seq_number + seq_offset
        updated_ack_num = ack_number + ack_offset
        if updated_ack_num == tcp_header_fields[2] and updated_seq_num == tcp_header_fields[3]:
            ## updating the ack_time
            last_ack_time = time.time()
            ## sequence number update
            seq = cwnd * mss
            ack_offset += len(tcp_response)
            ## if it is the first time writing to the file then removing the http headers from the file and writing it.
            if not is_data_written:
                data = remove_http_headers(tcp_response)
                if len(data) > 0:
                    new_file_pointer.write(data)
                    is_data_written = True
            else:
                ## writing to the file.
                new_file_pointer.write(tcp_response)
            if slow_start_flag == False:
                seq_new_offset = seq
            ### send the next ack packet, with the updated sequence number and ack number.
            handle_send_packet(client_ip_address, server_ip_address, "", seq_number + seq_offset, ack_number + ack_offset, 0x10, source_port, seq_new_offset)
            if tcp_header_fields[5] & 0x01:
                finshed_flag = True
                break
        else:
            cwnd = 1

    #######################################################################
        # Tearing down the connection after succefully completing the request.
    #########################################################################
    if finshed_flag == True:
        print("Tearing down the connection")
        ack_the_fin_flag()

    ## closing the resourced/
    print("File downloaded")
    new_file_pointer.close()
    sender_socket.close()
    receiver_socket.close()
   

if __name__ == "__main__":
    main()