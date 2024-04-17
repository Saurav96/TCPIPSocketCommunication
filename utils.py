import socket
from struct import *
from random import randint
import array
import random

### calculate the check sum for the packet
def checksum_calculation(packet):
    check_sum = 0
    highest_hex = 0xffff
    offset = 16
    extra_padding = "\0".encode()
    ## checkinng if extra padding is needed.
    if len(packet) % 2 == 0:
        word = array.array('h', packet)
    else:
        extra_padding_msg = (packet + extra_padding)
        word = array.array('h', extra_padding_msg)
    for letter in word:
        letter = letter & highest_hex
        check_sum += letter
    ## shifting the bit of the cheksum based on the offset.
    check_sum =  (check_sum & highest_hex) + (check_sum >> offset) 
    check_sum = check_sum + (check_sum >> offset)
    final_checksum = (~check_sum & highest_hex)
    return final_checksum
 
### Creates the pesudo header for the tcp that is used to calculate the checksum for the tcp.
def get_checksum_from_pseudo_header(tcp_fake_header, data, client_addr, server_addr):
    tcp_packet_length = len(tcp_fake_header) + len(data)
    pseudo_header_packet  = b""
     # client address 
    pseudo_header_packet += pack("!4s", client_addr)
    # server address
    pseudo_header_packet += pack("!4s", server_addr)
    # placeholder
    pseudo_header_packet += pack("!B", 0)
    # tcp protocol
    pseudo_header_packet += pack("!B", socket.IPPROTO_TCP)
    # tcp packet length
    pseudo_header_packet += pack("!H", tcp_packet_length)
    ## creation of pseudo headers.
    pseudo_packet = pseudo_header_packet + tcp_fake_header + bytes(data, 'utf-8')
    new_checksum = checksum_calculation(pseudo_packet)
    return new_checksum

### Creates a new raw sockect packet, that is it creates an Ip Headers and Tcp Headers from the scratch and combines
### both the TCP and IP headers to send it to the server.
def create_raw_socket_packet(client_ip, server_ip, data = "", seq_number = 0, ack_number = 0, flag_info = 0x02, source_port = 1234):
    client_addr = socket.inet_aton(client_ip)
    server_addr = socket.inet_aton(server_ip)
   
    #######################################################################
        ## Create TCP header
    #########################################################################
    window_size = socket.htons(65535)
    tcp_header_length = 5
    offset_reserve = (tcp_header_length << 4) + 0
    tcp_fake_header = b""
    # source port 
    tcp_fake_header += pack("!H", source_port)
    # dest port 
    tcp_fake_header += pack("!H", 80)
    # seq number
    tcp_fake_header += pack("!L", seq_number)
    # ack number 
    tcp_fake_header += pack("!L", ack_number)
    # header length
    tcp_fake_header += pack("!B", offset_reserve)
    # flags setup 
    tcp_fake_header += pack("!B", flag_info)
    # window length
    tcp_fake_header += pack("!H", window_size)
    # intial check sum 
    tcp_fake_header += pack("!H", 0)
    # urgent pointer
    tcp_fake_header += pack("!H", 0)
    # tcp_fake_header = pack('!HHLLBBHHH', source_port, 80, seq_number, ack_number, offset_reserve, flag_info, window_size, 0, 0)
    new_checksum = get_checksum_from_pseudo_header(tcp_fake_header, data, client_addr, server_addr)

    tcp_original_packet = b""
    # source port 
    tcp_original_packet += pack("!H", source_port)
    # dest port 
    tcp_original_packet += pack("!H", 80)
    # seq number
    tcp_original_packet += pack("!L", seq_number)
    # ack number 
    tcp_original_packet += pack("!L", ack_number)
    # header length
    tcp_original_packet += pack("!B", offset_reserve)
    # flags setup 
    tcp_original_packet += pack("!B", flag_info)
    # window length
    tcp_original_packet += pack("!H", window_size)
    # new check sum 
    tcp_original_packet += pack("H", new_checksum)
    # urgent pointer
    tcp_original_packet += pack("!H", 0)
    # tcp_packet = pack('!HHLLBBH', source_port, 80, seq_number, ack_number, offset_reserve, flag_info, window_size) + pack('H', new_checksum) + pack('!H', 0)


    #######################################################################
        ## Create IP header
    #########################################################################
    unique_id = random.randint(15000, 65535)
    ip_ihl_version = 5 + (4 << 4)
    total_header_length = len(data) + 40
    fragment_bytes = 0
    time_to_live = 255

    ip_fake_header = b""
    # ihl version
    ip_fake_header += pack("!B", ip_ihl_version)
    # type of service 
    ip_fake_header += pack("!B", 0)
    # total header length
    ip_fake_header += pack("!H", total_header_length)
    # unique id 
    ip_fake_header += pack("!H", unique_id)
    # fragment offset
    ip_fake_header += pack("!H", fragment_bytes)
    # time to live 
    ip_fake_header += pack("!B", time_to_live)
    # protocol tcp
    ip_fake_header += pack("!B", socket.IPPROTO_TCP)
    # check sum 
    ip_fake_header += pack("H", 0)
    # client address 
    ip_fake_header += pack("4s", client_addr)
    # server address 
    ip_fake_header += pack("4s", server_addr)


    ## updated check sum after calculation
    new_checksum = checksum_calculation(ip_fake_header)


    ip_original_header = b""
    # ihl version
    ip_original_header += pack("!B", ip_ihl_version)
    # type of service 
    ip_original_header += pack("!B", 0)
    # total header length
    ip_original_header += pack("!H", total_header_length)
    # unique id 
    ip_original_header += pack("!H", unique_id)
    # fragment offset
    ip_original_header += pack("!H", fragment_bytes)
    # time to live 
    ip_original_header += pack("!B", time_to_live)
    # protocol tcp
    ip_original_header += pack("!B", socket.IPPROTO_TCP)
    # check sum 
    ip_original_header += pack("H", new_checksum)
    # client address 
    ip_original_header += pack("4s", client_addr)
    # server address 
    ip_original_header += pack("4s", server_addr)

    total_packet = ip_original_header + tcp_original_packet + bytes(data, 'utf-8')
    return total_packet
    

### This method is used to parse the headers of both TCP and IP.
### when the data is received from the server then parsing must be done to 
### make sure that the headers are correct or not.
def parse_header_packet(header_packet, client_addr, server_addr, source_port):
    #######################################################################
        ## Ip header part parsing from the received socket
    #########################################################################
    ip_section_str = header_packet[:20]
    ip_header_values = unpack('!BBHHHBBH4s4s', ip_section_str)
    ip_receiver_protocol = ip_header_values[6]
    ip_receiver_dest_addr = ip_header_values[9]

    # check if ip address is same or not
    if client_addr != ip_receiver_dest_addr:
        # print("The destination Ip address dosen't match")
        raise ValueError
    # check if the protocol is same or not
    if ip_receiver_protocol != socket.IPPROTO_TCP:
        # print("The protocol dosen't match with tcp")
        raise ValueError

     #######################################################################
        ## TCP header part parsing from the received socket
    #########################################################################
    ## upack the tcp header
    tcp_header_packet = header_packet[20:]
    main_header_section = unpack('!HHLLBBH', tcp_header_packet[0:16])
    check_sum_section = unpack('H', tcp_header_packet[16:18])
    urgent_pointer_section = unpack('!H', tcp_header_packet[18:20])
    tcp_header_fields =  main_header_section + check_sum_section + urgent_pointer_section
    tcp_receiver_dest_port = tcp_header_fields[1] 

    ### check if the ports of the received packet is same or not.
    if source_port != tcp_receiver_dest_port:
        # print("receiver destination port number dosen't match with source port")
        raise ValueError

    tcp_data,mss = prepare_pseudo_header_for_check_sum(tcp_header_packet, tcp_header_fields, client_addr, server_addr)
    return tcp_header_fields, tcp_data, mss

### Creates the pseudo header from the receiver packets which will be used to check the checksum of the receiving packet. 
def prepare_pseudo_header_for_check_sum(tcp_header_packet, tcp_header_fields, client_addr, server_addr):
    header_offset = (tcp_header_fields[4] >> 4)
    extra_options = b""
    offset_last_index = 4*header_offset
    mss = 16
    ## getting the mss from the server.
    if header_offset > 5:
        extra_options = tcp_header_packet[20: offset_last_index]
        mss = unpack('!H', extra_options[0:4][2: ])[0]

    tcp_data = tcp_header_packet[offset_last_index:]
    tcp_header_length = len(tcp_header_packet)

    ### creating the psuedo header packet.
    pseudo_header = pack('!4s4sBBH', server_addr, client_addr, 0, socket.IPPROTO_TCP, tcp_header_length)
    receiver_checksum = tcp_header_fields[7]

    psuedo_plus_tcp_header = pseudo_header
    # source port 
    psuedo_plus_tcp_header += pack("!H", tcp_header_fields[0])
    # dest port 
    psuedo_plus_tcp_header += pack("!H", tcp_header_fields[1])
    # seq number
    psuedo_plus_tcp_header += pack("!L", tcp_header_fields[2])
    # ack number 
    psuedo_plus_tcp_header += pack("!L", tcp_header_fields[3])
    # header length
    psuedo_plus_tcp_header += pack("!B", tcp_header_fields[4])
    # flags setup 
    psuedo_plus_tcp_header += pack("!B", tcp_header_fields[5])
    # window length
    psuedo_plus_tcp_header += pack("!H", tcp_header_fields[6])
    # new check sum 
    psuedo_plus_tcp_header += pack("H", 0)
    # urgent pointer
    psuedo_plus_tcp_header += pack("!H", tcp_header_fields[8])
    psuedo_plus_tcp_header += extra_options 
    psuedo_plus_tcp_header += tcp_data

    new_checksum =  checksum_calculation(psuedo_plus_tcp_header)
    ## if checksum dosen't match then throw error.
    if receiver_checksum != new_checksum:
        print("Check sum dosen't match")
        raise ValueError

    return tcp_data, mss


### Creates the new file for appending the data from the receiver socket.
def create_new_file(url, file_path_address):
    new_file_name = url
    last_char = url[len(url) - 1]
    last_occurance = url.rfind("/")
    ## if there is no file name default value is index.html
    if last_occurance == -1 or last_char == "/" or file_path_address == "":
        new_file_name = 'index.html'
    else:
        index = last_occurance + 1
        new_file_name = url[index:]
    ## creating a new file
    new_file = open(new_file_name, 'w+')
    new_file.close()
    return open(new_file_name, 'r+b')

### prepare the string for the http get request.
def prepare_get_http_request(url, server_name, url_scheme):
    if url_scheme == 'http':
        return "GET " + url + " HTTP/1.0\r\nHost: " + server_name + "\r\nConnection: keep-alive\r\n\r\n"
    else:
        print("The request must be of type http")
        raise ValueError

### removes the headers of the HTTP from the string.
def remove_http_headers(tcp_packet):
    data = tcp_packet.split(bytes('\r\n\r\n', 'utf-8'), 1)
    return data[-1]

### checks if the falg is SNN/ACK flag or not.
def is_flag_syn_Ack(flag):
    return flag == 0x12

### After the handshake chage the sequence and ack numbers.
def change_seq_ack_num(tcp_header_fields):
    new_seq_num = tcp_header_fields[3]
    seq_num_from_res = tcp_header_fields[2]
    new_ack_num = seq_num_from_res + 1
    return new_seq_num, new_ack_num