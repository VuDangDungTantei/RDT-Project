import argparse
import socket
import sys
import time
import math

from utils import PacketHeader, compute_checksum

MAX_PACKET_SIZE = 1472
HEADER_SIZE = 16  
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE  

TYPE_START = 0
TYPE_END = 1
TYPE_DATA = 2
TYPE_ACK = 3

def make_packet(pkt_type, seq_num, payload=b''):
    length = len(payload)
    header = PacketHeader(type=pkt_type, seq_num=seq_num, length=length, checksum=0)
    pkt = header / payload
    chksum = compute_checksum(pkt)
    header.checksum = chksum
    pkt = header / payload
    return bytes(pkt)
    
def calculate_time(timer_start):
    if timer_start is not None:
        time_elapsed = time.time() - timer_start
        timeout_interval = 0.5 - time_elapsed
    else:
        timeout_interval = 0.5
    if timeout_interval <= 0:
        timeout_interval = 0.001
    return timeout_interval

def sender(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)

    message = sys.stdin.buffer.read()
    total_bytes = len(message)

    # 2-way handshake
    # Sending START packet
    start_packet = make_packet(TYPE_START, 0, b'')
    while True:
        s.sendto(start_packet, (receiver_ip, receiver_port))
        try:
            data, addr = s.recvfrom(2048)
            ack_header = PacketHeader(data[:16])
            stored_chksum = ack_header.checksum
            ack_header.checksum = 0
            if stored_chksum != compute_checksum(ack_header / b''):
                continue  
            if ack_header.type == TYPE_ACK and ack_header.seq_num == 1:
                break  
        except socket.timeout:
            continue

    num_packets = math.ceil(total_bytes / MAX_PAYLOAD_SIZE)
    
    # Key is seq_num and value is packet
    data_packets = {}
    for i in range(num_packets):
        chunk = message[i * MAX_PAYLOAD_SIZE : (i + 1) * MAX_PAYLOAD_SIZE]
        packet = make_packet(TYPE_DATA, i + 1, chunk)
        data_packets[i + 1] = packet

    base = 1         
    next_seq = 1
    send_time = {}

    while base <= num_packets:
        # Send all packet in window
        while next_seq < base + window_size and next_seq <= num_packets:
            s.sendto(data_packets[next_seq], (receiver_ip, receiver_port))
            send_time[next_seq] = time.time()
            next_seq += 1
        
        s.settimeout(calculate_time(send_time[base]))

        try:
            while True:
                ack_data, addr = s.recvfrom(2048)
                ack_hdr = PacketHeader(ack_data[:16])
                stored_chksum = ack_hdr.checksum
                ack_hdr.checksum = 0
                if stored_chksum != compute_checksum(ack_hdr / b''):
                    continue
                if ack_hdr.type == TYPE_ACK:
                    ack_seq = ack_hdr.seq_num
                    if ack_seq > base:
                        base = ack_seq
                        while next_seq < base + window_size and next_seq <= num_packets:
                            s.sendto(data_packets[next_seq], (receiver_ip, receiver_port))
                            send_time[next_seq] = time.time()
                            next_seq += 1
                        if base < next_seq:
                            s.settimeout(calculate_time(send_time[base]))
                        else:
                            break; 
        except socket.timeout:
            for seq in range(base, next_seq):
                s.sendto(data_packets[seq], (receiver_ip, receiver_port))
                send_time[seq] = time.time()
            s.settimeout(calculate_time(send_time[base]))

    #Sending END packet
    end_seq = num_packets + 1
    end_packet = make_packet(TYPE_END, end_seq, b'')
    s.sendto(end_packet, (receiver_ip, receiver_port))
    s.settimeout(0.5)
    try:
        ack_data, addr = s.recvfrom(2048)
        ack_hdr = PacketHeader(ack_data[:16])
        stored_chksum = ack_hdr.checksum
        ack_hdr.checksum = 0
        if stored_chksum == compute_checksum(ack_hdr / b''):
            if ack_hdr.type == TYPE_ACK and ack_hdr.seq_num == end_seq + 1:
                pass 
    except socket.timeout:
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip", help="The IP address of the host that receiver is running on")
    parser.add_argument("receiver_port", type=int, help="The port number on which receiver is listening")
    parser.add_argument("window_size", type=int, help="Maximum number of outstanding packets")
    args = parser.parse_args()
    sender(args.receiver_ip, args.receiver_port, args.window_size)

if __name__ == "__main__":
    main()
