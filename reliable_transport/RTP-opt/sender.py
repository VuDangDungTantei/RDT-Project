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

def sender(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)  

    message = sys.stdin.buffer.read()
    total_bytes = len(message)
    num_packets = math.ceil(total_bytes / MAX_PAYLOAD_SIZE)

    data_packets = {}
    for i in range(num_packets):
        chunk = message[i * MAX_PAYLOAD_SIZE:(i+1) * MAX_PAYLOAD_SIZE]
        packet = make_packet(TYPE_DATA, i + 1, chunk)
        data_packets[i + 1] = packet

    acked = {seq: False for seq in range(1, num_packets+1)}
    dup_ack_count = {seq: 0 for seq in range(1, num_packets+1)}

    # 3-way handshake
    # Sending START packet
    start_packet = make_packet(TYPE_START, 0, b'')
    while True:
        s.sendto(start_packet, (receiver_ip, receiver_port))
        try:
            data, addr = s.recvfrom(2048)
            ack_hdr = PacketHeader(data[:16])
            stored_chk = ack_hdr.checksum
            ack_hdr.checksum = 0
            if stored_chk != compute_checksum(ack_hdr / b''):
                continue
            if ack_hdr.type == TYPE_ACK and ack_hdr.seq_num == 0:
                break
        except socket.timeout:
            continue
    
    final_ack = make_packet(TYPE_ACK, 1, b'')
    s.sendto(final_ack, (receiver_ip, receiver_port))

    base = 1
    next_seq = 1

    while base <= num_packets:
        while next_seq < base + window_size and next_seq <= num_packets:
            s.sendto(data_packets[next_seq], (receiver_ip, receiver_port))
            next_seq += 1

        s.settimeout(0.5)

        try:
            while True:
                data, addr = s.recvfrom(2048)
                ack_hdr = PacketHeader(data[:16])
                stored_chk = ack_hdr.checksum
                ack_hdr.checksum = 0
                if stored_chk != compute_checksum(ack_hdr / b''):
                    continue
                if ack_hdr.type == TYPE_ACK:
                    ack_seq = ack_hdr.seq_num
                    if acked.get(ack_seq, False):
                        dup_ack_count[ack_seq] += 1
                        if dup_ack_count[ack_seq] == 3:
                            if ack_seq < num_packets:
                                s.sendto(data_packets[ack_seq + 1], (receiver_ip, receiver_port))
                                dup_ack_count[ack_seq] = 0
                        continue
                    if 1 <= ack_seq <= num_packets:
                        dup_ack_count[ack_seq] = 0
                        acked[ack_seq] = True
                        while base <= num_packets and acked.get(base, False):
                            base += 1
                        while next_seq < base + window_size and next_seq <= num_packets:
                            s.sendto(data_packets[next_seq], (receiver_ip, receiver_port))
                            next_seq += 1
        except socket.timeout:
            for seq in range(base, min(base + window_size, num_packets+1)):
                if not acked[seq]:
                    s.sendto(data_packets[seq], (receiver_ip, receiver_port))
            next_seq = min(base + window_size, num_packets + 1)

    end_seq = num_packets + 1
    end_packet = make_packet(TYPE_END, end_seq, b'')
    for num_try in range(3):
        s.sendto(end_packet, (receiver_ip, receiver_port))
        s.settimeout(0.5)
        try:
            data, addr = s.recvfrom(2048)
            ack_hdr = PacketHeader(data[:16])
            stored_chk = ack_hdr.checksum
            ack_hdr.checksum = 0
            if stored_chk == compute_checksum(ack_hdr / b''):
                if ack_hdr.type == TYPE_ACK and ack_hdr.seq_num == end_seq + 1:
                    break
        except socket.timeout:
            continue

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip", help="The IP address of the host that receiver is running on")
    parser.add_argument("receiver_port", type=int, help="The port number on which receiver is listening")
    parser.add_argument("window_size", type=int, help="Maximum number of outstanding packets")
    args = parser.parse_args()
    sender(args.receiver_ip, args.receiver_port, args.window_size)

if __name__ == "__main__":
    main()
