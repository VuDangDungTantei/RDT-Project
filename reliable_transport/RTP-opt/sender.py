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
TYPE_DATA  = 2
TYPE_ACK   = 3

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
            if ack_hdr.type == TYPE_ACK and ack_hdr.seq_num == 1:
                break
        except socket.timeout:
            continue

    base = 1
    next_seq = 1
    timer_start = None

    while base <= num_packets:
        while next_seq < base + window_size and next_seq <= num_packets:
            s.sendto(data_packets[next_seq], (receiver_ip, receiver_port))
            if timer_start is None:
                timer_start = time.time()
            next_seq += 1

        if timer_start is not None:
            elapsed = time.time() - timer_start
            remaining = 0.5 - elapsed
        else:
            remaining = 0.5
        if remaining <= 0:
            remaining = 0.001
        s.settimeout(remaining)

        try:
            data, addr = s.recvfrom(2048)
            ack_hdr = PacketHeader(data[:16])
            stored_chk = ack_hdr.checksum
            ack_hdr.checksum = 0
            if stored_chk != compute_checksum(ack_hdr / b''):
                continue
            if ack_hdr.type == TYPE_ACK:
                ack_seq = ack_hdr.seq_num
                if 1 <= ack_seq <= num_packets:
                    acked[ack_seq] = True
                    while base <= num_packets and acked.get(base, False):
                        base += 1
                    if base < next_seq:
                        timer_start = time.time()
                    else:
                        timer_start = None
        except socket.timeout:
            for seq in range(base, min(base + window_size, num_packets+1)):
                if not acked[seq]:
                    s.sendto(data_packets[seq], (receiver_ip, receiver_port))
            timer_start = time.time()

    end_seq = num_packets + 1
    end_packet = make_packet(TYPE_END, end_seq, b'')
    s.sendto(end_packet, (receiver_ip, receiver_port))
    s.settimeout(0.5)
    try:
        data, addr = s.recvfrom(2048)
        ack_hdr = PacketHeader(data[:16])
        stored_chk = ack_hdr.checksum
        ack_hdr.checksum = 0
        if stored_chk == compute_checksum(ack_hdr / b''):
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
