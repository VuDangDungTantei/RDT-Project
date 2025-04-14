import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

TYPE_START = 0
TYPE_END   = 1
TYPE_DATA  = 2
TYPE_ACK   = 3

def make_ack(ack_seq):
    header = PacketHeader(type=TYPE_ACK, seq_num=ack_seq, length=0, checksum=0)
    pkt = header / b''
    chksum = compute_checksum(pkt)
    header.checksum = chksum
    pkt = header / b''
    return bytes(pkt)

def receiver(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((receiver_ip, receiver_port))
    s.settimeout(0.5)

    in_connection = False
    expected_seq = 1  
    received_packets = {}

    while True:
        try:
            pkt, addr = s.recvfrom(2048)
        except socket.timeout:
            continue

        if len(pkt) < 16:
            continue

        pkt_header = PacketHeader(pkt[:16])
        payload = pkt[16:16 + pkt_header.length]

        stored_chk = pkt_header.checksum
        pkt_header.checksum = 0
        if stored_chk != compute_checksum(pkt_header / payload):
            continue

        pkt_type = pkt_header.type
        seq_num  = pkt_header.seq_num

        if pkt_type == TYPE_START:
            if not in_connection:
                in_connection = True
                expected_seq = 1
                received_packets = {}
                ack_pkt = make_ack(1)
                s.sendto(ack_pkt, addr)
            else:
                continue

        elif pkt_type == TYPE_DATA:
            if not in_connection:
                continue
            if seq_num >= expected_seq + window_size:
                continue

            if seq_num not in received_packets:
                received_packets[seq_num] = payload
            ack_pkt = make_ack(seq_num)
            s.sendto(ack_pkt, addr)

            if seq_num == expected_seq:
                while expected_seq in received_packets:
                    expected_seq += 1

        elif pkt_type == TYPE_END:
            if not in_connection:
                continue
            ack_pkt = make_ack(seq_num + 1)
            s.sendto(ack_pkt, addr)
            break

    assembled = []
    for seq in sorted(received_packets.keys()):
        assembled.append(received_packets[seq])
    full_message = b"".join(assembled)
    sys.stdout.buffer.write(full_message)
    sys.stdout.buffer.flush()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip", help="The IP address of the host that receiver is running on")
    parser.add_argument("receiver_port", type=int, help="The port number on which receiver is listening")
    parser.add_argument("window_size", type=int, help="Maximum number of outstanding packets")
    args = parser.parse_args()
    receiver(args.receiver_ip, args.receiver_port, args.window_size)

if __name__ == "__main__":
    main()

