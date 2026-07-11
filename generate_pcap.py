import struct
import time

def create_pcap():
    # Global header (24 bytes): magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network
    global_header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    
    with open('udp.pcap', 'wb') as f:
        f.write(global_header)
        
        # Generate 50 UDP packets
        for i in range(50):
            # Payload
            payload = b"Fake UDP Data " + str(i).encode()
            
            # UDP Header (8 bytes): sport, dport, len, cksum
            udp_len = 8 + len(payload)
            udp_hdr = struct.pack('!HHHH', 12345, 53, udp_len, 0)
            
            # IP Header (20 bytes): 
            # VHL, TOS, len, ID, frag, ttl, proto, cksum, src, dst
            ip_len = 20 + udp_len
            ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len, i, 0, 64, 17, 0, b'\xc0\xa8\x01\x64', b'\x08\x08\x08\x08')
            
            # Ethernet Header (14 bytes): dst, src, type
            eth_hdr = struct.pack('!6s6sH', b'\x55\x44\x33\x22\x11\x00', b'\x00\x11\x22\x33\x44\x55', 0x0800)
            
            packet = eth_hdr + ip_hdr + udp_hdr + payload
            
            # Packet header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
            ts = int(time.time())
            pkt_hdr = struct.pack('<IIII', ts, i*1000, len(packet), len(packet))
            
            f.write(pkt_hdr + packet)

create_pcap()
print("udp.pcap created!")
