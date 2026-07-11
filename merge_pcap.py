import struct

def read_pcap(filename):
    with open(filename, 'rb') as f:
        global_header = f.read(24)
        packets = []
        while True:
            pkt_hdr = f.read(16)
            if not pkt_hdr or len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_hdr)
            data = f.read(incl_len)
            packets.append(pkt_hdr + data)
        return global_header, packets

gh1, p1 = read_pcap('test_dpi.pcap')
gh2, p2 = read_pcap('udp.pcap')

with open('mixed_traffic.pcap', 'wb') as f:
    f.write(gh1) # Use the global header from the first file
    for p in p1: f.write(p)
    for p in p2: f.write(p)

print("mixed_traffic.pcap created!")
