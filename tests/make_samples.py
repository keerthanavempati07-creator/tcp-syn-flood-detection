"""Creates SYNTHETIC sample capture files in sample_data/ (pure Python, no Scapy).
The files are only written to disk - nothing is ever sent on a network.

Run:  python tests/make_samples.py
"""
import os
import random
import socket
import struct

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sample_data")
BASE_TS = 1_700_000_000


def frame(src, dst, sport, dport, flags):
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 8192, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return eth + ip + tcp


def write_pcap(name, packets):
    """packets: list of (timestamp_float, frame_bytes)"""
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in sorted(packets, key=lambda p: p[0]):
            sec = int(ts)
            f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(data), len(data)))
            f.write(data)


def normal_traffic(seconds=60):
    pk = []
    clients = ["192.168.1.%d" % i for i in range(10, 15)]
    for s in range(seconds):
        for _ in range(random.randint(1, 3)):                  # a few connections/second
            c = random.choice(clients)
            t = BASE_TS + s + random.random()
            sp = random.randint(40000, 60000)
            pk.append((t, frame(c, "192.0.2.10", sp, 80, 0x02)))             # SYN
            pk.append((t + .01, frame("192.0.2.10", c, 80, sp, 0x12)))       # SYN+ACK
            pk.append((t + .02, frame(c, "192.0.2.10", sp, 80, 0x10)))       # ACK
            for k in range(5):
                pk.append((t + .03 + k * .01, frame(c, "192.0.2.10", sp, 80, 0x18)))  # PSH+ACK
    return pk


def add_burst(pk, sources, start, secs, per_sec):
    for s in range(secs):
        for src in sources:
            for _ in range(per_sec):
                pk.append((BASE_TS + start + s + random.random(),
                           frame(src, "192.0.2.10", random.randint(1024, 65000), 80, 0x02)))


if __name__ == "__main__":
    random.seed(7)
    os.makedirs(OUT, exist_ok=True)
    write_pcap("normal_traffic.pcap", normal_traffic())

    p = normal_traffic()
    add_burst(p, ["203.0.113.50"], 20, 10, 40)         # one source, 40 SYN/s for 10 s
    write_pcap("single_source_burst.pcap", p)

    p = normal_traffic()
    add_burst(p, ["203.0.113.%d" % i for i in range(10, 16)], 30, 10, 15)   # 6 sources
    write_pcap("multi_source_burst.pcap", p)

    with open(os.path.join(OUT, "invalid_file.pcap"), "wb") as f:
        f.write(b"this is not a capture file")
    with open(os.path.join(OUT, "empty_capture.pcap"), "wb") as f:   # header, zero packets
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    print("Sample files written to", os.path.abspath(OUT))
