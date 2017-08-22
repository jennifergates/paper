# Run with python. Reads in test pcaps, multiplies each of them by 1000 and writes them all to the allpcapsx1000.pcap file

from scapy.all import *

path = '../pcaps/'
# Make sure files are in ascending time order or Bro will discard older packets.
files = ["ndn-tlv-websocket-notng.pcap", "ipv4-websocket-segmented.pcap", "websockets-issue-68-notng.pcap", "websocket.pcap", "test3.pcap", "sqlagent.pcap", "csrf-pwdchange.pcap", "blindsql2.pcap"]
for f in files:
    inpcap = path + f
    print inpcap
    packets = rdpcap(inpcap)
    output = PcapWriter("../pcaps/allpcapsx1000.pcap", append=True, sync=True)
    packet_time = packets[0].time

    for i in range(0,1000):
        output.write(packets)
        packet_time = packet_time + 3600
        for packet in packets:
            packet.time = packet_time
            packet_time += 1