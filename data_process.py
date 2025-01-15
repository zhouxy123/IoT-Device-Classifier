from scapy.all import *
from pandas import DataFrame
import math
import random
import glob


def pcap2vec(type, pcap_file):
    packets = rdpcap(pcap_file)
    pkt_num = len(packets)
    random_numbers = []
    if pkt_num >= 12:
        # 设置要生成的随机数个数为12
        num_of_numbers = 12

        # 设置随机数范围
        range_start = 1
        range_end = pkt_num

        # 生成不重复的随机数列表
        random_numbers = random.sample(range(range_start, range_end + 1), num_of_numbers)
        # print("生成的{}个不同的随机数为：".format(num_of_numbers))
        random_numbers.sort()
    else:
        # print(pkt_num)
        for num in range(1, pkt_num + 1):
            random_numbers.append(num)
        for num in range(1, 12 - pkt_num + 1):
            random_numbers.append(random.randrange(1, pkt_num))
        # print(random_numbers)
    i = 0
    ip_change = 0
    last_ip = ''
    row = []
    row.append(type)

    arp_array = []
    llc_array = []
    ip_array = []
    icmp_array = []
    icmpv6_array = []
    eapol_array = []
    tcp_array = []
    udp_array = []
    http_array = []
    https_array = []
    dhcp_array = []
    bootp_array = []
    ssdp_array = []
    dns_array = []
    mdns_array = []
    ntp_array = []
    length_array = []
    ip_change_array = []
    src_port_array = []
    dst_port_array = []

    for number in random_numbers:
        # print(number)
    # for packet in packets:
        packet = packets[number-1]

        i += 1
        if 'IP' in packet:
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
        elif 'IPv6' in packet:
            src_ip = packet['IPv6'].src
            dst_ip = packet['IPv6'].dst
        else:
            src_ip = ''
            dst_ip = ''

        # Data link layer(1-2)
        arp = int(packet.haslayer('ARP'))
        arp_array.append(arp)

        llc = int(packet.haslayer('LLC'))
        llc_array.append(llc)

        # Network layer(3-6)
        ip = int(packet.haslayer('IP'))
        ip_array.append(ip)

        icmp = int(packet.haslayer('ICMP'))
        icmp_array.append(icmp)

        icmpv6 = int(packet.haslayer('ICMPv6ND_NS'))
        icmpv6_array.append(icmpv6)

        eapol = int(packet.haslayer('EAPOL'))
        eapol_array.append(eapol)

        # Transport layer(7-8)
        tcp = int(packet.haslayer('TCP'))
        tcp_array.append(tcp)

        udp = int(packet.haslayer('UDP'))
        udp_array.append(udp)

        # Application layer(9-16)
        http = int(packet.haslayer('HTTP'))
        http_array.append(http)

        https = int(packet.haslayer('HTTPS'))
        https_array.append(https)

        dhcp = int(packet.haslayer('DHCP'))
        dhcp_array.append(dhcp)

        bootp = int(packet.haslayer('BOOTP'))
        bootp_array.append(bootp)

        ssdp = int(packet.haslayer('SSDP'))
        ssdp_array.append(ssdp)

        dns = int(packet.haslayer('DNS'))
        dns_array.append(dns)

        mdns = int(packet.haslayer('MDNS'))
        mdns_array.append(mdns)

        ntp = int(packet.haslayer('NTP'))
        ntp_array.append(ntp)

        # Length of packet(17)
        if len(packet) == 0:
            length = 0
        elif 1 <= len(packet) <= 400:
            length = math.floor((len(packet) - 1)/50)
        else:
            length = 8
        length_array.append(length)

        # dst IP address(18)
        if i >= 2:
            if dst_ip != last_ip:
                ip_change += 1
        last_ip = dst_ip
        ip_change_array.append(ip_change)

        # src and dst port(19-20)
        # [0, 1023]: well known port--1
        # [1024, 49151]: registered port--2
        # [49152, 65535]: dynamic port--3
        if tcp == 1:
            if 0 <= packet['TCP'].sport <= 1023:
                src_port = 1
            elif 1024 <= packet['TCP'].sport <= 49151:
                src_port = 2
            else:
                src_port = 3

            if 0 <= packet['TCP'].dport <= 1023:
                dst_port = 1
            elif 1024 <= packet['TCP'].dport <= 49151:
                dst_port = 2
            else:
                dst_port = 3

        elif udp == 1:
            if 0 <= packet['UDP'].sport <= 1023:
                src_port = 1
            elif 1024 <= packet['UDP'].sport <= 49151:
                src_port = 2
            else:
                src_port = 3

            if 0 <= packet['UDP'].dport <= 1023:
                dst_port = 1
            elif 1024 <= packet['UDP'].dport <= 49151:
                dst_port = 2
            else:
                dst_port = 3

        else:
            src_port = 0
            dst_port = 0
        src_port_array.append(src_port)
        dst_port_array.append(dst_port)

    row = (row + arp_array + llc_array + ip_array + icmp_array + icmpv6_array + eapol_array + tcp_array + udp_array
           + http_array + https_array + dhcp_array + bootp_array + ssdp_array + dns_array + mdns_array + ntp_array
           + length_array + ip_change_array + src_port_array + dst_port_array)
    return row


file_index = {}

def set_index(begin_index, folder_path):
    file_paths = glob.glob(os.path.join(folder_path, '**'), recursive=True)
    i = begin_index
    for file_path in file_paths:
        if os.path.isfile(file_path):
            file_index[file_path] = i
            i += 1
    return i

def generate_map():
    i = 0
    # Type 1: Aria
    i = set_index(i, "../captures_IoT-Sentinel/Aria")
    # Type 2: D-LinkCam
    i = set_index(i, "../captures_IoT-Sentinel/D-LinkCam")
    # Type 3: D-LinkDayCam
    i = set_index(i, "../captures_IoT-Sentinel/D-LinkDayCam")
    # Type 4: D-LinkDoorSensor
    i = set_index(i, "../captures_IoT-Sentinel/D-LinkDoorSensor")
    # Type 5: D-LinkHomeHub
    i = set_index(i, "../captures_IoT-Sentinel/D-LinkHomeHub")
    # Type 6: D-LinkSensor
    i = set_index(i, "../captures_IoT-Sentinel/D-LinkSensor")
    # Type 7: D-LinkSiren
    i = set_index(i, "../captures_IoT-Sentinel/D-LinkSiren")
    # Type 8: D-LinkSwitch
    i = set_index(i, "../captures_IoT-Sentinel/D-LinkSwitch")
    # Type 9: D-LinkWaterSensor
    i = set_index(i, "../captures_IoT-Sentinel/D-LinkWaterSensor")
    # Type 10: EdimaxCam
    i = set_index(i, "../captures_IoT-Sentinel/EdimaxCam1")
    i = set_index(i, "../captures_IoT-Sentinel/EdimaxCam2")
    # Type 11: EdimaxPlug1101W
    i = set_index(i, "../captures_IoT-Sentinel/EdimaxPlug1101W")
    # Type 12: EdimaxPlug2101W
    i = set_index(i, "../captures_IoT-Sentinel/EdimaxPlug2101W")
    # Type 13: EdnetCam
    i = set_index(i, "../captures_IoT-Sentinel/EdnetCam1")
    i = set_index(i, "../captures_IoT-Sentinel/EdnetCam2")
    # Type 14: EdnetGateway
    i = set_index(i, "../captures_IoT-Sentinel/EdnetGateway")
    # Type 15: HomeMaticPlug
    i = set_index(i, "../captures_IoT-Sentinel/HomeMaticPlug")
    # Type 16: HueBridge
    i = set_index(i, "../captures_IoT-Sentinel/HueBridge")
    # Type 17: HueSwitch
    i = set_index(i, "../captures_IoT-Sentinel/HueSwitch")
    # Type 18: iKettle2
    i = set_index(i, "../captures_IoT-Sentinel/iKettle2")
    # Type 19: Lightify
    i = set_index(i, "../captures_IoT-Sentinel/Lightify")
    # Type 20: MAXGateway
    i = set_index(i, "../captures_IoT-Sentinel/MAXGateway")
    # Type 21: SmarterCoffee
    i = set_index(i, "../captures_IoT-Sentinel/SmarterCoffee")
    # Type 22: TP-LinkPlugHS100
    i = set_index(i, "../captures_IoT-Sentinel/TP-LinkPlugHS100")
    # Type 23: TP-LinkPlugHS110
    i = set_index(i, "../captures_IoT-Sentinel/TP-LinkPlugHS110")
    # Type 24: WeMoInsightSwitch
    i = set_index(i, "../captures_IoT-Sentinel/WeMoInsightSwitch")
    # Type 25: WeMoLink
    i = set_index(i, "../captures_IoT-Sentinel/WeMoLink")
    # Type 26: WeMoSwitch
    i = set_index(i, "../captures_IoT-Sentinel/WeMoSwitch")
    # Type 27: Withings
    i = set_index(i, "../captures_IoT-Sentinel/Withings")


# generate_map()
# print(file_index)

# generate main dataset
'''
rows = []

def traverse_folder(type, folder_path):
    file_paths = glob.glob(os.path.join(folder_path, '**'), recursive=True)
    for file_path in file_paths:
        if os.path.isfile(file_path):
            # 对文件进行操作，例如打印文件路径
            # print(file_path)
            rows.append(pcap2vec(type, file_path))

# Type 1: Aria
traverse_folder(1, "../captures_IoT-Sentinel/Aria")
# Type 2: D-LinkCam
traverse_folder(2, "../captures_IoT-Sentinel/D-LinkCam")
# Type 3: D-LinkDayCam
traverse_folder(3, "../captures_IoT-Sentinel/D-LinkDayCam")
# Type 4: D-LinkDoorSensor
traverse_folder(4, "../captures_IoT-Sentinel/D-LinkDoorSensor")
# Type 5: D-LinkHomeHub
traverse_folder(5, "../captures_IoT-Sentinel/D-LinkHomeHub")
# Type 6: D-LinkSensor
traverse_folder(6, "../captures_IoT-Sentinel/D-LinkSensor")
# Type 7: D-LinkSiren
traverse_folder(7, "../captures_IoT-Sentinel/D-LinkSiren")
# Type 8: D-LinkSwitch
traverse_folder(8, "../captures_IoT-Sentinel/D-LinkSwitch")
# Type 9: D-LinkWaterSensor
traverse_folder(9, "../captures_IoT-Sentinel/D-LinkWaterSensor")
# Type 10: EdimaxCam
traverse_folder(10, "../captures_IoT-Sentinel/EdimaxCam1")
traverse_folder(10, "../captures_IoT-Sentinel/EdimaxCam2")
# Type 11: EdimaxPlug1101W
traverse_folder(11, "../captures_IoT-Sentinel/EdimaxPlug1101W")
# Type 12: EdimaxPlug2101W
traverse_folder(12, "../captures_IoT-Sentinel/EdimaxPlug2101W")
# Type 13: EdnetCam
traverse_folder(13, "../captures_IoT-Sentinel/EdnetCam1")
traverse_folder(13, "../captures_IoT-Sentinel/EdnetCam2")
# Type 14: EdnetGateway
traverse_folder(14, "../captures_IoT-Sentinel/EdnetGateway")
# Type 15: HomeMaticPlug
traverse_folder(15, "../captures_IoT-Sentinel/HomeMaticPlug")
# Type 16: HueBridge
traverse_folder(16, "../captures_IoT-Sentinel/HueBridge")
# Type 17: HueSwitch
traverse_folder(17, "../captures_IoT-Sentinel/HueSwitch")
# Type 18: iKettle2
traverse_folder(18, "../captures_IoT-Sentinel/iKettle2")
# Type 19: Lightify
traverse_folder(19, "../captures_IoT-Sentinel/Lightify")
# Type 20: MAXGateway
traverse_folder(20, "../captures_IoT-Sentinel/MAXGateway")
# Type 21: SmarterCoffee
traverse_folder(21, "../captures_IoT-Sentinel/SmarterCoffee")
# Type 22: TP-LinkPlugHS100
traverse_folder(22, "../captures_IoT-Sentinel/TP-LinkPlugHS100")
# Type 23: TP-LinkPlugHS110
traverse_folder(23, "../captures_IoT-Sentinel/TP-LinkPlugHS110")
# Type 24: WeMoInsightSwitch
traverse_folder(24, "../captures_IoT-Sentinel/WeMoInsightSwitch")
# Type 25: WeMoLink
traverse_folder(25, "../captures_IoT-Sentinel/WeMoLink")
# Type 26: WeMoSwitch
traverse_folder(26, "../captures_IoT-Sentinel/WeMoSwitch")
# Type 27: Withings
traverse_folder(27, "../captures_IoT-Sentinel/Withings")


df = DataFrame(rows, columns=['Type',
                                'ARP_1', 'ARP_2', 'ARP_3', 'ARP_4', 'ARP_5', 'ARP_6', 'ARP_7', 'ARP_8', 'ARP_9',
                                'ARP_10', 'ARP_11', 'ARP_12',
                                'LLC_1', 'LLC_2', 'LLC_3', 'LLC_4', 'LLC_5', 'LLC_6', 'LLC_7', 'LLC_8', 'LLC_9',
                                'LLC_10', 'LLC_11', 'LLC_12',
                                'IP_1', 'IP_2', 'IP_3', 'IP_4', 'IP_5', 'IP_6', 'IP_7', 'IP_8', 'IP_9',
                                'IP_10', 'IP_11', 'IP_12',
                                'ICMP_1', 'ICMP_2', 'ICMP_3', 'ICMP_4', 'ICMP_5', 'ICMP_6', 'ICMP_7', 'ICMP_8',
                                'ICMP_9', 'ICMP_10', 'ICMP_11', 'ICMP_12',
                                'ICMPv6_1', 'ICMPv6_2', 'ICMPv6_3', 'ICMPv6_4', 'ICMPv6_5', 'ICMPv6_6', 'ICMPv6_7',
                                'ICMPv6_8', 'ICMPv6_9', 'ICMPv6_10', 'ICMPv6_11', 'ICMPv6_12',
                                'EAPOL_1', 'EAPOL_2', 'EAPOL_3', 'EAPOL_4', 'EAPOL_5', 'EAPOL_6', 'EAPOL_7',
                                'EAPOL_8', 'EAPOL_9', 'EAPOL_10', 'EAPOL_11', 'EAPOL_12',
                                'TCP_1', 'TCP_2', 'TCP_3', 'TCP_4', 'TCP_5', 'TCP_6', 'TCP_7', 'TCP_8', 'TCP_9',
                                'TCP_10', 'TCP_11', 'TCP_12',
                                'UDP_1', 'UDP_2', 'UDP_3', 'UDP_4', 'UDP_5', 'UDP_6', 'UDP_7', 'UDP_8', 'UDP_9',
                                'UDP_10', 'UDP_11', 'UDP_12',
                                'HTTP_1', 'HTTP_2', 'HTTP_3', 'HTTP_4', 'HTTP_5', 'HTTP_6', 'HTTP_7', 'HTTP_8',
                                'HTTP_9', 'HTTP_10', 'HTTP_11', 'HTTP_12',
                                'HTTPS_1', 'HTTPS_2', 'HTTPS_3', 'HTTPS_4', 'HTTPS_5', 'HTTPS_6', 'HTTPS_7', 'HTTPS_8',
                                'HTTPS_9', 'HTTPS_10', 'HTTPS_11', 'HTTPS_12',
                                'DHCP_1', 'DHCP_2', 'DHCP_3', 'DHCP_4', 'DHCP_5', 'DHCP_6', 'DHCP_7', 'DHCP_8',
                                'DHCP_9', 'DHCP_10', 'DHCP_11', 'DHCP_12',
                                'BOOTP_1', 'BOOTP_2', 'BOOTP_3', 'BOOTP_4', 'BOOTP_5', 'BOOTP_6', 'BOOTP_7', 'BOOTP_8',
                                'BOOTP_9', 'BOOTP_10', 'BOOTP_11', 'BOOTP_12',
                                'SSDP_1', 'SSDP_2', 'SSDP_3', 'SSDP_4', 'SSDP_5', 'SSDP_6', 'SSDP_7', 'SSDP_8',
                                'SSDP_9', 'SSDP_10', 'SSDP_11', 'SSDP_12',
                                'DNS_1', 'DNS_2', 'DNS_3', 'DNS_4', 'DNS_5', 'DNS_6', 'DNS_7', 'DNS_8', 'DNS_9',
                                'DNS_10', 'DNS_11', 'DNS_12',
                                'MDNS_1', 'MDNS_2', 'MDNS_3', 'MDNS_4', 'MDNS_5', 'MDNS_6', 'MDNS_7', 'MDNS_8',
                                'MDNS_9', 'MDNS_10', 'MDNS_11', 'MDNS_12',
                                'NTP_1', 'NTP_2', 'NTP_3', 'NTP_4', 'NTP_5', 'NTP_6', 'NTP_7', 'NTP_8', 'NTP_9',
                                'NTP_10', 'NTP_11', 'NTP_12',
                                'length_1', 'length_2', 'length_3', 'length_4', 'length_5', 'length_6', 'length_7',
                                'length_8', 'length_9', 'length_10', 'length_11', 'length_12',
                                'dst ip change_1', 'dst ip change_2', 'dst ip change_3', 'dst ip change_4',
                                'dst ip change_5', 'dst ip change_6', 'dst ip change_7', 'dst ip change_8',
                                'dst ip change_9', 'dst ip change_10', 'dst ip change_11', 'dst ip change_12',
                                'src port_1', 'src port_2', 'src port_3', 'src port_4', 'src port_5', 'src port_6',
                                'src port_7', 'src port_8', 'src port_9', 'src port_1', 'src port_11', 'src port_12',
                                'dst port_1', 'dst port_2', 'dst port_3', 'dst port_4', 'dst port_5', 'dst port_6',
                                'dst port_7', 'dst port_8', 'dst port_9', 'dst port_10', 'dst port_11', 'dst port_12'])
df.to_csv('dataset.csv', index = False)
'''
