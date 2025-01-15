from scapy.all import *
from pandas import DataFrame
import math
import random
import glob
import pandas as pd
from data_process import pcap2vec
from data_process import file_index
from data_process import generate_map
from dim_reduce import principal_components
from classfier import train_classifier
# from classfier import accuracys


types = ['Aria',
         'D-LinkCam',
         'D-LinkDayCam',
         'D-LinkDoorSensor',
         'D-LinkHomeHub',
         'D-LinkSensor',
         'D-LinkSiren',
         'D-LinkSwitch',
         'D-LinkWaterSensor',
         'EdimaxCam',
         'EdimaxPlug1101W',
         'EdimaxPlug2101W',
         'EdnetCam',
         'EdnetGateway',
         'HomeMaticPlug',
         'HueBridge',
         'HueSwitch',
         'iKettle2',
         'Lightify',
         'MAXGateway',
         'SmarterCoffee',
         'TP-LinkPlugHS100',
         'TP-LinkPlugHS110',
         'WeMoInsightSwitch',
         'WeMoLink',
         'WeMoSwitch',
         'Withings']

features = ['ARP_1', 'ARP_2', 'ARP_3', 'ARP_4', 'ARP_5', 'ARP_6', 'ARP_7', 'ARP_8', 'ARP_9',
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
            'dst port_7', 'dst port_8', 'dst port_9', 'dst port_10', 'dst port_11', 'dst port_12']
def device_classify(file_name):
    data = pcap2vec(0, file_name)
    data = data[1:]
    print("original data:")
    print(data)

    generate_map()
    num = file_index[file_name]
    # print(num)

    df = pd.read_csv('components.csv', header=0, index_col=0)  # 读取数据
    data = df.values.tolist()
    X = [row[:-1] for row in data]
    X1 = []
    X1.append(X[num])
    print("principal components:")
    print(X1)
    pred_results = []

    RFs = []

    for i in range(1, 28):
        RF = train_classifier(i)
        RFs.append(RF)
    # print(X1)
    pred_results = []
    #print("accuracy:")
    #print(accuracys)

    for i in range(0, 27):
        y1_pred = RFs[i].predict(X1)
        pred_results.append(y1_pred[0])

    print("predicted results:")
    print(pred_results)
    result = -1
    for i in range(0, 27):
        if pred_results[i] == 1.0:
            result = i
            break

    print("classification result:")
    print(result)
    return result

# device_classify("../captures_IoT-Sentinel/EdimaxCam1/Setup-C-1-STA.pcap")
# /Users/zhouxy/Desktop/毕设/captures_IoT-Sentinel/WeMoInsightSwitch/Setup-A-7-STA.pcap

