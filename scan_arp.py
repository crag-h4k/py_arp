from scapy.all import srp, Ether, ARP, conf, arping
from time import sleep
from datetime import datetime
from json import dump
from requests import get
from pprint import pprint

from Target import Target
from utils import make_subnets, target_to_json
from cfg import ARP_DELAY, ARP_JSON, ARP_CSV, IFACE
from auth import hook_url
from send_slack import send_msg


def make_target(ip):
    ans, unans = arping(ip)
    conf.verb = 0
    for snd,rcv in ans:
        ipv4 = ip
        mac = rcv[Ether].src
        manu = find_vendor(mac)
        return Target(ipv4, mac, manu)

def arp_scan():
    subnets = make_subnets()
    for net in subnets:
        if '\n' in net:
            net = net.strip('\n')
        conf.verb = 0
        ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=net),timeout=2, iface=IFACE, inter=0.1)
        targets = []

        for snd,rcv in ans:
            ipv4 = rcv.sprintf(r'%ARP.psrc%')
            mac = rcv.sprintf(r'%Ether.src%')
            manu = find_vendor(mac)

            T = Target(ipv4, mac, manu)
            send_msg(target_to_json(T), hook_url)
            targets.append(T)

    return targets

def find_vendor(mac):
    #source: https://macvendors.co/api/python
    req = get('http://macvendors.co/api/%s' % mac)
    manu_data = req.json()
    return manu_data

def write_arp_csv(target_arr, fname):

    for T in target_arr:
        text =  str(T.ip) + ',' + str(T.mac) + ',' + str(T.ts) + '\n'
        with open(fname, 'a+') as f:
            f.write(text)

    return

def write_arp_json(target_arr, fname):
    json_name = 'targets_' + target_arr[0].ipv4
    data = {}
    data[json_name] = []

    for T in target_arr:
        target_info = target_to_json(T)
        pprint(target_info)
        data[json_name].append(target_info)

    with open(fname, 'a+') as f:
        dump(data,f)

    return

if __name__ == '__main__':
    #while True:
    print('init arp scan')
    write_arp_json(arp_scan(), ARP_JSON)
    #write_arp_csv(arp_scan(), ARP_CSV
        #sleep(ARP_DELAY)



