#!/usr/bin/python3
from arp import continuous_arp
from auto_bro import deploy_bro


def main():
    
    deploy_bro()
    continuous_arp()
    return 

main()
