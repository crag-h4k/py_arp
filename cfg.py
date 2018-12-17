#!/usr/bin/python3
from datetime import datetime

ARP_JSON = './scans/arp_results_' + datetime.now().strftime('%d_%b_%y') + '.json'
ARP_CSV = './scans/arp_results_' + datetime.now().strftime('%d_%b_%y') + '.csv'
ARP_DELAY = 30

IFACE = 'eth0'
