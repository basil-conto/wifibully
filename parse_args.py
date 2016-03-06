#!/usr/bin/python

import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='Start wifibully')
    parser.add_argument('-i', '--interface', required=True,
                        help='monitoring interface used to inject packets')
    parser.add_argument('-e', '--essid', required=True,
                        help='SSID of the target AP')
    parser.add_argument('-w', '--whitelist', nargs='+',
                        help="list of MAC addresses that shouldn't be targeted")

    return parser.parse_args()
