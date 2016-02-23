#!/usr/bin/python
__author__ = 'Adrian Puente Z. <apuente@medallia.com>'
__company__ = 'Hackarandas Inc.'

import os
import sys
import json
import urllib
import unirest
import argparse
import configparser

from time import strftime


def printMessage(strMsg): print ("[*] %s" % strMsg)


def printSuccess(strMsg): print ("[+] %s" % strMsg)


def printError(strMsg): print ("[!] %s" % strMsg)


def ts_readconfig(section='default'):
    """
    This function reads the config file where the API key is located and returns it.

    :param section: used to select the section of the config file. By default 'default' is used.
    :type section: str
    :return: the API key for authentication.
    """
    config = configparser.ConfigParser()
    home_dir = os.environ['HOME']
    config_file = home_dir + '/.threatstack/config'
    config.read(config_file)
    return config.get(section, 'key')


def ts_getagents(key):
    """
    This function tries to login to Threat Stack and return an authentication token.


    :param key: used to select the section of the config file. By default 'default' is used.
    :type key: str
    :return: authentication token.
    """
    url = 'https://app.threatstack.com/api/v1/agents'
    hders = {'Authorization': key}
    c_api = unirest.get(url, headers=hders)
    return c_api.raw_body


def main():
    now = strftime("%Y%m%d-%H%M%S")
    strDesc = '''Threat Stack Command Line Tool.'''

    parser = argparse.ArgumentParser(description=strDesc)
    parser.add_argument("-g", "--list-agents",
                        action="store_true",
                        help="lists all the agents in the organization.")
    parser.add_argument("-i", "--list-alerts",
                        action="store_true",
                        help="lists all the agents in the organization.")
    parser.add_argument("-p", "--list-policies",
                        action="store_true",
                        help="lists all the agents in the organization.")
    parser.add_argument("-o", "--list-organizations",
                        action="store_true",
                        help="lists all the agents in the organization.")
    parser.add_argument("-l", "--list-logs",
                        action="store_true",
                        help="lists all the agents in the organization.")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()

    if args.list_agents:
        print ts_getagents(ts_readconfig())


if __name__ == "__main__": main()
