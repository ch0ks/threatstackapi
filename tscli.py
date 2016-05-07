#!/usr/bin/python
__author__ = 'Adrian Puente Z. <ch0ks _at_ hackarandas _dot_ com>'
__company__ = 'Hackarandas Inc.'

import os
import sys
import json
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


def ts_apiclient(key, api_name):
    """
    This function is the actual client that makes the connections and retrieve the information.

    :param key: the authentication token.
    :type key: str
    :param api_name: the API's name that we want to access.
    :type api_name: str
    :return: the infomration retrieved in dictionary format,
    """
    url = 'https://app.threatstack.com/api/v1/' + api_name
    headers = {'Authorization': key}
    response = unirest.get(url, headers=headers)
    response_raw = response.raw_body
    data = json.loads(response_raw)
    return data

def ts_getagents(auth_token):
    """
    This function is a wrapper for the agents. It will validate that the parameters are the correct ones and
    request the information from the client.

    These are the parameters that you can pass to the function.:

    Parameter | Default | Description
    --------- | ------- | -----------
    organization | Owners | Setting the id of an organization you belong allows retrieve data in that context
    page | 0 | Set the page to retrieve related to the count
    count | 20 | Set the limit/total of entries to receive per page
    start | A week ago | Set the start of the date range
    end | Today | Set the end of the date range

    :param auth_token: used to select the section of the config file. By default 'default' is used.
    :type auth_token: str
    :return: authentication token.
    """
    data = ts_apiclient(auth_token, 'agents')
    if data:
        for agent in data:
            printSuccess("Endpoint: " + agent[u'hostname'])
            for key in agent.keys():
                printSuccess("\t" + unicode(key) + ": " + unicode(agent[key]))
    return data


def ts_getalerts(auth_token):
    """
    This function is a wrapper for the agents. It will validate that the parameters are the correct ones and
    request the information from the client.

    These are the parameters that you can pass to the function.:

    Parameter | Default | Description
    --------- | ------- | -----------
    organization | Owners | Setting the id of an organization you belong allows retrieve data in that context
    page | 0 | Set the page to retrieve related to the count
    count | 20 | Set the limit/total of entries to receive per page
    start | A week ago | Set the start of the date range
    end | Today | Set the end of the date range

    :param auth_token: used to select the section of the config file. By default 'default' is used.
    :type auth_token: str
    :return: authentication token.
    """
    data = ts_apiclient(auth_token, 'agents')
    return data

def ts_policies(auth_token):
    """
    This function is a wrapper for the api_client to retrieve the policies. 
    It will validate that the parameters are the correct ones and request the 
    information from the client.

    These are the parameters that you can pass to the function.:

    :param auth_token: used to select the section of the config file. By default 'default' is used.
    :type auth_token: str
    :return: authentication token.
    """
    data = ts_apiclient(auth_token, 'policies')
    return data

def ts_printpolicies(Policies):
    """
    This function retrieves all the policies and prints all the details in a ordely manner.

    These are the parameters that you can pass to the function.:

    :param auth_token: used to select the section of the config file. By default 'default' is used.
    :type auth_token: str
    :return: authentication token.
    """
    for policy in Policies:
      printSuccess("Name: %s, Number of Alerts %s" %(policy['name'] , policy['alert_rule_count']))
      for alert_policy in policy['alert_policy']:
        #printSuccess("-------------")
        printSuccess("\tTitle: %s" %alert_policy['title'])
        for key in alert_policy.keys():
          if key != 'exclusions' and key != 'title': printSuccess("\t\t%s: %s" %(key,alert_policy[key]))
        printSuccess("\t\tExclusions:")
        if alert_policy['exclusions']: printSuccess("\t\t\t%s" %'\n[+]\t\t\t'.join(alert_policy['exclusions']))

def ts_dumppolicies(Policies):
    """
    This function retrieves all the policies and creates the directory structure and dumps the policies
    in markup format so it can be exported to github.

    These are the parameters that you can pass to the function.:

    :param auth_token: used to select the section of the config file. By default 'default' is used.
    :type auth_token: str
    :return: authentication token.
    """
    for policy in Policies:
      directory=policy['name'].strip()
      if not os.path.exists(directory):
        os.makedirs(directory)
        printSuccess("Directory %s does not exists, created." %directory)
      else: printSuccess("Directory %s exists, populating.")

      for alert_policy in policy['alert_policy']:
        filename=alert_policy['title']+'.md'.strip()
        mdfile="# %s" %alert_policy['title']
        mdfile=mdfile+"%s\n\n" %alert_policy['description']
        mdfile=mdfile+"## Enabled\n\n```\n%s\n```\n\n" %alert_policy['enabled']
        mdfile=mdfile+"## Severity\n\n```\n%s\n```\n\n" %alert_policy['severity']
        mdfile=mdfile+"## Filter\n\n```\n%s\n```\n\n" %alert_policy['filter']
        mdfile=mdfile+"## Supression Rules\n\n```\n%s\n```\n\n" %'\n'.join(alert_policy['exclusions'])
        printSuccess("\tCreating file policy: %s" %filename)
        f = open(directory+'/'+filename, 'w')
        f.write(mdfile)
        f.close()

def main():
    now = strftime("%Y%m%d-%H%M%S")
    strDesc = '''Threat Stack Command Line Tool.'''

    parser = argparse.ArgumentParser(description=strDesc)
    parser.add_argument("-g", "--list-agents",
                        action="store_true",
                        help="lists all the agents in the organization")
    parser.add_argument("-i", "--list-alerts",
                        action="store_true",
                        help="lists all the agents in the organization")
    parser.add_argument("-p", "--list-policies",
                        action="store_true",
                        help="lists all the agents in the organization")
    parser.add_argument("-o", "--list-organizations",
                        action="store_true",
                        help="lists all the agents in the organization")
    parser.add_argument("-l", "--list-logs",
                        action="store_true",
                        help="lists all the agents in the organization")
    parser.add_argument("-d", "--dump-policies",
                        action="store_true",
                        help="dumps all the policies in the organization into individual md files")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()

    if args.list_agents:
        ts_getagents(ts_readconfig())
    elif args.list_alerts:
        ts_getalerts(ts_readconfig())
    elif args.list_policies:
        ts_printpolicies(ts_policies(ts_readconfig()))
    elif args.list_organizations:
        printError("Not yet implemented")
    elif args.list_logs:
        printError("Not yet implemented")
    elif args.dump_policies:
        ts_dumppolicies(ts_policies(ts_readconfig()))

if __name__ == "__main__": main()
