#!/usr/bin/python

import requests
import json
import os
import sys
import argparse
import getpass

# don't care about insecure certs (maybe you do, comment out if so)
requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

# where we login to get a bearer token
auth_uri = '/api/v1/auth/login'
cloud_token_url = 'https://login.cribl.cloud/oauth/token'

# define the collector URI
jobs_uri  = '/api/v1/m/<WG>/jobs'

#############################
# prompt for password if one is not supplied
class Password:
    # if password is provided, use it. otherwise prompt
    DEFAULT = 'Prompt if not specified'

    def __init__(self, value):
        if value == self.DEFAULT:
            value = getpass.getpass('Password: ')
        self.value = value

    def __str__(self):
        return self.value

#############################
# parse the command args
def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-D', '--debug', help='extra output',action='store_true')
    parser.add_argument('-l', '--leader', help='Leader URL, http(s)://leader:port',required=True)
    parser.add_argument('-u', '--username', help='API token id (cloud) or user id (self-managed)',required=True)
    parser.add_argument('-g', '--group', type=str, help="Target worker group", required=True)
    parser.add_argument('-c', '--collector', type=str, help="Target collector ID", required=False) 
    parser.add_argument('-f', '--filter', type=str, help="Filter to use, eg \"_raw.includes('1.2.3.4')\"", required=False) 
    parser.add_argument('-p', '--pipe', type=str, help="Pipeline ID to process with (optional)", required=False)
    parser.add_argument('-E', '--earliest', type=str, help="Earliest time: epoch or relative", required=False)
    parser.add_argument('-L', '--latest', type=str, help="Latest time: now, epoch or relative", required=False)
    parser.add_argument('-j', '--json', type=str, help="File path with the json payload template", required=True)
    parser.add_argument('-P', '--password', type=Password, help='Specify password or secret, or get prompted for it',default=Password.DEFAULT)
    args = parser.parse_args()
    return args

# some debug notes
def debug_log(log_str):
    if args.debug:
        print("DEBUG: {}".format(log_str))

#############################
# get logged in for self-managed instances
def auth(leader_url,un,pw):
    # get logged in and grab a token
    header = {'accept': 'application/json', 'Content-Type': 'application/json'}
    login = '{"username": "' + un + '", "password": "' + pw + '"}'
    r = requests.post(leader_url+auth_uri,headers=header,data=login,verify=False)
    if (r.status_code == 200):
        res = r.json()
        return res["token"]
    else:
        print("Login failed, terminating")
        print(str(r.json()))
        sys.exit()

# post the collector request
def post_collector(leader_url,jsondata, btoken):
    uri = jobs_uri.replace("<WG>", args.group)
    header = {'accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + btoken}
    debug_log("leader: " + leader_url)
    debug_log("uri: " + uri)
    #leader_url = "http://localhost:12345"
    r = requests.post(leader_url+uri,headers=header,json=jsondata,verify=False)
    if (r.status_code == 200):
        res = r.json()
        return res
    else:
        print("POST failed, terminating")
        print(str(r.json()))
        sys.exit()

#############################
# read and optinally modify the template file
def read_json_template(args):
    with open(args.json, "r") as f:
        file_data = f.read()
    json_data = json.loads(file_data)
    if 'collector' in args and args.collector != None:
        json_data['id'] = args.collector
    if 'filter' in args and args.filter != None:
        json_data['run']['expression'] = args.filter
    if 'pipe' in args and args.pipe != None:
        json_data['input']['pipeline'] = args.pipe
    if 'earliest' in args and args.earliest != None:
        json_data['run']['earliest'] = args.earliest
    if 'latest' in args and args.latest != None:
        json_data['run']['latest'] = args.latest
    return(json_data)

#############################
# get logged in for cloud
def cloud_auth(client_id,client_secret):
    # get logged in and grab a token
    header = {'accept': 'application/json', 'Content-Type': 'application/json'}
    login = '{"grant_type": "client_credentials","client_id": "' + client_id + '", "client_secret": "' + client_secret + '","audience":"https://api.cribl.cloud"}'
    r = requests.post(cloud_token_url,headers=header,data=login,verify=False)
    if (r.status_code == 200):
        res = r.json()
        debug_log("Bearer token: " + res["access_token"])
        return res["access_token"]
    else:
        print("Login failed, terminating")
        print(str(r.json()))
        sys.exit()


#############################
# main 
if __name__ == "__main__":
    args = parse_args()
    
    # get logged in
    if args.leader.find('cribl.cloud') > 0:
        bearer_token = cloud_auth(args.username,str(args.password))
    else:
        bearer_token = auth(args.leader,args.username, str(args.password))
    
    # read the payload template file
    debug_log("reading the collector payload json")
    template = read_json_template(args)
    debug_log(template)

    # send the payload
    debug_log("sending payload to collector endpoint")
    debug_log(template)
    results = post_collector(args.leader,template, bearer_token)
    debug_log(results)
    print('job id: ' + results['items'][0])
