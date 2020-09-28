#!/usr/bin/env python3

import sys,os,getopt
import traceback
import os
import fcntl
import json
import requests
import time
from datetime import datetime

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

from html.parser import HTMLParser

class integration(object):

    system_JSON_field_mappings = {
        'created_at': 'timestamp',
        'audit_log_user' : 'user_name',
        'audit_log_type' : 'log_type',
        'audit_log_id' : 'log_id',
    }

    JSON_field_mappings = {
        'id': 'event_id',
        'computer_hostname': 'client_hostname',
        'computer_external_ip': 'external_ip',
        'file_file_name': 'file_name',
        'computer_network_addresses_ips':'client_ip',
        'computer_network_addresses_macs':'client_address',
    }

    def ciscoamp_getEvents(self):
        params = {'start_date':self.last_run}
        response = self.ciscoamp_request('/v1/events', params = params)
        r_json = response.json()
        if 'data' not in r_json.keys():
            self.ds.log('ERROR', "data missing in response")
            return None

        events = r_json['data']
        extra_events = []
        for event in events:
            if 'computer' in event.keys():
                if 'links' in event['computer'].keys():
                    for key in event['computer']['links'].keys():
                        event['computer_links_' + key] = event['computer']['links'][key]
                    del event['computer']['links']
                for key in event['computer'].keys():
                    event['computer_' + key] = event['computer'][key]
                del event['computer']
            if 'file' in event.keys():
                if 'parent' in event['file'].keys():
                    if 'identity' in event['file']['parent'].keys():
                        file_parent_identity_sha256 = event['file']['parent']['identity']['sha256']
                        del event['file']['parent']['identity']
                    for key in event['file']['parent'].keys():
                        event['file_parent_' + key] = event['file']['parent'][key]
                    del event['file']['parent']
                if 'identity' in event['file'].keys():
                    file_identity_sha256 = event['file']['identity']['sha256']
                    del event['file']['identity']
                for key in event['file'].keys():
                    event['file_' + key] = event['file'][key]
                del event['file']

            if 'computer_network_addresses' in event.keys():
                ips = []
                macs = []
                for entry in event['computer_network_addresses']:
                    ips.append(entry['ip'])
                    macs.append(entry['mac'])
                event['computer_network_addresses_ips'] = ips
                event['computer_network_addresses_macs'] = macs
                del event['computer_network_addresses']

            event['message'] = "Event ID: " + str(event['id']) + " Event Type: " + event['event_type']
            event['category'] = 'Event'
            if 'vulnerabilities' in event.keys() and event['vulnerabilities'] != None:
                c_events = event['vulnerabilities']
                for c_event in c_events:
                    c_event['category'] = 'Event'
                    c_event['message'] = "Event ID: " + str(event['id']) + " vulnerabilities event"
                    c_event['id'] = event['id']
                    #c_event['timestamp'] = event['timestamp']
                    extra_events.append(c_event)
                del event['vulnerabilities']

        total_events = events + extra_events
        return total_events

    def ciscoamp_getAuditLogs(self):
        params = {'start_time':self.last_run, 'end_time':self.current_run}
        response = self.ciscoamp_request('/v1/audit_logs', params = params)
        r_json = response.json()
        if 'data' not in r_json.keys():
            self.ds.log('ERROR', "data missing in response")
            return None
        events = r_json['data']
        for event in events:
            event['message'] = "Audit Log Type: " + event['audit_log_type']
        return events


    def ciscoamp_request(self, path, params = None, verify=True, proxies=None):
        url = self.url + path
        self.ds.log('INFO', "Attempting to connect to url: " + url + " with params: " + json.dumps(params))
        try:
            response = requests.get(url, auth=(self.api_client_id, self.api_key), params = params, verify=verify, proxies=proxies)

        except Exception as e:
            self.ds.log('ERROR', "Exception in ensilo_request: {0}".format(str(e)))
            return None
        if not response or response.status_code != 200:
            self.ds.log('ERROR', "Received unexpected " + str(response) + " response from enSilo Server {0}.".format(url))
            self.ds.log('ERROR', "Exiting due to unexpected response.")
            sys.exit(0)
        return response



    def ciscoamp_main(self): 

        self.url = self.ds.config_get('ciscoamp', 'server_url')
        self.api_client_id = self.ds.config_get('ciscoamp', 'api_client_id')
        self.api_key = self.ds.config_get('ciscoamp', 'api_key')
        self.state_dir = self.ds.config_get('ciscoamp', 'state_dir')
        self.time_offset = int(self.ds.config_get('ciscoamp', 'time_offset'))
        self.last_run = self.ds.get_state(self.state_dir)
        self.time_format = "%Y-%m-%dT%H:%M:%S+00:00"
        current_time = time.time()
        if self.last_run == None:
            self.last_run = (datetime.utcfromtimestamp(60 * ((current_time - (self.time_offset * 10000)) // 60))).strftime(self.time_format)
        self.current_run = (datetime.utcfromtimestamp(current_time - self.time_offset)).strftime(self.time_format)

        events = self.ciscoamp_getEvents()

        system_events = self.ciscoamp_getAuditLogs()

        if events == None:
            self.ds.log('INFO', "There are no event logs to send")
        else:
            self.ds.log('INFO', "Sending {0} event logs".format(len(events)))
            for log in events:
                self.ds.writeJSONEvent(log, JSON_field_mappings = self.JSON_field_mappings, flatten = False)

        if system_events == None:
            self.ds.log('INFO', "There are no system event logs to send")
        else:
            self.ds.log('INFO', "Sending {0} system event logs".format(len(system_events)))
            for log in system_events:
                log['category'] = "system-events"
                self.ds.writeJSONEvent(log, JSON_field_mappings = self.system_JSON_field_mappings)


        self.ds.set_state(self.state_dir, self.current_run)
        self.ds.log('INFO', "Done Sending Notifications")


    def run(self):
        try:
            pid_file = self.ds.config_get('ciscoamp', 'pid_file')
            fp = open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.log('ERROR', "An instance is already running")
                # another instance is running
                sys.exit(0)
            self.ciscoamp_main()
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return
    
    def usage(self):
        print
        print(os.path.basename(__file__))
        print
        print('  No Options: Run a normal cycle')
        print
        print('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print('        in the current directory')
        print
        print('  -l    Log to stdout instead of syslog Local6')
        print
        print('  -g    Authenticate to Get Token then exit')
        print
    
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
        self.get_token = None
    
        try:
            opts, args = getopt.getopt(argv,"htlg")
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
            elif opt in ("-g"):
                self.get_token = True
    
        try:
            self.ds = DefenseStorm('ciscoampEventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:])
    i.run()

