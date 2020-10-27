#!/usr/bin/env python
#
#   Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
#   Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
#   Neither the name of Arista Networks nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ARISTA NETWORKS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
import argparse
import getpass
import hashlib
from logging import error
import re
import socket
import ssl
import sys
from datetime import datetime
from time import sleep
from uuid import uuid4

import urllib3
from cvprac.cvp_client import CvpClient
from cvprac.cvp_api import CvpApi as cvpApis
from cvprac.cvp_client_errors import CvpClientError
from cvprac.cvp_client_errors import CvpLoginError

# Work around for unsigned Certificates used in CVP instances
ssl._create_default_https_context = ssl._create_unverified_context



#
# Define command line options for optparse
#
usage = 'usage: %prog [options]'

# Define command line options for argparse
ap = argparse.ArgumentParser()
ap.add_argument(
    "-c",
    "--cvphostname",
    dest="cvphostname",
    action="store",
    required=True,
    help="CVP host name FQDN or IP",
)

ap.add_argument(
    "-u",
    "--cvpusername",
    dest="cvpusername",
    action="store",
    required=True,
    help="CVP username",
)

ap.add_argument(
    "-p",
    "--cvppassword",
    dest="cvppassword",
    action="store",
    required=False,
    default="",
    help="CVP password",
)

ap.add_argument(
    "-d",
    "--debug",
    dest="debug",
    action="store_true",
    help="If debug is set, nothing will actually be sent to CVP and proposed configs are written to terminal",
    default=False,
)

ap.add_argument(
    "-t",
    "--trace",
    dest="trace",
    action="store_true",
    help="If trace is set, alongside actual changes to CVP configlets, there will be trace messages to terminal",
    default=False,
)
ap.add_argument(
    "-e",
    "--executeChange",
    dest="executeChange",
    action="store_true",
    help="If ChangeControl is set, the Created Change Control will be automatically executed",
    default=False,
)

opts = ap.parse_args()

## If no password is passed then ask for it.
if opts.cvppassword == '':
    password =  getpass.getpass(prompt='Password: ', stream=None)
else:
    password = opts.cvppassword

#
# Assign command line options to variables and assign static variables.
#

host = opts.cvphostname
user = opts.cvpusername
debug = opts.debug
trace = opts.trace


class bcolors:
    NORMAL = '\033[0m'
    BOLD = '\033[1m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'

def connect(hostname, username, password, port = 443):
    ''' Connects to a CVP device using user provided credentials from opts.
    '''
    socket.setdefaulttimeout(3)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    client = CvpClient()
    try:
        client.connect([hostname],
                       username,
                       password,
                       protocol="https",
                       port=port)
    
    except CvpLoginError as error:
        timestamp = datetime.now().replace(microsecond=0)
        sys.stderr.write('{} {}ERROR{}: {}.\n'.format(timestamp, bcolors.ERROR, bcolors.NORMAL, error))
        sys.exit(1)

    return client

#
# Needed support functions
#
def checkCli(myConfig):
    newConfig = myConfig

    #
    # Global
    #

    newConfig = re.sub('aaa authorization console','aaa authorization serial-console', newConfig)
    newConfig = re.sub('enable secret','enable password', newConfig)
    newConfig = re.sub('errdisable detect cause link-flap - errdisable detect cause link-change', 'errdisable detect cause link-change', newConfig)
    newConfig = re.sub('ip dhcp smart-relay$', 'ip dhcp relay all-subnets', newConfig)
    newConfig = re.sub('ip dhcp smart-relay global', 'ip dhcp relay all-subnets default', newConfig)
    newConfig = re.sub('ip domain-name', 'dns domain', newConfig)
    newConfig = re.sub('ip http client source-interface', 'ip http client local-interface', newConfig)
    newConfig = re.sub('link state track', 'link tracking group', newConfig)
    newConfig = re.sub('lldp holdtime', 'lldp hold-time', newConfig)
    newConfig = re.sub('lldp reinit', 'lldp timer reinitialization', newConfig)
    newConfig = re.sub('lldp tlv-select', 'lldp tlv transmit', newConfig)
    newConfig = re.sub('ntp source', 'ntp local-interface', newConfig)
    newConfig = re.sub('ptp sync interval', 'ptp sync-message interval', newConfig)
    newConfig = re.sub('service sequence-numbers', 'logging format sequence-numbers', newConfig)
    newConfig = re.sub('sshkey', 'ssh-key', newConfig)
    newConfig = re.sub('vlan internal allocation policy', 'vlan internal order', newConfig)
    newConfig = re.sub('snmp-server source-interface', 'snmp-server local-interface', newConfig)
    newConfig = re.sub('spanning-tree bridge assurance', 'spanning-tree transmit active', newConfig)
    newConfig = re.sub('spanning-tree loopguard default', 'spanning-tree guard loop default', newConfig)
    newConfig = re.sub('spanning-tree portfast bpdufilter default', 'spanning-tree edge-port bpdufilter default', newConfig)
    newConfig = re.sub('spanning-tree portfast bpduguard default', 'spanning-tree edge-port bpduguard default', newConfig)
    newConfig = re.sub('spanning-tree transmit hold-count', 'spanning-tree bpdu tx hold-count', newConfig)
    newConfig = re.sub('spanning-tree vlan ', 'spanning-tree vlan-id ', newConfig)
    newConfig = re.sub('vrf definition', 'vrf instance', newConfig)

    #
    # router bgp
    #

    newConfig = re.sub('peer-group', 'peer group', newConfig)
    newConfig = re.sub('bgp listen limit', 'dynamic peer max', newConfig)
    newConfig = re.sub('fall-over bfd', 'bfd', newConfig)
    newConfig = re.sub('soft-reconfiguration', 'rib-in pre-policy retain', newConfig)
    newConfig = re.sub('transport connection-mode', 'passive', newConfig)

    #
    # router ospf
    #

    newConfig = re.sub('nssa translate type7 always', 'not-so-stubby lsa type-7 convert type-5', newConfig)
    newConfig = re.sub('bfd all-interfaces', 'bfd default', newConfig)
    newConfig = re.sub('ip ospf name-lookup', 'router-id output-format hostnames', newConfig)
    newConfig = re.sub('timers basic', 'timers', newConfig)
    newConfig = re.sub('timers lsa arrival', 'timers lsa rx min interval', newConfig)
    newConfig = re.sub('timers throttle lsa all', 'timers lsa tx delay initial', newConfig)
    newConfig = re.sub('timers throttle spf', 'timers spf delay initial', newConfig)

    #
    # interfaces
    #

    newConfig = re.sub('arp timeout', 'arp aging timeout', newConfig)
    newConfig = re.sub('dot1x max-reauth-req', 'dot1x max-reauth-req', newConfig)
    newConfig = re.sub('ip ospf bfd', 'ip ospf neighbor bfd', newConfig)
    newConfig = re.sub('ip ospf shutdown', 'ip ospf disabled', newConfig)
    newConfig = re.sub('ip pim bfd-instance', 'pim bfd', newConfig)
    newConfig = re.sub('ip pim bsr-border', 'pim bsr border', newConfig)
    newConfig = re.sub('ip pim query-interval', 'pim hello interval', newConfig)
    newConfig = re.sub('ip pim register-source', 'register local-interface', newConfig)
    newConfig = re.sub('ip rip v2-broadcast', 'rip v2 multicast disable', newConfig)
    newConfig = re.sub('ipv6 nd ra suppress', 'ipv6 nd ra disabled', newConfig)
    newConfig = re.sub('ipv6 ospf retransmit-interval', 'ospfv3 ipv6 retransmit-interval', newConfig)
    newConfig = re.sub('isis lsp-interval', 'isis lsp tx interval', newConfig)
    newConfig = re.sub('lacp rate', 'lacp timer', newConfig)
    newConfig = re.sub('link state group', 'link tracking group', newConfig)
    newConfig = re.sub('priority-flow-control mode', 'priority-flow-control', newConfig)
    newConfig = re.sub('private-vlan mapping', 'pvlan mapping', newConfig)
    newConfig = re.sub('snmp trap link-status', 'snmp trap link-change', newConfig)
    newConfig = re.sub('switchport backup interface', 'switchport backup-link', newConfig)
    newConfig = re.sub('switchport port-security maximum', 'switchport port-security mac-address maximum', newConfig)
    newConfig = re.sub('switchport vlan mapping', 'switchport vlan translation', newConfig)
    newConfig = re.sub('vrf forwarding', 'vrf', newConfig)
    newConfig = re.sub('(vrrp [1-9]+) authentication', r'\1' + ' authentication', newConfig)
    newConfig = re.sub('(vrrp [1-9]+) delay reload', r'\1' + ' timers delay reload', newConfig)
    newConfig = re.sub('(vrrp [1-9]+) description', r'\1' + ' session description', newConfig)
    newConfig = re.sub('(vrrp [1-9]+) ip', r'\1' + ' ipv4', newConfig)
    newConfig = re.sub('(vrrp [1-9]+) priority', r'\1' + ' priority-level', newConfig)
    newConfig = re.sub('(vrrp [1-9]+) shutdown', r'\1' + ' disabled', newConfig)
    newConfig = re.sub('(vrrp [1-9]+) timers advertise', r'\1' + ' advertisement interval', newConfig)
    newConfig = re.sub('(vrrp [1-9]+) track', r'\1' + ' tracked-object', newConfig)

    #
    # Class maps, policy maps , control plane, ACL
    #

    newConfig = re.sub('class-map type control-plane', 'class-map type copp', newConfig)
    newConfig = re.sub('policy-map type control-plane', 'policy-map type copp', newConfig)
    newConfig = re.sub('policy-map type qos', 'policy-map type quality-of-service', newConfig)
    newConfig = re.sub('statistics per-entry', 'counters per-entry', newConfig)
    newConfig = re.sub('control-plane', 'system control-plane', newConfig)

    #
    # Community list
    #

    newConfig = re.sub('ip community-list expanded', 'ip community-list regexp', newConfig)
    newConfig = re.sub('ip extcommunity-list expanded', 'ip extcommunity-list regexp', newConfig)
    newConfig = re.sub('ip extcommunity-list standard', 'ip extcommunity-list', newConfig)

    #
    # IGMP
    #

    #   newConfig = re.sub('ip igmp query-max-response-time', 'igmp query-max-response-time', newConfig)
    #   newConfig = re.sub('[\ ]+ip igmp query-max-response-time', '   query-max-response-time', newConfig)
    newConfig = re.sub('ip igmp snooping vlan immediate-leave', 'ip igmp snooping vlan fast-leave', newConfig)
    newConfig = re.sub('ip igmp snooping vlan mrouter', 'ip igmp snooping vlan multicast-router', newConfig)
    newConfig = re.sub('ip igmp snooping vlan static', 'ip igmp snooping vlan member', newConfig)

    #
    # MSDP
    #

    newConfig = re.sub('ip msdp cache-sa-state', '', newConfig)
    newConfig = re.sub('ip msdp default-peer', 'default-peer', newConfig)
    newConfig = re.sub('ip msdp description', 'description', newConfig)
    newConfig = re.sub('ip msdp group-limit', 'sa-limit', newConfig)
    newConfig = re.sub('ip msdp keepalive', 'keepalive', newConfig)
    newConfig = re.sub('ip msdp mesh-group', 'mesh-group', newConfig)
    newConfig = re.sub('ip msdp originator-id', 'originator-id local-interface', newConfig)
    newConfig = re.sub('ip msdp peer', 'peer', newConfig)
    newConfig = re.sub('ip msdp sa-filter in', 'sa filter in', newConfig)
    newConfig = re.sub('ip msdp sa-filter out', 'sa filter out', newConfig)
    newConfig = re.sub('ip msdp sa-limit', 'sa limit', newConfig)
    newConfig = re.sub('ip msdp shutdown', 'disabled', newConfig)
    newConfig = re.sub('ip msdp timer', 'connection retry interval', newConfig)

    #
    # Router PIM
    #

    newConfig = re.sub('ip pim anycast-rp', 'anycast-rp', newConfig)
    newConfig = re.sub('ip pim bfd', 'bfd', newConfig)
    newConfig = re.sub('ip pim log-neighbor-changes', 'log neighbors', newConfig)
    newConfig = re.sub('ip pim neighbor-filter', 'pim neighbor filter', newConfig)
    newConfig = re.sub('ip pim spt-threshold group-list', 'spt threshold match list', newConfig)
    newConfig = re.sub('ip pim ssm range', 'ssm address range', newConfig)


    #
    # router rip
    #

    #    default-metric - metric default (router rip)

    #
    # ISIS
    #

    #passive-interface - passive


    # ccnPeon bgp listen range reconverter from 'peer group' back to 'peer-group' which is invalid syntax.
    # Checks every line in newConfig for 'bgp listen range'. If this exists, just replace 'peer group' with 'peer-group'
    reconvert = ''
    for line in newConfig.splitlines():
        if 'bgp listen range' in line:
            #sys.stderr.write('===========================================================\n\n\n\n')
            #sys.stderr.write('================LINE================\n\n\n\n')
            #sys.stderr.write('===========================================================\n')
            #sys.stderr.write('{}'.format(line))
            line = line.replace('peer group', 'peer-group')
            reconvert += '{}\n'.format(line)
        else:
            reconvert += '{}\n'.format(line)

	
    newConfig = reconvert

    return newConfig

def main():
    if trace:
        timestamp = datetime.now().replace(microsecond=0)
        sys.stderr.write('{} {}INFO:{} Assembling inventory of devices running EOS 4.21 or greater.\n\n\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL))
    
    # Create a connection to a CVP cluster
    cvpclnt = connect(opts.cvphostname, opts.cvpusername, opts.cvppassword)

    if trace:
        sys.stderr.write('===========================================================\n')
        sys.stderr.write('CVP Host   : {}.\n'.format(opts.cvphostname))
        sys.stderr.write('CVP Version: {}.\n'.format(cvpApis(cvpclnt).get_cvp_info()['version']))
        sys.stderr.write('Flags Debug:{}  Trace:{}  ExecuteCCM:{}\n'.format(
            opts.debug, opts.trace, opts.executeChange))
        sys.stderr.write('===========================================================\n')

    # Get a list of devices - cvprac currently only returns provisioned devices
    deviceList = cvpApis(cvpclnt).get_inventory()

    # Parse the device list and extract devices with EOS versions higher than 4.21.x
    upgradedDevices = []
    for device in deviceList:
        if debug:
            sys.stderr.write('===========================================================\n')
            sys.stderr.write('Device Data:{} - {} .\n'.format(device['fqdn'], device['key']))
            sys.stderr.write('===========================================================\n')
        if (device['containerName'] != 'Undefined' and int(device['version'].split('.')[1]) >= 21):
            upgradedDevices.append(device)

    sys.stderr.write('\n')
    pendingTasks = []

    # Parse list of EOS 4.21.x+ and find associated configlets
    for device in upgradedDevices:
        if trace:
            sys.stderr.write('===========================================================\n')
            sys.stderr.write('Processing device {}.\n'.format(device['fqdn']))
            sys.stderr.write('===========================================================\n')

        deviceConfiglets = cvpApis(cvpclnt).get_configlets_by_netelement_id(device['key'])
        if deviceConfiglets['total'] > 0:
            if debug:
                sys.stderr.write('===========================================================\n')
                sys.stderr.write('Configlet Count:{} .\n'.format(deviceConfiglets['total']))
                sys.stderr.write('===========================================================\n')
            for configletData in deviceConfiglets['configletList']:
                if debug:
                    sys.stderr.write('===========================================================\n')
                    sys.stderr.write('Found Configlet:{} .\n'.format(configletData['name']))
                    sys.stderr.write('===========================================================\n')
                if configletData['type'] == 'Static':
                    if trace:
                        timestamp = datetime.now().replace(microsecond=0)
                        sys.stderr.write('{} {}INFO{}: Working on configlet: {}\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, configletData['name']))
                    
                    # Update Config with new Command Set
                    newConfig = checkCli(configletData['config'])
                    # Hash Configs to check them
                    currentConfigHash = hashlib.md5((configletData['config'].replace('\t', '').replace('\r', '').replace('\n', '')).encode('utf-8')).hexdigest()
                    newConfigHash = hashlib.md5((newConfig.replace('\t', '').replace('\r', '').replace('\n', '')).encode('utf-8')).hexdigest()

                    if debug:
                        sys.stderr.write('===========================================================\n')
                        sys.stderr.write('Checking Configlet Config: {}\n'.format(configletData['name']))
                        sys.stderr.write('===========================================================\n')

                        if currentConfigHash == newConfigHash:
                            sys.stderr.write('No changes\n')
                        else:
                            sys.stderr.write('{}\n'.format(newConfig))
                    else:
                        if currentConfigHash != newConfigHash:
                            if trace:
                                timestamp = datetime.now().replace(microsecond=0)
                                sys.stderr.write('{} {}INFO{}: Updating configlet: {}\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, configletData['name']))

                            configletData['config'] = newConfig

                            try:
                                cvpApis(cvpclnt).update_configlet(configletData['config'],configletData['key'],configletData['name'], True)
                                tasks = cvpApis(cvpclnt).change_control_available_tasks()
                            #except cvpServices.CvpError as error: # replaced by cvprac
                            except CvpClientError as error:
                                timestamp = datetime.now().replace(microsecond=0)
                                sys.stderr.write('{} {}WARNING{}: {}.\n'.format(timestamp, bcolors.WARNING, bcolors.NORMAL, error))
                            else:
                                for task in tasks:
                                    pendingTasks.append(task['ccId'])

                    sys.stderr.write('\n')
        sys.stderr.write('\n')

    if debug:
        sys.stderr.write('===========================================================\n')
        sys.stderr.write('Pending Task List: {}\n'.format(pendingTasks))
        sys.stderr.write('===========================================================\n')

    if not debug and len(pendingTasks) > 0:
        timestamp = datetime.now().replace(microsecond=0)
        sys.stderr.write('{} {}INFO{}: Creating CvEosConversion_cvprac.py {} Change Control.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, timestamp))

        # Create Change control from pending tasks
        ccid = str(uuid4())
        ccName = 'CvEosConversion{}'.format(timestamp)
        cvpApis(cvpclnt).create_change_control_v3(ccid, ccName, pendingTasks)

        if opts.executeChange:
            # Approve Created Change Control
            timestamp = datetime.now().replace(microsecond=0)
            sys.stderr.write('{} {}INFO{}: Auto approved {} Change Control.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, ccName))
            cvpApis(cvpclnt).approve_change_control(ccid, str(timestamp))

            # Execute Created Change Control
            timestamp = datetime.now().replace(microsecond=0)
            sys.stderr.write('{} {}INFO{}: Executing {} Change Control.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, ccName))
            cvpApis(cvpclnt).execute_change_controls(ccid)

            if trace:
                timestamp = datetime.now().replace(microsecond=0)
                sys.stderr.write('{} {}INFO{}: Checking status of {} Change Control.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, ccName))
            
            # Check Progress of Change Control..
            ccRunning = True
            while ccRunning:
                timestamp = datetime.now().replace(microsecond=0)
                status = cvpApis(cvpclnt).get_change_control_status(ccid)

                if status['status']['state'] == 'Completed':
                    ccRunning = False
                    timestamp = datetime.now().replace(microsecond=0)
                    sys.stderr.write('{} {}INFO{}: {} Change Control complete.  Exiting.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, ccName))

                elif status['status']['state'] == 'Failed':
                    ccRunning = False
                    timestamp = datetime.now().replace(microsecond=0)
                    sys.stderr.write('{} {}ERROR{}:  {} Change Control unsuccessful.  Initiate Network Rollback.\n'.format(timestamp, bcolors.ERROR, bcolors.NORMAL, ccName))

                else:
                    timestamp = datetime.now().replace(microsecond=0)
                    sys.stderr.write('{} {}INFO{}: {} Change Control outstanding.  Sleeping 30 seconds...\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, ccName))
                    sleep (30)
        else:
            timestamp = datetime.now().replace(microsecond=0)
            sys.stderr.write('{} {}INFO{}: Created ChangeControl {}-{}.  Please execute from CVP GUI..\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, ccid, ccName))
            return

    elif not debug and len(pendingTasks) > 0:
        timestamp = datetime.now().replace(microsecond=0)
        sys.stderr.write('{} {}INFO{}: Created tasks {}.  Please execute from CVP GUI..\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, pendingTasks))
        return
    else:
        timestamp = datetime.now().replace(microsecond=0)
        sys.stderr.write('{} {}INFO{}: Debug Mode or No Tasks Created. [{} Tasks] Exiting.\n'.format(
            timestamp, bcolors.BOLD, bcolors.NORMAL, len(pendingTasks)))

main()
