#!/usr/bin/env python
#
# Copyright (c) 2016, Arista Networks, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
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

import cvp, optparse, string, re

#
# Needed support functions
#

def checkCli(myLine):
	replacedLine = re.sub('aaa authorization console','aaa authorization serial-console', myLine)
	replacedLine = re.sub('.*peer-group.*', 'peer group', myLine)
	return replacedLine

#area nssa translate type7 always - area not-so-stubby lsa type-7 convert type-5
#arp timeout - arp aging timeout
#bfd all-interfaces - bfd default
#bgp listen limit - dynamic peer max <n>
#class-map type control-plane - class-map type copp
#control-plane - system control-plane
#default-metric - metric default
#dot1x max-reauth-req - dot1x reauthorization request limit <n>
#errdisable detect cause link-flap - errdisable detect cause link-change
#ip community-list expanded - ip community-list regexp
#ip dhcp smart-relay - ip dhcp relay all-subnets
#ip dhcp smart-relay global - ip dhcp relay all-subnets default
#ip domain-name - dns domain
#ip extcommunity-list expanded - ip extcommunity-list regexp
#ip extcommunity-list standard - ip extcommunity-list
#ip http client source-interface - ip http client local-interface
#ip igmp query-max-response-time - igmp query-max-response-time, query-max-response-time
#ip igmp query-max-response-time - query-max-response-time
#ip igmp snooping vlan immediate-leave - ip igmp snooping vlan fast-leave
#ip igmp snooping vlan mrouter - ip igmp snooping vlan multicast-router
#ip igmp snooping vlan static - ip igmp snooping vlan member
#ip msdp cache-sa-state - <removed>
#ip msdp default-peer - default-peer
#ip msdp description - description
#ip msdp group-limit - sa-limit
#ip msdp keepalive - keepalive
#ip msdp mesh-group - mesh-group
#ip msdp originator-id - originator-id local-interface
#ip msdp peer - peer <p>
#ip msdp sa-filter in - sa filter in
#ip msdp sa-filter out - sa filter out
#ip msdp sa-limit - sa limit
#ip msdp shutdown - disabled
#ip msdp timer - connection retry interval
#ip ospf bfd - ip ospf neighbor bfd
#ip ospf name-lookup - router-id output-format hostnames
#ip ospf shutdown - ip ospf disabled
#ip pim anycast-rp - anycast-rp
#ip pim bfd - bfd
#ip pim bfd-instance - pim bfd
#ip pim bsr-border - pim bsr border
#ip pim log-neighbor-changes - log neighbors
#ip pim neighbor-filter - pim neighbor filter
#ip pim query-interval - pim hello interval
#ip pim register-source - register local-interface
#ip pim spt-threshold group-list - spt threshold match list
#ip pim ssm range - ssm address range
#ip rip v2-broadcast - rip v2 multicast disable
#ipv6 nd ra suppress - ipv6 nd ra disabled
#ipv6 ospf retransmit-interval - ospfv3 ipv6 retransmit-interval
#isis lsp-interval - isis lsp tx interval
#passive-interface - passive
#lacp rate - lacp timer
#link state group - link tracking group <g> [upstream | downstream]
#link state track - link tracking group <g>
#lldp holdtime - lldp hold-time
#lldp reinit - lldp timer reinitialization
#lldp tlv-select - lldp tlv transmit
#neighbor fall-over bfd - neighbor bfd
#neighbor soft-reconfiguration - neighbor rib-in pre-policy retain
#neighbor transport connection-mode - neighbor passive
#ntp source - ntp local-interface
#policy-map type control-plane - policy-map type copp
#policy-map type qos - policy-map type quality-of-service
#priority-flow-control mode - priority-flow-control
#private-vlan mapping - pvlan mapping
#ptp sync interval - ptp sync-message interval
#service sequence-numbers - logging format sequence-numbers
#snmp trap link-status - snmp trap link-change
#snmp-server source-interface - snmp-server local-interface
#spanning-tree bridge assurance - spanning-tree transmit active
#spanning-tree loopguard default - spanning-tree guard loop default
#spanning-tree portfast bpdufilter default - spanning-tree edge-port bpdufilter default
#spanning-tree portfast bpduguard default - spanning-tree edge-port bpduguard default
#spanning-tree transmit hold-count - spanning-tree bpdu tx hold-count
#spanning-tree vlan - spanning-tree vlan-id
#statistics per-entry - counters per-entry
#switchport backup interface - switchport backup-link
#switchport port-security maximum - switchport port-security mac-address maximum
#switchport vlan mapping - switchport vlan translation
#timers basic - timers
#timers lsa arrival - timers lsa rx min interval
#timers throttle lsa all - timers lsa tx delay initial
#timers throttle spf - timers spf delay initial
#username sshkey - username ssh-key
#vlan internal allocation policy - vlan internal order
#vrf definition - vrf instance
#vrf forwarding - vrf
#vrrp authentication - vrrp peer authentication
#vrrp delay reload - vrrp timers delay reload
#vrrp description - vrrp session description
#vrrp ip - vrrp ipv4
#vrrp ip secondary - vrrp ipv4 secondary
#vrrp priority - vrrp priority-level
#vrrp shutdown - vrrp disabled
#vrrp timers advertise - vrrp advertisement interval
#vrrp track - vrrp tracked-object

#
# Define command line options for optparse
#

usage = 'usage: %prog [options]'
op = optparse.OptionParser(usage=usage)
op.add_option( '-c', '--cvphostname', dest='cvphostname', action='store', help='CVP host name FQDN or IP', type='string')
op.add_option( '-u', '--cvpusername', dest='cvpusername', action='store', help='CVP username', type='string')
op.add_option( '-p', '--cvppassword', dest='cvppassword', action='store', help='CVP password', type='string')
op.add_option( '-d', '--debug', dest='debug', action='store', help='If debug is yes, nothing will actually be sent to CVP and proposed configs are written to terminal', type='string', default='no')

opts, _ = op.parse_args()

#
# Assign command line options to variables and assign static variables.
#

host = opts.cvphostname
user = opts.cvpusername
password = opts.cvppassword
debug = opts.debug

#
# Connect and authenticate with CVP server
#

server = cvp.Cvp( host )
server.authenticate( user , password )

#
# Get all configlets and put them in a list
#

myConfiglets = server.getConfiglets()

#
# Start processiong configuration line by line in the configlet
#

for configlet in myConfiglets:
	myConfig = configlet.config
	newConfig = ""

	configLines = myConfig.splitLines()

	for line in configLines:
		newConfig =  newConfig + checkCli(line) + "\n"

#
# If debug is yes, print all proposed configuration to terminal
#

	if debug == "yes":
		print "Configlet %s, Configuration:\n%s" % ( configlet.name , newConfig )

