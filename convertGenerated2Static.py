#!/usr/bin/env python
#
# Copyright (c) 2020, Arista Networks, Inc.
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



from datetime import datetime
from time import sleep, time
from uuid import uuid4
import argparse, cvp, cvpServices, getpass, os, re, socket, sys, urllib3


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



CVP_LIST = [ os.environ.get('PRIMARY_DEVICE_INTF_IP', None), os.environ.get('SECONDARY_DEVICE_INTF_IP', None), os.environ.get('TERTIARY_DEVICE_INTF_IP', None) ]
AUTO_EXECUTE_TASKS = False



class bcolors:
    NORMAL = '\033[0m'
    BOLD = '\033[1m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'



class cvpApis(object):
    def __init__(self):
        socket.setdefaulttimeout(3)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            self.server = cvp.Cvp(host=host, ssl=True, port=443, tmpDir='')
            self.server.authenticate(user, password)

        except cvpServices.CvpError as error:
            timestamp = datetime.now().replace(microsecond=0)
            sys.stderr.write('{} {}ERROR{}: {}.\n'.format(timestamp, bcolors.ERROR, bcolors.NORMAL, error))      
            sys.exit(1)

        try:
            self.service = cvpServices.CvpService(host=host, ssl=True, port=443, tmpDir='')
            self.service.authenticate(user, password)

        except cvpServices.CvpError as error:
            timestamp = datetime.now().replace(microsecond=0)
            sys.stderr.write('{} {}ERROR{}: {}.\n'.format(timestamp, bcolors.ERROR, bcolors.NORMAL, error))
            sys.exit(1)

    def addChangeControlApproval(self, request):
        return self.server.addChangeControlApproval(request)

    def addConfiglet(self, configlet):
        return self.server.addConfiglet(configlet)

    def applyConfigletToDevice(self, deviceIpAddress, deviceFqdn, deviceMac, cnl, ckl, cbnl, cbkl, createPendingTask=True):
        return self.service.applyConfigletToDevice(deviceIpAddress, deviceFqdn, deviceMac, cnl, ckl, cbnl, cbkl, createPendingTask)

    def cancelTask(self, taskId):
        return self.service.cancelTask(taskId)

    def deleteConfiglet(self, configlet):
        return self.server.deleteConfiglet(configlet)

    def getChangeControlStatus(self, request):
        return self.server.getChangeControlStatus(request)

    def getConfiglet(self, configletName):
        return self.server.getConfiglet(configletName)

    def getConfiglets(self, configletNames=''):
        return self.server.getConfiglets(configletNames)

    def getConfigletsInfo(self):
        return self.service.getConfigletsInfo()
  
    def getContainer(self, containerName):
        return self.server.getContainer(containerName)

    def getDevice(self, deviceMacAddress, provisioned=True):
        return self.server.getDevice(deviceMacAddress, provisioned)

    def getDevices(self, provisioned=True):
        return self.server.getDevices()

    def removeConfigletAppliedToDevice(self, device, configletList):
        return self.server.removeConfigletAppliedToDevice(device, configletList)

    def startChangeControl(self, request):
        return self.server.startChangeControl(request)

    def updateChangeControl(self, request):
        return self.server.updateChangeControl(request)



def main():
    sys.stderr.write('\n\n\n\n\n')


    timestamp = datetime.now().replace(microsecond=0)
    sys.stderr.write('{} {}INFO{}: Getting CVP device inventory...\n\n\n\n\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL))
    deployedDevices = [device for device in cvpApis().getDevices() if device.containerName != 'Undefined'] 


    pendingTasks = []


    for device in deployedDevices:
        sys.stderr.write('===========================================================\n')
        sys.stderr.write('Processing device {}.\n'.format(device.fqdn))
        sys.stderr.write('===========================================================\n')


        timestamp = datetime.now().replace(microsecond=0)
        sys.stderr.write('{} {}INFO{}: Obtaining configlets applied to device.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL))
        existingConfiglets = device.configlets


        generatedConfigletsApplied = False
        newConfigletList = device.configlets


        for configlet in device.configlets:
            thisConfiglet = cvpApis().getConfiglet(configlet)


            if isinstance(thisConfiglet, cvp.GeneratedConfiglet):
                generatedConfigletsApplied = True

                newConfiglet = cvp.Configlet(thisConfiglet.name, thisConfiglet.config, 'Static', thisConfiglet.user, thisConfiglet.sslConfig)

                if debug:
                    sys.stderr.write('\n\n\nConfiglet: {}\n'.format(newConfiglet.name))
                    sys.stderr.write('==============================\n')
                    sys.stderr.write('{}'.format(newConfiglet.config))

                else:
                    if trace:
                        timestamp = datetime.now().replace(microsecond=0)
                        sys.stderr.write('{} {}INFO{}: Removing Generated configlet {} from Device {}.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, configlet, device.fqdn))

                    try:
                        configletList = []
                        configletList.append(thisConfiglet)
                        taskIdList = cvpApis().removeConfigletAppliedToDevice(device, configletList)

                    except cvpServices.CvpError as error:
                        timestamp = datetime.now().replace(microsecond=0)
                        sys.stderr.write('{} {}WARNING{}: {}.\n'.format(timestamp, bcolors.WARNING, bcolors.NORMAL, error))

                    else:
                        taskList = []
                        for taskId in taskIdList:
                            cvpApis().cancelTask(taskId)

                        if trace:
                            timestamp = datetime.now().replace(microsecond=0)
                            sys.stderr.write('{} {}INFO{}: Deleting Generated configlet {}.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, configlet))

                        try:
                            cvpApis().deleteConfiglet(thisConfiglet)

                        except cvpServices.CvpError as error:
                            timestamp = datetime.now().replace(microsecond=0)
                            sys.stderr.write('{} {}WARNING{}: {}.\n'.format(timestamp, bcolors.WARNING, bcolors.NORMAL, error))

                        if trace: 
                            timestamp = datetime.now().replace(microsecond=0)
                            sys.stderr.write('{} {}INFO{}: Creating Static configlet {}.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, configlet))

                        try:
                            cvpApis().addConfiglet(newConfiglet)

                        except cvpServices.CvpError as error:
                            timestamp = datetime.now().replace(microsecond=0)
                            sys.stderr.write('{} {}WARNING{}: {}.\n'.format(timestamp, bcolors.WARNING, bcolors.NORMAL, error))

            
            # Match on Generated configlets prior to CVP 2016.1.1 which don't follow Class GeneratedConfiglet schema
            elif thisConfiglet is None:
                targetConfigletInfo = [configletInfo for configletInfo in cvpApis().getConfigletsInfo() if configletInfo['name'] == configlet]

                if targetConfigletInfo[0]['type'] == 'Generated':
                    generatedConfigletsApplied = True

                newConfiglet = cvp.Configlet(configlet, targetConfigletInfo[0]['config'], 'Static', targetConfigletInfo[0]['user'], targetConfigletInfo[0]['sslConfig'])

                if debug:
                    sys.stderr.write('\n\n\nConfiglet: {}\n'.format(newConfiglet.name))
                    sys.stderr.write('==============================\n')
                    sys.stderr.write('{}'.format(newConfiglet.config))

                else:
                    if trace:
                        timestamp = datetime.now().replace(microsecond=0)
                        sys.stderr.write('{} {}INFO{}: Removing Generated configlet {} from Device {}.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, configlet, device.fqdn))

                    try:
                        configletList = []
                        configletList.append(cvp.Configlet(configlet, targetConfigletInfo[0]['config'], targetConfigletInfo[0]['type'], targetConfigletInfo[0]['user'], targetConfigletInfo[0]['sslConfig']))
                        taskIdList = cvpApis().removeConfigletAppliedToDevice(device, configletList)

                    except cvpServices.CvpError as error:
                        timestamp = datetime.now().replace(microsecond=0)
                        sys.stderr.write('{} {}WARNING{}: {}.\n'.format(timestamp, bcolors.WARNING, bcolors.NORMAL, error))

                    else:
                        taskList = []
                        for taskId in taskIdList:
                            cvpApis().cancelTask(taskId)

                        if trace:
                            timestamp = datetime.now().replace(microsecond=0)
                            sys.stderr.write('{} {}INFO{}: Deleting Generated configlet {}.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, configlet))

                        try:
                            cvpApis().deleteConfiglet(cvp.Configlet(configlet, targetConfigletInfo[0]['config'], targetConfigletInfo[0]['type'], targetConfigletInfo[0]['user'], targetConfigletInfo[0]['sslConfig']))

                        except cvpServices.CvpError as error:
                            timestamp = datetime.now().replace(microsecond=0)
                            sys.stderr.write('{} {}WARNING{}: {}.\n'.format(timestamp, bcolors.WARNING, bcolors.NORMAL, error))


                        if trace:
                            timestamp = datetime.now().replace(microsecond=0)
                            sys.stderr.write('{} {}INFO{}: Creating Static configlet {}.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, configlet))

                        try:
                            cvpApis().addConfiglet(newConfiglet)

                        except cvpServices.CvpError as error:
                            timestamp = datetime.now().replace(microsecond=0)
                            sys.stderr.write('{} {}WARNING{}: {}.\n'.format(timestamp, bcolors.WARNING, bcolors.NORMAL, error))


        if not debug and generatedConfigletsApplied:
            timestamp = datetime.now().replace(microsecond=0)
            sys.stderr.write('{} {}INFO{}: Getting CVP configlet inventory info...\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL))
            allConfigletsInfo = cvpApis().getConfigletsInfo()

            ckl = []
            for configlet in newConfigletList:
                for configletInfo in allConfigletsInfo:
                    if re.match(configletInfo['name'], configlet) is not None:
                        ckl.append(configletInfo['key'])

            try:
                tasks = cvpApis().applyConfigletToDevice(device.ipAddress, device.fqdn, device.macAddress, device.configlets, ckl, [], [])

            except cvpServices.CvpError as err:
                timestamp = datetime.now().replace(microsecond=0)
                sys.stderr.write('{}{} {}ERROR{}: ({}) {}{}\nUnable to continue.\n'.format(bcolors.NORMAL, timestamp, bcolors.ERROR, bcolors.NORMAL, error.errorCode, error.errorMessage, bcolors.NORMAL))
                sys.exit(0)

            else:
                timestamp = datetime.now().replace(microsecond=0)
                sys.stderr.write('{} {}INFO{}: Applying new static configlet(s) to device {}.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, device.fqdn))

            for task in tasks:
                pendingTasks.append(int(task))

        sys.stderr.write('\n\n\n\n\n')


    if not debug and len(pendingTasks) > 0:
        timestamp = datetime.now().replace(microsecond=0)
        startTime = time()
        sys.stderr.write('{} {}INFO{}: Creating convertGenerated2Static {} Change Control.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, timestamp))


        request = {}
        request['config'] = {}
        request['config']['id'] = str(uuid4())
        request['config']['name'] = 'convertGenerated2StaticV5 {}'.format(timestamp)
        request['config']['root_stage'] = {}
        request['config']['root_stage']['id'] = 'Root Stage'
        request['config']['root_stage']['stage_row'] = []


        stages = []
        i = 1
        for taskId in pendingTasks:
            stage = {}
            stage['id'] = str(uuid4())
            stage['name'] = 'stage1-{}'.format(i)
            stage['action'] = {}
            stage['action']['name'] = 'task'
            stage['action']['args'] = {}
            stage['action']['args']['TaskID'] = str(taskId)

            stages.append(stage)

            i += 1


        request['config']['root_stage']['stage_row'].append({'stage': stages})
        result = cvpApis().updateChangeControl(request)


        timestamp = datetime.now().replace(microsecond=0)
        sys.stderr.write('{} {}INFO{}: Auto approved {} Change Control.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, request['config']['name']))
        cvpApis().addChangeControlApproval({'cc_id': result['id'], 'cc_timestamp': result['update_timestamp']})


        timestamp = datetime.now().replace(microsecond=0)
        sys.stderr.write('{} {}INFO{}: Executing {} Change Control.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, request['config']['name']))
        cvpApis().startChangeControl({'cc_id': result['id']})


        if trace:
            timestamp = datetime.now().replace(microsecond=0)
            sys.stderr.write('{} {}INFO{}: Checking status of {} Change Control.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, request['config']['name']))


        ccRunning = True
        ccFailed = False
        while ccRunning:
            timestamp = datetime.now().replace(microsecond=0)
            status = cvpApis().getChangeControlStatus({'cc_id': result['id']})


            if status['status']['state'] == 'Completed':
                ccRunning = False
                timestamp = datetime.now().replace(microsecond=0)
                sys.stderr.write('{} {}INFO{}: {} Change Control complete.  Exiting.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, request['config']['name']))


            elif status['status']['state'] == 'Failed':
                ccRunning = False
                ccFailed = True
                timestamp = datetime.now().replace(microsecond=0)
                sys.stderr.write('{} {}ERROR{}: Configlet Fix {} Change Control unsuccessful.  Initiating Network Rollback.\n'.format(timestamp, bcolors.ERROR, bcolors.NORMAL, request['config']['name']))


            else:
                timestamp = datetime.now().replace(microsecond=0)
                sys.stderr.write('{} {}INFO{}: {} Change Control outstanding.  Sleeping 30 seconds...\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, request['config']['name']))
                sleep (30)


    elif not debug and len(pendingTasks) > 0:
        timestamp = datetime.now().replace(microsecond=0)
        sys.stderr.write('{} {}INFO{}: Created tasks {}.  Please execute from CVP GUI..\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL, pendingTasks))
        return


    else:
        timestamp = datetime.now().replace(microsecond=0)
        sys.stderr.write('{} {}INFO{}: No changes made. Exiting.\n'.format(timestamp, bcolors.BOLD, bcolors.NORMAL))



main()
