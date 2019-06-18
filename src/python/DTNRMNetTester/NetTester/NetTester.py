#!/usr/bin/env python
# TODO: This is also used only for Testing purposes at SC.
"""
    Ruler component pulls all actions from Site-FE and applies these rules on DTN

Copyright 2017 California Institute of Technology
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
Title                   : dtnrm
Author                  : Justas Balcas
Email                   : justas.balcas (at) cern.ch
@Copyright              : Copyright (C) 2016 California Institute of Technology
Date                    : 2018/11/08
"""
import os
import sys
import json
import copy
import time
import glob
import urllib2
import subprocess
import psutil
from DTNRMLibs.MainUtilities import getStreamLogger, externalCommand
from DTNRMLibs.MainUtilities import getDefaultConfigAgent, createDirs, contentDB

COMPONENT = 'NetTester'

# TODO from configuration.
GIST = 'https://gist.githubusercontent.com/juztas/db3a7e6987c99a9bf17a1e74e5461a38/raw/SENSE-DATANODES'

def executeCmd(command, logger):
    """ Execute interfaces commands. """
    logger.info('Asked to execute %s command' % command)
    cmdOut = externalCommand(command, False)
    out, err = cmdOut.communicate()
    msg = 'Command: %s, Out: %s, Err: %s, ReturnCode: %s' % (command, out.rstrip(), err.rstrip(), cmdOut.returncode)
    logger.info(msg)
    return out.rstrip(), err.rstrip(), cmdOut.returncode

def getUUID(inline):
    """ Get UUID from the Requested delta """
    splLine = inline.split(':')
    for item in splLine:
        if item.startswith('conn+'):
            return item[5:]
    return None

def getGistContent():
    """ Get GIST config for endpoints """
    req = urllib2.Request(GIST)
    try:
        resp = urllib2.urlopen(req)
        return resp.read()
    except urllib2.URLError as e:
        print e.reason
        return ""

def cleanLogs(files):
    """ Clean log files """
    for fileName in files:
        if os.path.isfile(fileName):
            os.unlink(fileName)
        with open(fileName, 'w+') as fd:
            fd.write("Time to start %s" % int(time.time()))

class FDTWorker(object):
    """ FDT Worker to start client and server on the host and initiate transfer """
    def __init__(self, configIn, loggerIn):
        self.config = configIn
        self.logger = loggerIn
        self.logDir = self.config.get('general', 'private_dir') + "/DTNRM/NetTester/logs/"
        createDirs(self.logDir)
        self.fdtLoc = '%s/fdt.jar' % self.config.get('general', 'sense_client')
        self.serverCmd = "java -jar %s -p %%s -P %%s -noupdates" % self.fdtLoc
        self.clientCmd = "java -jar %s -p %%s -P %%s -noupdates -c %%s -nettest" % self.fdtLoc

    def startServer(self, vlandelta, streams=8, orch=True):
        """ Start FDT Server """
        port = vlandelta['vlan']
        cmd = self.serverCmd % (port, streams)
        logFile = "%s/%s-server.json" % (self.logDir, port)
        cleanLogs([logFile, "%s.stdout" % logFile, "%s.stderr" % logFile])
        with open(logFile, 'w+') as fd:
            fd.write('Start server from python')
            fd.write('Command: %s' % cmd)
        self.logger.info('Executing this command %s' % cmd)
        proc = subprocess.Popen(cmd, shell=True,
                                stdout=file("%s.stdout" % logFile, "ab+"),
                                stderr=file("%s.stderr" % logFile, "ab+"))
        self.logger.info("PID: %s", proc.pid)
        return proc.pid

    def startClient(self, vlandelta, streams=8, orch=True):
        """ Start FDT Client """
        sip = None
        cmd = None
        logFile = None
        if orch:
            for item in vlandelta['proc_ips']:
                if item != vlandelta['ip']:
                    sip = item
            port = vlandelta['vlan']
            cmd = self.clientCmd % (port, streams, sip[:-3])
            logFile = "%s/%s-client-%s.json" % (self.logDir, port, sip[:-3])
        else:
            sip = vlandelta['ip']
            port = vlandelta['vlan']
            cmd = self.clientCmd % (port, streams, sip)
            logFile = "%s/%s-client-%s.json" % (self.logDir, port, sip)
        cleanLogs([logFile, "%s.stdout" % logFile, "%s.stderr" % logFile])
        with open(logFile, 'w+') as fd:
            fd.write('Start client from python')
            fd.write('Command: %s' % cmd)
        self.logger.info('Executing this command %s' % cmd)
        proc = subprocess.Popen(cmd, shell=True,
                                stdout=file("%s.stdout" % logFile, "ab+"),
                                stderr=file("%s.stderr" % logFile, "ab+"))
        self.logger.info("PID: %s", proc.pid)
        return proc.pid

    def status(self, spid):
        """ Get Status of Server/Client Worker """
        proc = psutil.Process(spid)
        if proc.status() == psutil.STATUS_ZOMBIE:
            self.stop(spid)
            raise psutil.NoSuchProcess('Pid %s is ZOMBIE Process' % spid)
        return True

    def stop(self, spid):
        proc = psutil.Process(spid)
        proc.terminate()
        return True


class NetTester(object):
    def __init__(self, configIn, loggerIn, args=None):
        self.config, self.logger = getDefaultConfigAgent(COMPONENT, configIn, loggerIn)
        self.workDir = self.config.get('general', 'private_dir') + "/DTNRM/NetTester/jsons/"
        self.fdtworker = FDTWorker(self.config, self.logger)
        self.senseclient = self.config.get('general', 'sense_client')
        self.customInput = args
        createDirs(self.workDir)
        self.IPs = []
        self.vlanConfDir = self.config.get('general', 'private_dir') + "/DTNRM/RulerAgent/"
        self.logger.info("==== NetTester Start Work.")
        self.agentdb = contentDB(logger=self.logger, config=self.config)

    def getIPs(self, inputObj):
        if isinstance(inputObj, list):
            for item in inputObj:
                self.getIPs(item)
        elif isinstance(inputObj, dict):
            for dKey, dValue in inputObj.items():
                if dKey == 'IP Address':
                    self.IPs.append(dValue)
                elif isinstance(dValue, list):
                    self.getIPs(dValue)

    def getServiceInfo(self, uniqUUID):
        statusCmd = "sh %s/status.sh -s -h 179-132.research.maxgigapop.net %s" % (self.senseclient, uniqUUID)
        manifestCmd = "sh %s/manifest.sh -s -h 179-132.research.maxgigapop.net -f manifest-1.xml %s" % (self.senseclient, uniqUUID)
        statusout = executeCmd(statusCmd, self.logger)
        if statusout[0].strip() == 'CREATE - READY':
            self.logger.info('This %s has state READY' % uniqUUID)
            manifestOut = executeCmd(manifestCmd, self.logger)
            manOut = json.loads(manifestOut[0])
            if 'jsonTemplate' not in manOut.keys():
                self.logger.info('Orchestrator returned info does not have jsonTemplate')
                return False
            manOut = json.loads(manOut['jsonTemplate'])
            self.getIPs(manOut)
            if len(self.IPs) != 2:
                self.logger.info('Skipping because I did not got 2 IPs for service %s' % uniqUUID)
                return False
            return True
        return False

    def stopService(self, pubPID):
        try:
            self.fdtworker.status(pubPID)
            self.fdtworker.stop(pubPID)
        except psutil.NoSuchProcess as ex:
            self.logger.debug(str(ex))
        return

    def publicTransfers(self):
        gitContent = getGistContent()
        publicTrack = self.agentdb.getFileContentAsJson('%s/publictransfer.dict' % self.workDir)
        if not publicTrack:
            publicTrack = {'servers': {}, 'clients': {}}
        mypubIP = self.config.get('general', "pub_ip")
        servers = []
        for line in gitContent.split('\n'):
            if line.startswith('#'):
                continue
            out = filter(None, line.split(' '))
            if out:
                servers.append(out)
        self.logger.info('I received git content and there is %s servers' % len(servers))
        self.logger.info('My IP is: %s' % mypubIP)
        # Let's check first if my IP is defined at all
        lineNum = -1
        startServer = 0
        startClient = 0
        for iCount in range(0, len(servers)):
            if mypubIP == servers[iCount][1]:
                lineNum = iCount
        if lineNum == -1:
            self.logger.info('My service is not defined in the output of gist. Will not start any transfers')
            self.logger.info('More details: %s' % servers)
            # In case we have any pending transfers, we need to stop them.
            dcopy = copy.deepcopy(publicTrack)
            for pubPort, pubPID in dcopy['servers'].items():
                self.logger.info('Checking status for server %s and %s' % (pubPort, pubPID))
                self.stopService(pubPID)
                del publicTrack['servers'][pubPort]
            for pubPort, pubPID in dcopy['clients'].items():
                self.logger.info('Checking status for client %s and %s' % (pubPort, pubPID))
                self.stopService(pubPID)
                del publicTrack['clients'][pubPort]
        # First we check servers information based on port:
        if lineNum != -1 and servers[lineNum][2]:
            startServer = servers[lineNum][2]
            self.logger.info('My service information %s' % servers[lineNum])
            self.logger.info('Checking public servers if they are up...')
            streams = servers[lineNum][3]
            for portNum in range(0, len(servers)):
                if portNum == lineNum:
                    continue
                if not startServer:
                    continue
                port = servers[lineNum][portNum + 5]
                if port in publicTrack['servers'].keys():
                    # Check Status of specific server port
                    try:
                        self.logger.info('Checking status for %s and %s' % (port, publicTrack['servers'][port]))
                        self.fdtworker.status(publicTrack['servers'][port])
                        continue
                    except psutil.NoSuchProcess as ex:
                        self.logger.debug(str(ex))
                # Here means either process is not running or it was never started...
                self.logger.info('Starting server for %s port' % port)
                newpid = self.fdtworker.startServer({'vlan': port}, streams, orch=False)
                publicTrack['servers'][port] = newpid
        else:
            self.logger.info('This service is not configured to act as Server. Will not start FDT Services')
        # Let's Check all the clients who are pushing data...
        if lineNum != -1:
            startClient = servers[lineNum][3]
        for iCount in range(0, len(servers)):
            if not startClient:
                continue  # We are not starting clients if it is not configured in gist;
            if lineNum == iCount:
                continue  # We just ignore client to do transfers to ourselves.
            if servers[iCount][2]:
                # Means there should be a service listening...
                sip = servers[iCount][1]
                port = servers[iCount][lineNum + 5]
                streams = servers[iCount][4]
                # It is a simple matrix, where the column belongs to a specific endhost.
                if sip in publicTrack['clients'].keys():
                    # Check status of specific client port
                    try:
                        self.logger.info('Checking status for %s and transfer to: %s' % (port, sip))
                        self.fdtworker.status(publicTrack['clients'][sip])
                        continue
                    except psutil.NoSuchProcess as ex:
                        self.logger.debug(str(ex))
                self.logger.info('Starting client for %s port to %s' % (port, sip))
                clientpid = self.fdtworker.startClient({'vlan': port, 'ip': sip}, streams, False)
                publicTrack['clients'][sip] = clientpid
        self.agentdb.dumpFileContentAsJson('%s/publictransfer.dict' % self.workDir, publicTrack)

    def start(self):
        knownReq = []
        self.publicTransfers()
        for filename in glob.glob("%s*.json" % self.vlanConfDir):
            self.IPs = []
            currentdelta = self.agentdb.getFileContentAsJson(filename)
            currentprocessdelta = None
            if 'vlan' not in currentdelta.keys():
                self.logger.info("vlan id is not present in delta %s. Continue" % currentdelta)
                continue
            if 'connectionID' not in currentdelta.keys():
                continue
            knownReq.append(currentdelta['vlan'])
            currentprocessdelta = self.agentdb.getFileContentAsJson('%s/%s.json' % (self.workDir, currentdelta['vlan']))
            if currentprocessdelta:
                for fdttype in ['server', 'client']:
                    if currentprocessdelta['%s_pid' % fdttype]:
                        try:
                            self.logger.info('Checking status for %s and %s' % (fdttype, currentprocessdelta))
                            self.fdtworker.status(currentprocessdelta['%s_pid' % fdttype])
                        except psutil.NoSuchProcess as ex:
                            self.logger.debug(str(ex))
                            newpid = None
                            self.logger.info('Starting new %s for %s' % (fdttype, currentprocessdelta))
                            if fdttype == 'server':
                                newpid = self.fdtworker.startServer(currentprocessdelta)
                            else:
                                newpid = self.fdtworker.startClient(currentprocessdelta)
                            currentprocessdelta['%s_pid' % fdttype] = newpid
                            self.agentdb.dumpFileContentAsJson('%s/%s.json' % (self.workDir, currentdelta['vlan']), currentprocessdelta)
            else:
                serviceID = getUUID(currentdelta['connectionID'])
                if not serviceID:
                    self.logger.info("Failed to get service ID from %s" % currentdelta)
                    continue
                serviceInfo = self.getServiceInfo(serviceID)
                if serviceInfo:
                    currentprocessdelta = copy.deepcopy(currentdelta)
                    currentprocessdelta['proc_ips'] = self.IPs
                    self.logger.info('Full content %s' % currentprocessdelta)
                    self.logger.info('Starting server')
                    serverpid = self.fdtworker.startServer(currentprocessdelta)
                    self.logger.info('Starting client')
                    clientpid = self.fdtworker.startClient(currentprocessdelta)
                    # Time to save new process.
                    currentprocessdelta['server_pid'] = serverpid
                    currentprocessdelta['client_pid'] = clientpid
                    self.agentdb.dumpFileContentAsJson('%s/%s.json' % (self.workDir, currentdelta['vlan']), currentprocessdelta)
        for filename in glob.glob("%s/*.json" % self.workDir):
            # Get File content:
            currentagent = self.agentdb.getFileContentAsJson(filename)
            if currentagent['vlan'] in knownReq:
                self.logger.info('This request %s is still active. All OK' % filename)
                continue
            # Here means this request does not exist anymore on DTN-RM Agent. We need to check status on Orchestrator
            self.logger.info('This request is not active on DTN. Will check Orchestrator and if active, will not touch it.')
            serviceID = getUUID(currentagent['connectionID'])
            serviceInfo = self.getServiceInfo(serviceID)
            if not serviceInfo:
                if os.path.isfile(filename):
                    os.remove(filename)
                for fdttype in ['server', 'client']:
                    try:
                        self.logger.info('Orchestrator did not replied with status ready info. Stopping %s...' % fdttype)
                        self.fdtworker.stop(currentagent['%s_pid' % fdttype])
                    except psutil.NoSuchProcess as ex:
                        self.logger.debug(str(ex))
            else:
                self.logger.info('This is strange... Was dtn manually cleaned? DTN does not have this delta anymore, but status in orchestrator is active.')

def execute(configIn=None, loggerIn=None, args=None):
    ruler = NetTester(configIn, loggerIn, args)
    ruler.start()


if __name__ == "__main__":
    print 'WARNING: ONLY FOR DEVELOPMENT!!!!. Number of arguments:', len(sys.argv), 'arguments.'
    print 'Arg1: location of deltas'
    print 'Argument List:', str(sys.argv)
    if len(sys.argv) == 2:
        execute(loggerIn=getStreamLogger(), args=sys.argv[1])
    else:
        execute(loggerIn=getStreamLogger())
