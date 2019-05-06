# Copyright (c) 2015 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.
'''
@Copyright: 2015-2016 Arista Networks, Inc.
Arista Networks, Inc. Confidential and Proprietary.

Cvp.py is a library which can be used to perform various
actions over the cvp instance. There are numerous methods each
corresponding to each action. Methods are listed below in the Cvp class.
'''
import os
import time
import cvpServices
import errorCodes
import socket
import re
import base64
import io
import zipfile

# Compliance codes for devices and containers
DEVICE_IN_COMPLIANCE = 0
DEVICE_CONFIG_OUT_OF_SYNC = 1
DEVICE_IMAGE_OUT_OF_SYNC = 2
DEVICE_IMG_CONFIG_OUT_OF_SYNC = 3
DEVICE_IMG_CONFIG_IN_SYNC = 4
DEVICE_NOT_REACHABLE = 5
DEVICE_IMG_UPGRADE_REQD = 6
DEVICE_EXTN_OUT_OF_SYNC = 7
DEVICE_CONFIG_IMG_EXTN_OUT_OF_SYNC = 8
DEVICE_CONFIG_EXTN_OUT_OF_SYNC = 9
DEVICE_IMG_EXTN_OUT_OF_SYNC = 10
DEVICE_UNAUTHORIZED_USER = 11

complianceCodes = {
   DEVICE_IN_COMPLIANCE : 'In compliance',
   DEVICE_CONFIG_OUT_OF_SYNC : 'Config out of sync',
   DEVICE_IMAGE_OUT_OF_SYNC : 'Image out of sync',
   DEVICE_IMG_CONFIG_OUT_OF_SYNC : 'Image and Config out of sync',
   DEVICE_IMG_CONFIG_IN_SYNC : 'Unused',        # was: 'Image and Config in sync'
   DEVICE_NOT_REACHABLE : 'Device not reachable',
   DEVICE_IMG_UPGRADE_REQD : 'Image upgrade required',
   DEVICE_EXTN_OUT_OF_SYNC : 'Extensions out of sync',
   DEVICE_CONFIG_IMG_EXTN_OUT_OF_SYNC : 'Config, Image and Extensions out of sync',
   DEVICE_CONFIG_EXTN_OUT_OF_SYNC : 'Config and Extensions out of sync',
   DEVICE_IMG_EXTN_OUT_OF_SYNC : 'Image and Extensions out of sync',
   DEVICE_UNAUTHORIZED_USER : 'Unauthorized User',
}

# AAA settings notation
AAA_SETTINGS = [ 'Local', 'RADIUS', 'TACACS' ]

class EncryptionAlgorithm( object ):
   rsa = 'RSA'

class DigestAlgorithm( object ):
   sha256rsa = 'SHA256withRSA'

def encoder( obj ):
   '''Returns JSON-serializable version of the obj'''
   if hasattr( obj, 'jsonable' ):
      return obj.jsonable()
   else:
      raise TypeError

class Jsonable( object ):
   '''This class represents a JSON-serializable object. The default serialization
   is to just return the class' __dict__.'''

   def __init__( self ):
      pass

   def jsonable( self ):
      ''' Returns modules namespace as dictionary'''
      return self.__dict__

class Image( Jsonable ):
   '''Image class, stores all required information about
   an image.

   state variables:
      name -- name fo the image
      rebootRequired -- Reboot required after applying this image( True/False )
   '''
   def __init__( self, name, rebootRequired=False ):
      super( Image, self ).__init__( )
      self.name = name
      self.rebootRequired = rebootRequired

   def __repr__( self ):
      return 'Image "%s"' % self.name

class Theme( Jsonable ):
   '''Theme class, stores all required information about a theme.

   state variables:
      name -- file name
      themeType -- either backgroundImage or logo
      isActive -- is active theme
   '''
   def __init__( self, name, themeType, isActive ):
      super( Theme, self ).__init__( )
      self.name = name
      self.themeType = themeType
      self.isActive = isActive

   def __repr__( self ):
      return 'Theme "%s"' % self.name

class Container( Jsonable ):
   '''Container class, stores all required information about
   a container

   State variables:
      name -- name of the container
      configlets -- list of configlet name assigned to container
      imageBundle -- name of the image bundle assigned to container
      parentName -- Name of the parent container
   '''

   def __init__( self, name, parentName, configlets='', imageBundle=''):
      super( Container, self ).__init__( )
      self.name = name
      self.configlets = configlets
      self.imageBundle = imageBundle
      self.parentName = parentName

   def __repr__( self ):
      return 'Container "%s"' % self.name

class Task( Jsonable ):
   ''' Task class, Stores information about a Task

   State variables:
      taskId -- work order Id assigned to the task
      description -- information explaining what task is about
   '''
   COMPLETED = 'Completed'
   PENDING = 'Pending'
   FAILED = 'Failed'
   CANCELED = 'Cancelled'
   CONFIG_PUSH_IN_PROGRESS = 'Configlet Push In Progress'
   IMAGE_PUSH_IN_PROGRESS = 'Image Push In Progress'
   DEVICE_REBOOT_IN_PROGRESS = 'Device Reboot In Progress'

   def __init__( self, taskId, status, description='' ):
      super( Task, self ).__init__( )
      self.taskId = int( taskId )
      self.status = status
      self.description = description

   def __repr__( self ):
      return 'Task "%s"' % self.taskId

class CCTask( Task ):
   ''' A Class for Tasks associated with Change Control.

   State variables:
      taskOrder -- Order of the task executed in a Change control
   '''

   def __init__( self, taskId, status, description, taskOrder = 1,
                cloneId = None ):
      super( CCTask, self ).__init__( taskId, status, description )
      self.taskOrder = taskOrder
      self.parentCCId = cloneId

class ChangeControl( Jsonable ):
   ''' Change Control class, that stores information about change controls
   State variables:
      Id(type: int) -- Id of the change control
      Name -- Name assigned to the change control
      schedule -- timeDate in local time zone to schedule a change control
      snapshotTemplateKey -- snapshot template key for the change control
      taskList -- List of CCTask objects to be included for the change control
      status -- Status of change control
   '''
   COMPLETED = 'Completed'
   PENDING = 'Pending'
   FAILED = 'Failed'
   CANCELLED = 'Cancelled'
   ABORTED = 'Aborted'
   NEW = 'New'

   # Making ccTaskList default None as when we call getChangeControls API,
   # returned data from change control does not have ccTaskList field.
   def __init__( self, ccName, ccTaskList, scheduleTime=None,
                 snapshotTemplateKey=None, status=NEW, ccId=None ):
      super( ChangeControl, self ).__init__()
      self.Id = ccId
      self.Name = ccName
      self.schedule = scheduleTime
      self.snapshotTemplateKey = snapshotTemplateKey
      self.taskList = ccTaskList
      self.status = status

class Rollback( Jsonable ):
   ''' Rollback class, stores information about the rollback variables
   State variables:
      rollbackType -- Type of rollback
      rollbackTime -- Unix time to which rollback is to happen
      device -- an Device object that indicates the device being rolledback
      configRollbackInfo -- Information regards to the snapshot or task from
                            which the config details are being used to
                            rollback the device config. Its a Dict with
                            'taskId' and 'snapshot' as keys
      imageRollbackInfo -- Information regards to the snapshot or task from
                           which the image details are being used to
                           rollback the device image. Image should be
                           available in the Cvp for the rollabck to occur.
                           Its a Dict with 'taskId' and 'snapshot' as keys
   '''

   def __init__( self, rollbackType, rollbackTime, device ):
      super( Rollback, self ).__init__()
      assert isinstance( device, Device )
      self.rollbackType = rollbackType
      self.rollbackTime = rollbackTime
      self.device = device
      self.configRollbackInfo = None
      self.imageRollbackInfo = None

class NetworkRollback( Jsonable ):
   ''' NetworkRollback class to host network rollback information
   State variables:
      container -- An instance of Container rolled back
      rollbackType -- The type of the rollback
      rollbackTime -- Unix time to which rollback is to happen
      startIndex - pagination start index
      endIndex - pagination end index
      cc -- An instance of Change Control that handles the network rollback
            tasks
   '''
   CONFIG_ROLLBACK = 'Config Rollback'
   IMAGE_ROLLBACK = 'Image Rollback'
   CONFIG_IMAGE_ROLLBACK = 'Config and Image Rollback'

   def __init__( self, container, rollbackTime, rollbackType,
                   startIndex=0, endIndex=15 ):
      super( NetworkRollback, self ).__init__()
      self.container = container
      self.rollbackTime = rollbackTime
      self.rollbackType = rollbackType
      self.startIndex = startIndex
      self.endIndex = endIndex
      self.cc = None

class Device( Jsonable ):
   ''' Device class helps store all the information about a particular device

   state variables:
      ipAddress -- ip address of the device
      fqdn -- fully qualified domain name for the device
      macAddress -- mac address of the device
      containerName -- name of the parent container
      imageBundle -- name of the imageBundle assigned to device
      configlets -- list of names of configlets assigned to the device
      status -- Device's registration status
      model -- Device's model number
      sn -- Device's serial number
      complianceCode -- Device's compliance status
   '''
   UNKNOWN = 'Unknown'
   REG_IN_PROGRESS = 'Registration_In_Progress'
   REGISTERED = 'Registered'
   AUTO_UPGRADE_FAILED = 'Auto image upgrade failed'
   DCA_INSTALLATION_IN_PROGRESS = 'Certificate installation in-progress'
   DCA_INSTALLATION_FAILED = 'Certificate installation failed'
   def __init__( self, ipAddress, fqdn, macAddress, containerName, imageBundle=None,
                 configlets=None, status=UNKNOWN, model=None, sn=None,
                 complianceCode=None ):
      super( Device, self ).__init__( )
      self.ipAddress = ipAddress
      self.fqdn = fqdn
      self.macAddress = macAddress
      self.containerName = containerName
      self.imageBundle = imageBundle
      self.configlets = configlets
      self.status = status
      self.model = model
      self.sn = sn
      self.cc = complianceCode

   def __repr__( self ):
      return 'Device "%s"' % self.fqdn or self.ipAddress or self.macAddress

class Configlet( Jsonable ):
   '''Configlet class stores all the information necessary about the
   configlet

   state variables:
      name -- name of the configlet
      config -- configuration information inside configlet
      type -- to store the type of the configlet
      user -- the user that created this configlet. Pre-loaded configlets have
              'cvp system' as the user.
      sslConfig -- A Boolean indicating if this is a system pre-loaded special ssl configlet for
                   secure device communication.
   '''
   def __init__( self, name, config, configletType='Static', user=None,
                 sslConfig=False ):
      super( Configlet, self ).__init__( )
      self.name = name
      self.config = config
      self.configletType = configletType
      self.user = user
      self.sslConfig = sslConfig

   def __repr__( self ):
      return 'Configlet "%s"' % self.name

class ConfigletBuilder( Configlet ):
   ''' ConfigletBuilder class stores all the information about the Configlet
   builder

   state variables:
      name -- name of the Configlet Builder
      formList -- list of forms part of configlet builder
      mainScript -- the configlet builder mainscript
   '''
   def __init__( self, name, formList, mainScript, **kwargs ):
      super( ConfigletBuilder, self ).__init__( name, '', **kwargs )
      self.formList = formList
      self.mainScript = mainScript
      self.configletType = 'Builder'

class GeneratedConfiglet( Configlet ):
   '''GeneratedConfiglet class stores information about the generated configlets.
   Mapping between the generated configlet, configlet builder, container and device

   State variables:
      builderName -- name of the configlet builder that generated this configlet
      ContainerName -- Name of the container to which the builder was assigned
      deviceMac -- Mac address of the device to which this configlet is assigned
   '''

   def __init__( self, name, config, builderName, containerName, deviceMac, **kwargs ):
      super( GeneratedConfiglet, self ).__init__( name, config, **kwargs )
      self.builderName = builderName
      self.containerName = containerName
      self.deviceMac = deviceMac
      self.configletType = 'Generated'

class ReconciledConfiglet( Configlet ):
   '''ReconciledConfiglet  class stores information about the reconciled configlets.
   State variables:
      deviceMac -- Mac address of the devices
   '''
   def __init__( self, name, config, deviceMac, **kwargs ):
      super( ReconciledConfiglet, self ).__init__( name, config, **kwargs )
      self.deviceMac = deviceMac
      self.configletType = 'Reconciled'

class User( Jsonable ):
   ''' User class stores all the information about an users

   State variables:
      userId -- unique user id of the user
      firstName -- first name of user
      LastName -- last name of the user
      emailID -- email ID of the user
      contactNumber -- contact number for the user

   '''
   def __init__( self, userId, email, roleList, userStatus='DISABLED',
                 firstName='', lastName='', contactNumber='', userType='Local' ):
      super( User, self ).__init__( )
      self.userId = userId
      self.email = email
      self.roleList = roleList
      self.userStatus = userStatus
      self.firstName = firstName
      self.lastName = lastName
      self.contactNumber = contactNumber
      self.userType = userType

   def __repr__( self ):
      return 'User "%s"' % self.userId

class Role( Jsonable ):
   ''' Stores all essential information about a specific role

   State variables:
      name -- name of the role
      description -- Description about the Role
      moduleList -- list of permissions
      key -- key of the role
   '''

   def __init__( self, name, description, moduleList, key=None ):
      super( Role, self ).__init__( )
      self.key = key
      self.name = name
      self.description = description
      self.moduleList = moduleList

   def __repr__( self ):
      return 'Role "%s"' % self.name

class ImageBundle( Jsonable ):
   '''ImageBundle class objects stores all necessary information about the
   bundle

   state variables:
      name -- name of the image bundle
      imageNames -- keys corresponding to images present in this image bundle
      certified -- indicates whether image bundle is certified or not
      user -- User that created this bundle
   '''
   def __init__( self, name, imageNames, certified=False, user=None ):
      super( ImageBundle, self ).__init__( )
      self.name = name
      self.imageNames = imageNames
      self.certified = certified
      self.user = user

   def __repr__( self ):
      return 'ImageBundle "%s"' % self.name

class AaaServer( Jsonable ):
   '''
   Aaa Server Class object holds all information about
   AAA server

   state variables:
   serverType -- AAA server type Local, TACACS, RADIUS
   authType -- authorization type Local, TACACS, RADIUS
   port -- Port
   ipAddress -- Ip address of remote AAA server
   authMode -- authorization mode ASCII, PAD, CHAP
   status -- Status of AAA server Enabled, Disabled
   '''
   ENABLED = "Enabled"
   DISABLED = "Disabled"

   def __init__( self, serverType, authType, port,
         ipAddress, authMode, accountPort,
         status=ENABLED, key=None ):
      assert ( status == self.ENABLED or status == self.DISABLED ), 'status can' \
               ' be %s or %s.' %( self.ENABLED, self.DISABLED )
      super( AaaServer, self ).__init__( )
      self.serverType = serverType
      self.authType = authType
      self.port = port
      self.ipAddress = ipAddress
      self.authMode = authMode
      self.status = status
      self.createdDateInLongFormat = int( round( time.time() * 1000 ) )
      self.accountPort = accountPort
      self.key = key

   def __repr__( self ):
      return 'AAAServer "%s"' % self.ipAddress

class AaaUser( Jsonable ):
   '''
   User object representing user need to be tested
   agaist AAA server.
   '''
   def __init__( self, userId, password ):
      super( AaaUser, self ).__init__( )
      self.userId = userId
      self.password = password

   def __repr__( self ):
      return 'AAAUser "%s"' % self.userId

class AaaSettings( Jsonable ):
   '''
   AAA settings object which stores inforamtion about Authentication and
   Authorization server type.
   '''
   def __init__( self, authenticationServerType, authorizationServerType ):
      super( AaaSettings, self ).__init__( )
      self.authenticationServerType = authenticationServerType
      self.authorizationServerType = authorizationServerType

class Event( Jsonable ):
   '''
   Event class that represents events such as compliance check, reconcile.
   '''
   INITIALIZED = 'INITIALIZED'
   IN_PROGRESS = 'IN_PROGRESS'
   COMPLETED = 'COMPLETED'
   CANCELED = 'CANCELLED'

   def __init__( self, eventId, parentEventId, objectId, eventType, status,
                 complianceCode, message, errors, warnings, addlData ):
      super( Event, self ).__init__()
      self.eventId = eventId
      self.parentEventId = parentEventId
      self.objectId = objectId
      self.eventType = eventType
      self.status = status
      self.complianceCode = complianceCode
      self.message = message
      self.errors = errors
      self.warnings = warnings
      # addlData contains additional data about this event, which is the device
      # structure as of now. If "unAuthorized" field is set, it means the
      # complianceCode is not current, but the last known state.
      self.addlData = addlData

   def __repr__( self ):
      return 'Event "%s"' % self.eventId

class Backup( Jsonable ):
   '''
   Backup class that represents CVP backups.
   '''
   def __init__( self, key, name, createdTimestamp, location, size ):
      super( Backup, self ).__init__()
      self.key = key
      self.name = name
      self.createdTimestamp = createdTimestamp
      self.location = location
      self.size = size

   def __repr__( self ):
      return 'Backup "%s"' % self.key

class CertificateInfo( Jsonable ):
   '''
   This is the base class for certificates.
   '''
   def __init__( self, commonName, subjectAlternateNameIPList,
            subjectAlternateNameDNSList, organization, organizationUnit, location,
            state, country, encryptionAlgorithm, digestAlgorithm, keyLength,
            description ):
      # No other instance variable should be added as this object will be converted
      # to dictionary/json and used in Cvp.generateCertificate().
      super( CertificateInfo, self ).__init__()
      self.commonName = commonName
      self.subjectAlternateNameIPList = subjectAlternateNameIPList
      self.subjectAlternateNameDNSList = subjectAlternateNameDNSList
      self.country = country
      self.state = state
      self.location = location
      self.organization = organization
      self.organizationUnit = organizationUnit
      self.encryptAlgorithm = encryptionAlgorithm
      self.digestAlgorithm = digestAlgorithm
      self.keyLength = keyLength
      self.description = description

   def getSubject( self ):
      return "CN=%s, O=%s, OU=%s, L=%s, ST=%s, C=%s" % ( self.commonName,
         self.organization, self.organizationUnit, self.location, self.state,
         self.country )

class Certificate( CertificateInfo ):
   '''
   This class represents a X.509 certificate.
   '''
   CVP = 'cvpCert'
   DCA = 'dcaCert'
   def __init__( self, certType, commonName, subjectAlternateNameIPList,
            subjectAlternateNameDNSList, organization, organizationUnit, location,
            state, country, encryptionAlgorithm, digestAlgorithm, keyLength,
            validity, description, skipTypeCheck=False ):
      super( Certificate, self ).__init__( commonName, subjectAlternateNameIPList,
            subjectAlternateNameDNSList, organization, organizationUnit, location,
            state, country, encryptionAlgorithm, digestAlgorithm, keyLength,
            description )
      # No other instance variable should be added as this object will be converted
      # to dictionary/json and used in Cvp.generateCertificate().
      if not skipTypeCheck:
         Certificate.checkCertificateType( certType )
      self.certType = certType
      self.validity = validity

   @classmethod
   def checkCertificateType( cls, certType ):
      '''
      Checks the certificate type and raises an assertion if it is invalid.
      '''
      assert certType in [ cls.DCA, cls.CVP ], (
             'Invalid certificate type: %s' % certType )

   def __repr__( self ):
      return 'Certificate("%s", %s)' % ( self.commonName, self.certType )

class CSR( CertificateInfo ):
   '''
   This class represents a X.509 certificate signing request.
   '''
   def __init__( self, commonName, subjectAlternateNameIPList,
            subjectAlternateNameDNSList, organization, organizationUnit, location,
            state, country, encryptionAlgorithm, digestAlgorithm, keyLength,
            emailId, description ):
      super( CSR, self ).__init__( commonName, subjectAlternateNameIPList,
            subjectAlternateNameDNSList, organization, organizationUnit, location,
            state, country, encryptionAlgorithm, digestAlgorithm, keyLength,
            description )
      # No other instance variable should be added as this object will be converted
      # to dictionary/json and used in Cvp.generateCSR().
      self.emailId = emailId

   def getSubject( self ):
      return "CN=%s, O=%s, OU=%s, L=%s, ST=%s, C=%s/emailAddress=%s" % ( self.commonName,
         self.organization, self.organizationUnit, self.location, self.state,
         self.country, self.emailId )

class Cvp( Jsonable ):
   '''Class Cvp represents an instance of CVP. It provides high level python
   APIs to retrieve and modify CVP state.'''

   def __init__( self, host, ssl=True, port=443, tmpDir='' ):
      super( Cvp, self ).__init__( )
      self.cvpService = cvpServices.CvpService( host, ssl, port, tmpDir )

   def __repr__( self ):
      return 'Cvp "%s"' % self.url()

   def hostIs( self, host ):
      self.cvpService.hostIs( host )

   def url( self ):
      return self.cvpService.url( )

   def sessionIs( self, sessionId ):
      '''Choose a particular user session. This is meant to be used from a
         configbuilder to avoid authenticating with a username/password and to
         instead use session id.
      Arguments:
        sessionId - id of an already open user session.
      '''
      self.cvpService.sessionIs( sessionId )

   def authenticate( self, username, password ):
      '''Authenticate the user login credentials
      Arguments:
         username -- username for login ( type : string )
         password -- login pasword (type : String )
      Raises:
         CvpError -- If invalid login credentials
      '''
      self.cvpService.authenticate( username, password )

   def logout( self ):
      '''Logging session out
      Raises:
         CvpError -- If invalid session
      '''
      self.cvpService.logout()

   def _getContainerConfigletMap( self, configletNameList ):
      '''Finds which configlets are  mapped to which containers'''
      configletMap = {}
      for configletName in configletNameList:
         containersInfo = self.cvpService.configletAppliedContainers( configletName )
         for containerInfo in containersInfo:
            configletNameList = []
            key = containerInfo[ 'containerName' ]
            if key in configletMap:
               configletNameList = configletMap[ containerInfo[ 'containerName' ] ]
               configletNameList.append( configletName )
               configletMap[ containerInfo[ 'containerName' ] ] = configletNameList
            else :
               configletNameList.append( configletName )
               configletMap[ containerInfo[ 'containerName' ] ] = configletNameList
      return configletMap

   def _getContainerImageBundleMap( self, imageBundleNameList ):
      '''Finds which image bundle is mapped to which containers.'''
      imageBundleMap = {}
      for imageBundleName in imageBundleNameList:
         containersInfo = self.cvpService.imageBundleAppliedContainers(
                                                                    imageBundleName )
         for containerInfo in containersInfo:
            imageBundleMap[ containerInfo[ 'containerName' ] ] = imageBundleName
      return imageBundleMap

   def _getDeviceImageBundleMap( self, imageBundleNameList ):
      '''Finds which image bundle is mapped to which devices.'''
      imageBundleMap = {}
      for imageBundleName in imageBundleNameList:
         devicesInfo = self.cvpService.imageBundleAppliedDevices( imageBundleName )
         for deviceInfo in devicesInfo:
            imageBundleMap[ deviceInfo [ 'ipAddress' ] ] = imageBundleName
      return imageBundleMap

   def _getImageBundleNameList( self ):
      ''' finds the list of image bundles present in the cvp instance'''
      imageBundleNameList = []
      imageBundlesInfo = self.cvpService.getImageBundles()
      for imageBundleInfo in imageBundlesInfo:
         imageBundleNameList.append( imageBundleInfo[ 'name' ] )
      return imageBundleNameList

   def _getConfigletNameList( self ):
      '''finds the list of configlets present in the cvp instance'''
      configletNameList = []
      configletsInfo = self.cvpService.getConfigletsInfo()
      for configletInfo in configletsInfo:
         configletNameList.append( configletInfo[ 'name' ] )
      return configletNameList

   def getDevices( self, provisioned=True ):
      '''Collect information of all the devices. Information of device consist
      of the device specifications like ip address, mac address( key ), configlets
      and image bundle applied to device.
      Arguments:
         provisioned- False would get all onboarded devices,True would get only the provisioned ones
      Returns:
         deviceList -- List of device ( type : List of Device ( class ) )
      '''
      imageBundleNameList = self._getImageBundleNameList()
      imageBundleMap = self._getDeviceImageBundleMap( imageBundleNameList )
      devicesInfo, containersInfo = self.cvpService.getInventory( provisioned=provisioned)
      deviceList = []
      for deviceInfo in devicesInfo:
         deviceMacAddress = deviceInfo[ 'systemMacAddress' ]
         if deviceMacAddress not in containersInfo:
            if provisioned:
               raise cvpServices.CvpError( errorCodes.INVALID_CONTAINER_NAME )
            else:
               parentContainerName = ""
               configletNames = None
         else:
            parentContainerName = containersInfo[ deviceInfo[ 'systemMacAddress' ] ]
            configletsInfo = self.cvpService.getDeviceConfiglets( deviceMacAddress )
            configletNames = [ configlet[ 'name' ] for configlet in configletsInfo ]
         appliedImageBundle = []
         if deviceInfo[ 'ipAddress' ] in imageBundleMap:
            appliedImageBundle = imageBundleMap[ deviceInfo[ 'ipAddress' ] ]
         cc = DEVICE_IN_COMPLIANCE if not deviceInfo[ 'complianceCode' ] else \
                        int( deviceInfo[ 'complianceCode'] )
         deviceList.append( Device( ipAddress=deviceInfo[ 'ipAddress' ],
                                    fqdn= deviceInfo[ 'fqdn' ],
                                    macAddress=deviceMacAddress,
                                    containerName=parentContainerName,
                                    imageBundle=appliedImageBundle,
                                    configlets=configletNames,
                                    status=deviceInfo[ 'status' ],
                                    model=deviceInfo[ 'modelName' ],
                                    sn=deviceInfo[ 'serialNumber' ],
                                    complianceCode=cc ) )
      return deviceList

   def _getContainerInfo( self, containerName ):
      '''Returns container information for given container name'''
      containersInfo = self.cvpService.searchTopology(
                       containerName )[ 'containerList' ]
      if not containersInfo:
         raise cvpServices.CvpError( errorCodes.INVALID_CONTAINER_NAME )
      for containerInfo in containersInfo:
         # Container names are not case sensitive
         if containerInfo[ 'name' ].lower() == containerName.lower():
            return containerInfo
      return None

   def getDevice( self, deviceMacAddress, provisioned=True ):
      '''Retrieve information about device like ip address, mac address( key ),
      configlets and image bundle applied to device.
      Arguments:
         provisioned- False would get all onboarded devices,True would get only the provisioned ones
      Returns:
         device -- Information about the device ( type : Device ( class ) )
      '''
      imageBundleNameList = self._getImageBundleNameList()
      imageBundleMap = self._getDeviceImageBundleMap( imageBundleNameList )
      devicesInfo, containersInfo = self.cvpService.getInventory( provisioned=provisioned )
      for deviceInfo in devicesInfo:
         if deviceInfo[ "systemMacAddress" ] != deviceMacAddress:
            continue
         if deviceMacAddress not in containersInfo:
            raise cvpServices.CvpError( errorCodes.INVALID_CONTAINER_NAME )
         parentContainerName = containersInfo[ deviceMacAddress ]
         configletsInfo = self.cvpService.getDeviceConfiglets(
                 deviceInfo[ "systemMacAddress"] )
         configletNames = [ configlet[ 'name' ] for configlet in configletsInfo ]
         appliedImageBundle = []
         if deviceInfo[ 'ipAddress' ] in imageBundleMap:
            appliedImageBundle = imageBundleMap[ deviceInfo[ 'ipAddress' ] ]
         cc = DEVICE_IN_COMPLIANCE if not deviceInfo[ 'complianceCode' ] else \
                        int( deviceInfo[ 'complianceCode'] )
         device = Device( ipAddress=deviceInfo[ 'ipAddress' ],
                          fqdn=deviceInfo[ 'fqdn' ],
                          macAddress=deviceMacAddress,
                          containerName=parentContainerName,
                          imageBundle=appliedImageBundle,
                          configlets=configletNames,
                          status=deviceInfo[ 'status' ],
                          model=deviceInfo[ 'modelName' ],
                          sn=deviceInfo[ 'serialNumber' ],
                          complianceCode=cc )
         return device
      return None

   def getConfiglets( self, configletNames='' ):
      '''Retrieve the full set of Configlets
      Returns:
         configletList -- information of all configlets
            ( type : List of Configlet ( class ) )
      '''
      configletList = []
      configlets = []
      configletsInfo = self.cvpService.getConfigletsInfo()
      for configletInfo in configletsInfo:
         # getConfiglet returns unused configlets as None
         configlet = self.getConfiglet( configletInfo[ 'name' ] )
         if configlet:
            configletList.append( configlet )
      if configletNames:
         configlets = [ configlet for configlet in configletList if
                        str( configlet.name ).lower() in configletNames ]
      else:
         configlets = configletList
      return configlets

   def getContainers( self ):
      '''Retrieve the hierarchy of the containers and store information on all
      of these containers. Information of container consist of specifications
      like container name, configlets and image bundle applied to container.
      Returns:
         containers -- list of container informations
            ( type : List of Container ( class ) )
      '''
      imageBundleNameList = self._getImageBundleNameList()
      imageBundleMap = self._getContainerImageBundleMap( imageBundleNameList )
      containersInfo = self.cvpService.filterTopology()
      rawContainerInfoList = []
      rawContainerInfoList.append( containersInfo )
      containers = []
      containers = self._recursiveParse( containers, rawContainerInfoList,
                                         imageBundleMap, '' )
      return containers

   def _recursiveParse( self, containers, childContainerInfoList,
                        imageBundleMap, parentContainerName):
      ''' internal function for recursive depth first search to obtain container
      information from the container hierarchy. It handles different cases
      like the configlet applied or not, image bundle applied or not to containers'''
      for containerInfo in childContainerInfoList:
         if containerInfo[ 'childContainerList' ]:
            containers = self._recursiveParse( containers,
                                 containerInfo[ 'childContainerList' ],
                                 imageBundleMap, containerInfo[ 'name' ] )
         containerName = containerInfo[ 'name' ]
         containerKey = containerInfo[ 'key' ]
         configletsInfo = self.cvpService.getContainerConfiglets( containerKey )
         configletNames = [ configlet[ 'name' ] for configlet in configletsInfo ]
         appliedImageBundle = None
         if containerName in imageBundleMap:
            appliedImageBundle = imageBundleMap[ containerName ]
         containers.append( Container( containerName, parentContainerName,
                                       configletNames, appliedImageBundle ) )
      return containers

   def getContainer( self, containerName ):
      '''Retrieve container Information like container name, configlets and
      image bundle applied to the container
      Arguments
         ContainerName -- name of the container ( type : String )
      Raises:
         CvpError -- If container name is invalid
      Returns:
         containerInfo -- Information about the container
         ( type : Container( class ) )
      '''
      containerInfo = self._getContainerInfo( containerName )
      imageBundleNameList = self._getImageBundleNameList()
      imageBundleMap = self._getContainerImageBundleMap( imageBundleNameList )
      parentName = ''
      containerName = containerInfo[ 'name' ]
      containerKey = containerInfo[ 'key' ]
      if containerInfo[ 'key' ] != 'root':
         parentName = self.cvpService.getContainerInfoByKey(
                           containerKey )[ 'parentName' ]
      configletsInfo = self.cvpService.getContainerConfiglets( containerKey )
      configletNames = [ configlet[ 'name' ] for configlet in configletsInfo ]
      appliedImageBundle = None
      if containerName in imageBundleMap:
         appliedImageBundle = imageBundleMap[ containerName ]
      return Container( containerName, parentName, configletNames,
                        appliedImageBundle )

   def getUndefContainerInfo( self ):
      ''' retrieves information about the undefined container
      Returns:
         containerInfo -- Information about the undefined container
         ( type : Container( class ) )
      '''
      containerInfo = self.cvpService.getContainerInfoByKey(
                                                    cvpServices.UNDEF_CONTAINER_KEY )
      return self.getContainer( containerInfo[ 'name' ] )

   def getThemes( self, storageDirPath='' ):
      '''Themes are downloaded and saved to the directory given by "storageDirPath"
      Argument:
         storageDirPath -- path to directory for storing theme files ( optional )
            ( type : String )
      Returns:
         themeList -- List of themes downloaded
            ( type : List of Theme ( class ) )'''
      themeList = []
      themeFilenamesByType = self.cvpService.getThemes( storageDirPath )
      for themeType in themeFilenamesByType.keys():
         themeFilenames = themeFilenamesByType[ themeType ]
         for i in range( len( themeFilenames ) ):
            themeFilename = themeFilenames[ i ]
            # first theme is the active theme
            themeList.append( Theme( themeFilename, themeType,
                              isActive=( i == 0 ) ) )
      return themeList

   def getImages( self , storageDirPath='', download=False ):
      '''Images are downloaded and saved in directory path given by "storageDirPath"
      Argument:
         storageDirPath -- path to directory for storing image files ( optional )
            ( type : String )
      Returns:
         imageNameList -- List of inforamtion of images downloaded
            ( type : List of Image ( class ) )'''
      imageList = []
      imagesInfo = self.cvpService.getImagesInfo()
      for imageInfo in imagesInfo:
         rebootRequired = ( imageInfo[ 'isRebootRequired' ] == 'true' )
         imageList.append( Image( imageInfo[ 'name' ], rebootRequired ) )
         if download:
            self.cvpService.downloadImage( imageInfo[ 'name' ],
                                           imageInfo[ 'imageId' ],
                                           storageDirPath )
      return imageList

   def reconcileDeviceConfig( self, device, configlets ):
      '''
      Validate the given "configlets", and reconcile against "device".
      If a reconcile configlet is generated as a result, return that, or None.
      Note that the reconcile configlet needs to be explicitly added to CVP and
      mapped to the device by the caller, if desired.
      Arguments:
         device -- device object
         configlets -- List of configlets applied to device
      Returns
         Reconcile configlet, or None
      '''
      configletKeyList = self._getConfigletKeys( [ c.name for c in configlets ] )
      return self._getReconciledConfiglet( device, configletKeyList )

   def _getReconciledConfiglet( self, device, configletKeyList ):
      '''
      Validate the configlets with keys in "configleyKeyList", and reconcile
      against "device".
      If a reconcile configlet is generated as a result, return that, or None.
      Note that the reconcile configlet needs to be explicitly added to CVP and
      mapped to the device by the caller, if desired.
      Arguments:
         device -- device object
         configletKeyList -- List of keys of configlets applied to device
      Returns
         Reconcile configlet, or None
      '''
      validateResponse = self.cvpService.validateAndCompareConfiglets(
            device.macAddress, configletKeyList )
      if not validateResponse[ 'reconciledConfig' ]:
         # No reconcile configlet generated
         return None
      reconcile = ReconciledConfiglet(
            validateResponse[ 'reconciledConfig' ][ 'name' ],
            validateResponse[ 'reconciledConfig' ][ 'config' ],
            device.macAddress )
      return reconcile

   def reconcileContainer( self, container, wait=True, timeout=0 ):
      '''Initiate a reconcile operation on 'container'. This generates an event.
      If wait == True, wait for the event to finish, and return the consolidated
      report for all devices under the container. timeout is the number of seconds
      to wait for, or indefinitely if 0.
      If wait == False, Otherwise, just return an event
      ID. The caller can call getEvent*() later to query its status.
      Returns: Event results or event ID.
      Raises: CvpError in case of any error.
      '''
      assert isinstance( container, Container )
      containerInfo = self._getContainerInfo( container.name )
      if not containerInfo:
         raise cvpServices.CvpError( errorCodes.INVALID_CONTAINER_NAME  )
      containerId = containerInfo.get( 'key' )

      eventId = self.cvpService.reconcileContainer( containerId )[ 'data' ]
      if wait:
         # wait for the event to complete
         end = time.time() + timeout
         while True:
            if timeout != 0 and time.time() >= end:
               break
            parentEventData = self.cvpService.getEvent( eventId )[ 'data' ]
            if parentEventData[ 'status' ] == 'COMPLETED':
               childEventData = self.cvpService.getChildEventData( eventId )
               assert parentEventData[ 'total' ] == childEventData[ 'total' ]
               events = []
               for subEvent in childEventData[ 'data' ]:
                  assert eventId == subEvent[ 'parentKey' ]
                  assert subEvent[ 'status' ] == 'COMPLETED'
                  events.append( Event( subEvent[ 'key' ],
                                        subEvent[ 'parentKey' ],
                                        subEvent[ 'objectId' ],
                                        subEvent[ 'eventType' ],
                                        subEvent[ 'status' ],
                                        int( subEvent[ 'data' ][ 'complianceCode' ] ),
                                        subEvent[ 'message' ],
                                        subEvent[ 'errors' ],
                                        subEvent[ 'warning' ],
                                        subEvent[ 'data' ] ) )
               return events
            else:
               time.sleep( 1 )

         if timeout != 0 and time.time() >= end:
            # raise timeout error
            raise cvpServices.CvpError( errorCodes.TIMEOUT )
      else:
         return eventId

   def getImage( self, imageName , storageDirPath='', download=False ):
      ''' Image is downloaded and saved in directory path given by "storageDirPath"
      Argument :
         imageName -- name of image to be downloaded ( type : String )
         storageDirPath -- path to directory for storing image files ( optional )
         ( type : String )
      Raises:
         CvpError -- If image name is incorrect
      '''
      imagesInfo = self.cvpService.getImagesInfo()
      imagePresentFlag = False
      for imageInfo in imagesInfo:
         if imageInfo[ 'name' ] == imageName:
            rebootRequired = ( imageInfo[ 'isRebootRequired' ] == 'true' )
            image = Image( imageInfo[ 'name' ], rebootRequired )
            imagePresentFlag = True
            if download:
               self.cvpService.downloadImage( imageInfo[ 'name' ],
                                              imageInfo[ 'imageId' ],
                                              storageDirPath )
            break
      if imagePresentFlag == False:
         raise cvpServices.CvpError( errorCodes.INVALID_IMAGE_NAME )
      return image

   def getConfiglet( self, configletName ):
      '''Retrieve a specific configlet.
      Argument:
         configletName -- name of the configlet ( type : String )
      Raises:
         CvpError : If configlet name is invalid
      Returns:
         Configlet -- information of the configlet ( type : Configlet ( class ) )
      '''
      configletInfo = self.cvpService.getConfigletByName( configletName )
      genConfigMapInfo = self.cvpService.getConfigletMapper()
      if ( configletInfo[ 'type' ] == 'Static' and
           configletInfo[ 'reconciled' ] == False ):
         return Configlet( configletInfo[ 'name' ], configletInfo[ 'config' ],
                           configletType=configletInfo[ 'type' ],
                           user=configletInfo[ 'user' ],
                           sslConfig=configletInfo[ 'sslConfig' ] )
      elif ( configletInfo[ 'type' ] == 'Static' and
             configletInfo[ 'reconciled' ] == True ):
         for configlet in genConfigMapInfo[ 'configletMappers' ]:
            if configlet[ 'configletId' ] == configletInfo[ 'key' ]:
               return ReconciledConfiglet( configletInfo[ 'name' ],
                                 configletInfo[ 'config' ], configlet[ 'objectId' ],
                                 user=configletInfo[ 'user' ] )
      elif configletInfo[ 'type' ] == 'Generated':
         for genConfiglet in genConfigMapInfo[ 'generatedConfigletMappers' ]:
            if configletInfo[ 'key' ] == genConfiglet[ 'configletId' ]:
               builderInfo = self.cvpService.getConfigletBuilder(
                                    genConfiglet[ 'configletBuilderId' ] )
               containerInfo = self.cvpService.getContainerInfoByKey(
                                    genConfiglet[ 'containerId' ] )
               containerName = containerInfo[ 'name' ]
               return GeneratedConfiglet( configletInfo[ 'name' ],
                                    configletInfo[ 'config' ], builderInfo[ 'name' ],
                                    containerName, genConfiglet[ 'netElementId' ],
                                    user=configletInfo[ 'user' ],
                                    sslConfig=configletInfo[ 'sslConfig' ] )
      elif configletInfo[ 'type' ] == 'Builder':
         configletBuilderInfo = self.cvpService.getConfigletBuilder(
                                  configletInfo[ 'key' ] )
         self._removeFormKeys( configletBuilderInfo )
         return ConfigletBuilder( configletInfo[ 'name' ],
                                  configletBuilderInfo[ 'formList' ],
                                  configletBuilderInfo[ 'main_script' ][ 'data' ],
                                  user=configletInfo[ 'user' ],
                                  sslConfig=configletInfo[ 'sslConfig' ] )
      else:
         raise cvpServices.CvpError( errorCodes.INVALID_CONFIGLET_TYPE, "Invalid"
                               " configlet type : %s configlet name : %s" % (
                               configletInfo[ 'type' ], configletInfo[ 'name' ] ) )

   def _removeFormKeys( self, configletBuilderInfo ):
      '''remove keys from the forms'''
      for form in configletBuilderInfo[ 'formList' ]:
         if 'configletBuilderId' in form:
            del form[ 'configletBuilderId' ]
         if 'key' in form:
            del form[ 'key' ]

   def addConfiglet( self, configlet ):
      '''Add a configlet to cvp inventory.
         Note that configlet.user is ignored, and the configlet is marked as added
         by the user that's currently authenticated.
      Argument:
         configlet -- information of the new configlet
            ( type : Configlet ( class ) )
      Raises:
         CvpError -- If configlet name is invalid
      '''
      assert isinstance( configlet, Configlet )
      if isinstance( configlet, ConfigletBuilder ):
         self.cvpService.addConfigletBuilder( configlet.name,
                                           configlet.formList, configlet.mainScript )
      # Configlet object has type not but not used as the underlying api doesn't support it.
      elif isinstance( configlet, GeneratedConfiglet ):
         self._addGeneratedConfiglet( configlet )
      elif isinstance( configlet, ReconciledConfiglet ):
         self.cvpService.addReconciledConfiglet( configlet.name, configlet.config,
                                                 configlet.deviceMac )
      elif isinstance( configlet, Configlet ):
         self.cvpService.addConfiglet( configlet.name, configlet.config )
      else:
         raise cvpServices.CvpError( errorCodes.INVALID_CONFIGLET_TYPE, "Invalid"
                               " configlet type : %s, configlet name : %s" % (
                               configlet.configletType, configlet.name ) )

   def _addGeneratedConfiglet( self, configlet ):
      '''Adds the mapping be the generated configlets, devices and containers'''
      containerInfo = self._getContainerInfo( configlet.containerName )
      containerId = containerInfo[ 'key' ]
      builderInfo = self.cvpService.getConfigletByName( configlet.builderName )
      builderId = builderInfo[ 'key' ]
      self.cvpService.addGeneratedConfiglet( configlet.name, configlet.config,
                                             containerId, configlet.deviceMac,
                                             builderId )

   def updateConfiglet( self, configlet, waitForTaskIds=False ):
      ''' updating an existing configlet in Cvp instance
      Argument:
          configlet -- updated information of the configlet
            ( type : Configlet ( class ) )
          waitForTaskIds -- should the API return task ids ( type : Boolean )
      Returns:
         if waitForTaskIds is True, this function waits for any tasks to be created
         as a result of updating the configlet, and returns the list of tasks.
         Otherwise, None.
         List of Tasks -- list of the generated tasks ( type : List of Tasks )
      Raises:
         CvpError -- If configlet name is invalid
      '''
      assert isinstance( configlet, Configlet )
      configletInfo = self.cvpService.getConfigletByName( configlet.name )
      configletKey = configletInfo[ 'key' ]
      listOfTasks = []
      listOfTaskIds = []
      if isinstance( configlet, ConfigletBuilder ):
         self._insertCBFormKeys( configlet, configletKey )
         listOfTaskIds = self.cvpService.updateConfigletBuilder( configlet.name,
            configlet.formList, configlet.mainScript, configletKey,
            waitForTaskIds=waitForTaskIds )
      elif isinstance( configlet, ReconciledConfiglet ):
         self.cvpService.updateReconciledConfiglet( configlet.name,
                               configlet.config, configletKey, configlet.deviceMac )
      else:
         listOfTaskIds = self.cvpService.updateConfiglet( configlet.name,
                                    configlet.config, configletKey, waitForTaskIds )
      if listOfTaskIds:
         tids = [ int( t ) for t in listOfTaskIds ]
         for tid in tids:
            info = self.cvpService.getTaskById( tid )
            task = Task( tid, info[ 'workOrderUserDefinedStatus' ],
	                 info[ 'description' ] )
            listOfTasks.append( task )
      return listOfTasks

   def _insertCBFormKeys( self, configlet, configletKey ):
      '''Retrieves the keys of the forms'''
      currCB = self.cvpService.getConfigletBuilder( configletKey )
      currForms = currCB[ 'formList' ]
      formKeys = {}
      for form in currForms:
         formKeys[ form[ 'fieldId' ] ] = form[ 'key' ]
      for form in configlet.formList:
         if form[ 'fieldId' ] in formKeys:
            form[ 'key' ] = formKeys[ form[ 'fieldId' ] ]

   def deleteConfiglet( self, configlet ):
      '''Remove a configlet from the Cvp instance
      Argument:
         configlet -- information of the configlet to be removed
            ( type : Confgilet ( class ) )
      Raises:
         CvpError -- If configlet name is invalid
      '''
      assert isinstance( configlet, Configlet )
      configletInfo = self.cvpService.getConfigletByName( configlet.name )
      configletKey = configletInfo[ 'key' ]
      self.cvpService.deleteConfiglet( configlet.name, configletKey )

   def updateImageBundle( self, imageBundle, imageList ):
      '''update an image bundle in Cvp instance
      Argument:
         imageBundle -- updated image bundle information.
            ( type : ImageBundle ( class ) )
         imageList -- image objects list ( type : List Image Class )
      Raises:
         CvpError -- If image bundle name is invalid
      '''
      assert isinstance( imageBundle, ImageBundle )
      assert all ( isinstance( image, Image ) for image in imageList )
      currImageBundle = self.cvpService.getImageBundleByName( imageBundle.name )
      imageBundleKey = currImageBundle[ 'key' ]
      imageDataList = []
      for image in imageList:
         imageData = self._addImage( str( image.name ) )
         if image.rebootRequired == True:
            imageData[ 'isRebootRequired' ] = 'true'
         else:
            imageData[ 'isRebootRequired' ] = 'false'
         imageDataList.append( imageData )
      self.cvpService.updateImageBundle( imageBundle.name, imageBundle.certified,
                                         imageDataList, imageBundleKey )

   def addImageBundle( self, imageBundle, imageList, imagesSrcDir='' ):
      ''' Add an image bundle with an image.
      Arguments:
         imageBundle -- image bundle inforamtion object ( type: ImageBundle class )
         imageList -- image objects list ( type : List Image Class )
         imagesSrcDir -- path to the image source directory ( type : str )
      Raises:
         CvpError -- If image bundle with same name already exists
      '''
      assert isinstance( imageBundle, ImageBundle )
      assert all ( isinstance( image, Image ) for image in imageList )
      imageInfoList = []
      for image in imageList:
         imageData = self._addImage( str( image.name ), imagesSrcDir )
         if image.rebootRequired == True:
            imageData[ 'isRebootRequired' ] = 'true'
         else:
            imageData[ 'isRebootRequired' ] = 'false'
         imageInfoList.append( imageData )
      self.cvpService.saveImageBundle( imageBundle.name, imageBundle.certified,
                                       imageInfoList )

   def _convertToImageData( self, imageInfo ):
      '''
      Convert imageInfo to imageData format
      Returns:
         imageData -- condensed information about image
      '''
      imageData = { 'name' : imageInfo[ 'name' ],
                    'imageSize' : imageInfo[ 'imageSize' ],
                    'md5' : imageInfo[ 'md5' ],
                    'version' : imageInfo[ 'version' ],
                    'swiMaxHwepoch' : imageInfo[ 'swiMaxHwepoch' ],
                    'swiVarient' : imageInfo[ 'swiVarient' ] }
      return imageData

   def _addImage( self, imageName, imagesSrcDir='' ):
      '''Check if image is already present in CVP instance or not.
      If not then add the image to the CVP in instance.
      Arguments:
         imageName -- Name of the image to add ( type : str )
         imagesSrcDir -- path to the image source directory ( type : str )
      Returns:
         imageData -- information of the added image
      '''
      imageAddFlag = False
      imagesInfo = self.cvpService.getImagesInfo()
      for imageInfo in imagesInfo:
         if imageInfo[ 'name' ] == os.path.basename( imageName ):
            imageAddFlag = True
            break
      if imageAddFlag == False:
         imageInfo = self.cvpService.addImage( imageName, imagesSrcDir )
         imageData = self._convertToImageData( imageInfo )
         return imageData
      else:
         for imageInfo in imagesInfo:
            if os.path.basename( imageName ) == imageInfo['name']:
               imageData = self._convertToImageData( imageInfo )
         return imageData

   def addImage( self, image, strDirPath='.' ):
      '''Adds image to the Cvp Instance'''
      assert isinstance( image, Image )
      self.cvpService.addImage( image.name, strDirPath )

   def addTheme( self, theme, strDirPath='.' ):
      '''Adds theme to the Cvp Instance '''
      assert isinstance( theme, Theme )
      themeFilename = theme.name
      themeType = theme.themeType
      themeInfo = self.cvpService.addTheme( themeFilename, themeType, strDirPath )
      if theme.isActive: #theme
         self.cvpService.applyTheme( themeInfo[ 'key' ], themeType )

   def mapImageBundleToDevice( self, device, imageBundle, force=False ):
      '''Map image Bundle to device
      Arguments:
         imageBundle -- image bundle object ( type : ImageBundle( class ) )
         device -- name of the device ( type : Device ( class ) )
         force -- do map even if the same bundle is already mapped to it
      Raises:
         CvpError -- If image bundle name is invalid
      Returns:
         taskIdList -- List of task ids
      '''
      assert isinstance( device, Device )
      assert isinstance( imageBundle, ImageBundle )
      imageBundleKey = ''
      imageBundleInfo = self.cvpService.getImageBundleByName( imageBundle.name )
      imageBundleKey = imageBundleInfo[ 'key' ]
      currDeviceImageMapper = self.cvpService.getDeviceImageBundleMapper(
                                                                  device.macAddress )
      if not force and imageBundleKey in currDeviceImageMapper:
         return
      if imageBundleKey == '':
         raise cvpServices.CvpError( errorCodes.INVALID_IMAGE_BUNDLE_NAME )
      return self.cvpService.applyImageBundleToDevice( device.macAddress,
                                                       device.fqdn,
                                                       imageBundle.name,
                                                       imageBundleKey )

   def mapImageBundleToContainer( self, container, imageBundle ):
      '''Map imageBundle to container
      Arguments:
         container -- type : Container class
         imageBundle --  type : ImageBundle Class
      Raises:
         CvpError -- If container name or image bundle name is invalid
      Returns:
         taskIdList -- List of task ids
      '''
      assert isinstance( container, Container )
      assert isinstance( imageBundle, ImageBundle )

      if container.name == 'Undefined':
         containerKey = 'undefined_container'
      else:
         containerInfo = self._getContainerInfo( container.name )
         containerKey = containerInfo[ 'key' ]

      imageBundleKey = ''
      imageBundleInfo = self.cvpService.getImageBundleByName( imageBundle.name )
      imageBundleKey = imageBundleInfo[ 'key' ]
      if imageBundleKey == '':
         raise cvpServices.CvpError( errorCodes.INVALID_IMAGE_BUNDLE_NAME )
      return self.cvpService.applyImageBundleToContainer( container.name,
                                                          containerKey,
                                                          imageBundle.name,
                                                          imageBundleKey )

   def removeImageBundleAppliedToContainer( self, container, imageBundle ):
      '''Removes image bundle applied to the Container
      Arguments:
         container -- type : Container class
         imageBundle -- type : ImageBundle Class
      Returns:
         taskIdList -- List of task ids
      '''
      assert isinstance( container, Container )
      assert isinstance( imageBundle, ImageBundle )
      imageBundleKey = ''
      containerInfo = self._getContainerInfo( container.name )
      containerKey = containerInfo[ 'key' ]
      imageBundleInfo = self.cvpService.getImageBundleByName( imageBundle.name )
      imageBundleKey = imageBundleInfo[ 'key' ]
      if imageBundleKey == '':
         raise cvpServices.CvpError( errorCodes.INVALID_IMAGE_BUNDLE_NAME )
      self.cvpService.removeImageBundleAppliedToContainer( container.name,
                                    containerKey, imageBundle.name, imageBundleKey )

   def _getConfigletKeys( self, configletNameList ):
      '''Returns keys for corresponding configlet names in the
      configletNameList'''
      configletKeyList = []
      configletNum = len( configletNameList )
      configletsInfo = self.cvpService.getConfigletsInfo()
      configletsInfoDict = {}
      for configletInfo in configletsInfo:
         configletsInfoDict[ configletInfo [ 'name' ] ] = configletInfo[ 'key' ]
      configletKeyList = [ configletsInfoDict [ name ] for name
                           in configletNameList if name in configletsInfoDict ]
      if len( configletKeyList ) < configletNum:
         raise cvpServices.CvpError( errorCodes.INVALID_CONFIGLET_NAME )
      return configletKeyList

   def mapConfigletToContainer( self, container, configletList ):
      '''Map the configlets to container
      Arguments:
         container -- type : Container class
         configletList -- List of configlet objects to be applied
               ( type : List of Configlet Class )
      Raises:
         CvpError -- If the configlet names or container name are invalid
      Returns:
         taskIdList -- List of task ids
      '''
      assert isinstance( container, Container )
      assert all ( isinstance( configlet, Configlet ) for configlet in
                                                                      configletList )
      containerInfo = self._getContainerInfo( container.name )
      containerKey = containerInfo[ 'key' ]
      configletsInfo = self.cvpService.getContainerConfiglets( containerKey )
      actionReqd, cnl, ckl, cbnl, cbkl = self._checkNewConfigMapping( configletsInfo,
                                                                      configletList )
      if actionReqd:
         return self.cvpService.applyConfigletToContainer( container.name,
                                                           containerKey,
                                                    cnl, ckl, cbnl, cbkl )

   def _checkNewConfigMapping( self, appliedConfigs, newConfigletList,
                               device=None ):
      ''' Checks whether the new configlets to be applied to CVP objects ( Device,
      Container ) are already applied or not. Returns actionRegd ( flag ), final cnl,
      cknl, cbnl, cbkl'''
      cnl = []
      ckl = []
      cbnl = []
      cbkl = []
      appliedConfigNames = []
      appliedCBNames = []
      actionReqd = False
      for configlet in appliedConfigs:
         if configlet[ 'type' ] in [ 'Static', 'Generated', 'Reconciled' ]:
            appliedConfigNames.append( configlet[ 'name' ] )
         elif configlet[ 'type' ] == 'Builder':
            appliedCBNames.append( configlet[ 'name' ] )
         else:
            raise cvpServices.CvpError( errorCodes.INVALID_CONFIGLET_TYPE,
                  "Invalid configlet type Error: configlet name : %s, type: %s" % (
                  configlet[ 'name' ], configlet[ 'type' ] ) )
      for configlet in newConfigletList:
         if ( configlet.name not in appliedConfigNames and configlet.name not in
              appliedCBNames ):
            if configlet.configletType in [ 'Static', 'Generated', 'Reconciled' ]:
               cnl.append( configlet.name )
            elif configlet.configletType == 'Builder':
               cbnl.append( configlet.name )
            else:
               raise cvpServices.CvpError( errorCodes.INVALID_CONFIGLET_TYPE,
                  "Invalid configlet type Error: configlet name : %s, type: %s" % (
                  configlet.name, configlet.configletType ) )
      cnl = appliedConfigNames + cnl
      cbnl = appliedCBNames + cbnl
      if cnl != appliedConfigNames or cbnl != appliedCBNames:
         actionReqd = True
      ckl = self._getConfigletKeys( cnl )
      cbkl = self._getConfigletKeys( cbnl )
      return actionReqd, cnl, ckl, cbnl, cbkl


   def _checkRemoveConfigMapping( self, appliedConfigs, rmConfigletList ):
      '''Creates the list of configlets that needs to be there after removal of
      specific configlets'''
      cnl = []
      cbnl = []
      rmCnl = []
      rmCbnl = []
      for configlet in rmConfigletList:
         if configlet.configletType in [ 'Static', 'Generated', 'Reconciled' ]:
            rmCnl.append( configlet.name )
         elif configlet.configletType == 'Builder':
            rmCbnl.append( configlet.name )
         else:
            raise cvpServices.CvpError( errorCodes.INVALID_CONFIGLET_TYPE,
               "Invalid configlet type Error: configlet name : %s, type: %s" % (
               configlet.name, configlet.configletType ) )
      actionReqd = False

      for configlet in appliedConfigs:
         if ( ( configlet[ 'name' ] not in rmCnl ) and ( configlet[ 'name' ]
               not in rmCbnl ) ):
            actionReqd = True
            if configlet[ 'type' ] in [ 'Static', 'Generated', 'Reconciled' ] :
               cnl.append( configlet[ 'name' ] )
            elif configlet[ 'type' ] == 'Builder':
               cbnl.append( configlet[ 'name' ] )
            else:
               raise cvpServices.CvpError( errorCodes.INVALID_CONFIGLET_TYPE,
                     ( "Invalid configlet type Error: configlet name : %s, type: %s"
                     % ( configlet[ 'name' ], configlet[ 'type' ] ) ) )
      if not cnl and not cbnl:
         actionReqd = True
      return actionReqd, cnl, cbnl, rmCnl, rmCbnl

   def removeConfigletAppliedToContainer( self, container, configletList ):
      '''remove configlet mapped to containers
      Arguments:
         container -- type : Container class
         configletList -- List of configlet objects to be removed
            ( type : List of Configlet Class )
      Raises:
         CvpError -- If the configlet names or container name are invalid
      Returns:
         taskIdList -- List of task ids
      '''
      assert isinstance( container, Container )
      assert all ( isinstance( configlet, Configlet ) for configlet in
                                                                      configletList )
      configletNameList = []
      for configlet in configletList:
         configletNameList.append( configlet.name )
      if not configletNameList:
         return 'No configlets to remove'
      containerInfo = self._getContainerInfo( container.name )
      containerKey = containerInfo[ 'key' ]
      configletsInfo = self.cvpService.getContainerConfiglets( containerKey )
      actionReqd, cnl, cbnl, rmCnl, rmCbnl = self._checkRemoveConfigMapping(
                                          configletsInfo, configletList )
      if actionReqd:
         containerInfo = self._getContainerInfo( container.name )
         containerKey = containerInfo[ 'key' ]
         ckl = self._getConfigletKeys( cnl )
         cbkl = self._getConfigletKeys( cbnl )
         rmCkl = self._getConfigletKeys( rmCnl )
         rmCbkl = self._getConfigletKeys( rmCbnl )
         return self.cvpService.removeConfigletFromContainer( container.name,
                                                              containerKey,
                                                       cnl, ckl, cbnl, cbkl,
                                                       rmCnl, rmCkl, rmCbnl, rmCbkl )

   def removeConfigletAppliedToDevice( self, device, configletList ):
      '''remove configlet mapped to device
      Arguments:
         device -- type : Container device
         configletList -- List of configlet objects to be removed
            ( type : List of Configlet Class )
      Raises:
         CvpError -- If the configlet names or container name are invalid
      Returns:
         taskIdList -- List of task ids
      '''
      assert isinstance( device, Device )
      assert all ( isinstance( configlet, Configlet ) for configlet in
                                                                      configletList )
      configletNameList = []
      for configlet in configletList:
         configletNameList.append( configlet.name )
      if not configletNameList:
         return 'No configlets to remove'
      configletsInfo = self.cvpService.getDeviceConfiglets( device.macAddress )
      actionReqd, cnl, cbnl, rmCnl, rmCbnl = self._checkRemoveConfigMapping(
                                          configletsInfo, configletList )
      if actionReqd:
         ckl = self._getConfigletKeys( cnl )
         cbkl = self._getConfigletKeys( cbnl )
         rmCkl = self._getConfigletKeys( rmCnl )
         rmCbkl = self._getConfigletKeys( rmCbnl )
         return self.cvpService.removeConfigletFromDevice( device.fqdn,
                                                           device.ipAddress,
                                                    device.macAddress, cnl, ckl,
                                                    cbnl, cbkl, rmCnl, rmCkl, rmCbnl,
                                                    rmCbkl )

   def addContainer( self, container ):
      '''Add container to the inventory
      Arguments:
         container -- container to be added ( type : Container( class ) )
      Raises:
         CvpError -- If container parent name ( parentName ) is invalid
         CvpError -- If container name ( name ) is invalid
         CvpError -- If container already exists.
      Returns:
         taskIdList -- List of task Ids
      '''
      assert isinstance( container, Container )
      parentContainerName = container.parentName
      parentContainerInfo = self._getContainerInfo( parentContainerName )
      parentContainerId = parentContainerInfo[ 'key' ]
      return self.cvpService.addContainer( container.name,
                                    container.parentName, parentContainerId )

   def isDevicePresent( self, device ):
      '''Check if device is present in inventory or not.
      This calls getNetElementById() for checking the device info. getNetElmentById() returns
      the persistent info of the devices. If a given device has been marked for deletion, even
      then this will return the device info(rather than an empty list if the call is made to
      getInventory()). When the device has been removed from CVP, this API will return
      {
        "122801": "Entity does not exist"
      }
      Arguments:
         device -- device to be queried ( type : Device( class ) )
      '''
      try:
         self.cvpService.getNetElementById(device.macAddress)
      except cvpServices.CvpError as e:
         if e.errorCode == errorCodes.NETELEMENT_ENTITY_DOES_NOT_EXIST:
            return False
      return True

   def importDeviceByCsv( self, filename, strDirPath='' ):
      '''Add devices by giving the csv file containing proper infomation
      Arguments:
         filename -- the file name of the csv file
         strDirPath -- the directory path of the csv file
      Raises:
         CvpError -- If device status is unauthorized access
         CvpError -- If device is failed after connection attempt
      Returns:
         device -- list of successfully connected device
               ( Type: List of Device ( class ) )
      '''
      devicesInfo = self.cvpService.importDeviceByCsv( filename, strDirPath )
      deviceList = []
      for deviceInfo in devicesInfo:
         dev = Device( deviceInfo[ 'ipAddress' ],
                  deviceInfo[ 'fqdn' ],
                  deviceInfo[ 'systemMacAddress' ],
                  deviceInfo[ 'containerName' ] )
         deviceList.append( dev )
      connectedDeviceList = \
         self._checkTempDeviceStatus( deviceList )
      self.cvpService.saveInventory()
      for device in deviceList:
         self._checkDCAInstallStatus( device.macAddress )
      return connectedDeviceList

   def onboardDevice( self, ipAddressOrName ):
      '''Add the device by giving the ipAddress or host name of device without
      mapping to container
      '''
      return self.cvpService.onboardDevices( [ipAddressOrName] )

   def bulkImportDevice( self, ipAddressOrNameList, containerName,
           executeTask=False ):
      '''
      Add the devices with provided IP address or host name to the specified
      container. If 'executeTask' is set to 'True', the 'device add' tasks are
      also executed which may include config reconciliation, config push and
      image push to the device depending upon the config and image applied to
      the destination container.
      Arguments:
         ipAddressOrNameList -- list of ip addresses or names of hosts to be
                          imported ( type: List of strings )
         containerName -- Name of the container to which devices need to be mapped
         executeTask -- Execute the 'device add' tasks if set to 'True'
      Raises:
         HTTPError -- If the request to onboard the device or the request to
         map the device to the container returns an unsuccessful status code
         CvpError -- If task execution fails
         CvpError -- If invalid container name is provided
      Returns:
         ( connectedDevices, taskIdMap )
         connectedDevices -- map of successfully connected devices
               ( Type: Map with provided IP address or hostname as the key and
               Device ( class ) as the value )
         taskIdMap -- map of the created 'device add' tasks
                ( Type: Map with provided IP address or hostname as the key and
                the corressponding task ID ( string ) as the value )
      '''
      containers = self.cvpService.searchContainer( containerName )
      if len(containers) == 0:
         raise cvpServices.CvpError( errorCodes.INVALID_CONTAINER_NAME )
      containerId = containers[0][ 'Key' ]
      deviceIpToContainerKeyMap = {}
      for ipAddress in ipAddressOrNameList:
         deviceIpToContainerKeyMap[ ipAddress ] = containerId
      taskIdMap = self.cvpService.bulkAddToInventory( deviceIpToContainerKeyMap )
      connectedDevices = self._getDevicesFromInventory( ipAddressOrNameList )

      if ( not executeTask ) or ( not taskIdMap ):
         return connectedDevices, taskIdMap

      taskList = []
      for ipOrName, taskId in taskIdMap.iteritems():
         taskInfo = self.cvpService.getTaskById( int( taskId ) )
         task = Task( taskId, taskInfo[ 'workOrderUserDefinedStatus' ],
                     taskInfo[ 'description' ] )
         taskList.append( task )

         configletKeyList = []
         connectedDevice = connectedDevices[ ipOrName ]
         for configlet in self.cvpService.getDeviceConfiglets(
                 connectedDevice.macAddress ):
            configletKeyList.append( configlet[ 'key' ] )
         if len( configletKeyList ) > 0:
            # Reconciliation is necessary if there are some configlets to be pushed
            # to the device
            reconciledConfiglet = self._getReconciledConfiglet( connectedDevice,
                    configletKeyList )
            if reconciledConfiglet is not None:
               self.addConfiglet( reconciledConfiglet )

      self.executeTasks( taskList )
      self.monitorTaskStatus( taskList )
      return connectedDevices, taskIdMap

   def _getDevicesFromInventory(self, ipAddressOrNameList):
      ipAddressOrNameSet = set( ipAddressOrNameList )
      devices, _ = self.cvpService.getInventory(populateParentContainerKeyMap=False)
      connectedDevices = {}
      for deviceInfo in devices:
         deviceName = ""
         if deviceInfo[ 'ipAddress' ] in ipAddressOrNameSet:
            deviceName = deviceInfo[ 'ipAddress' ]
         if deviceInfo[ 'hostname' ] in ipAddressOrNameSet:
            deviceName = deviceInfo[ 'hostname' ]
         if deviceInfo[ 'fqdn' ] in ipAddressOrNameSet:
            deviceName = deviceInfo[ 'fqdn' ]
         if deviceName == "":
            continue
         containerKey = deviceInfo["parentContainerKey"]
         if containerKey == "":
            containerName = ""
         else:
            containerName = self.cvpService.getContainerInfoByKey(
               containerKey )['name']
         connectedDevices[ deviceName ] = Device(
                           ipAddress=deviceInfo[ 'ipAddress' ],
                           fqdn=deviceInfo[ 'fqdn' ],
                           macAddress=deviceInfo['systemMacAddress'],
                           containerName=containerName,
                           status=deviceInfo[ 'status' ],
                           model=deviceInfo[ 'modelName' ],
                           sn=deviceInfo[ 'serialNumber' ],
                           complianceCode=0 )
      return connectedDevices

   def importDevice( self, ipAddressOrName, containerName, executeTask=False ):
      '''Add the device by giving the ipAddress or host name of device
      in proper container. If 'executeTask' is set to 'True', the 'device add'
      task is also executed which may include config reconciliation, config
      push and image push to the device depending upon the config and image
      applied to the destination container.
      Arguments:
         ipAddressOrName -- either ipAddress or host name String
         containerName -- parent container of the device
         executeTask -- executes the 'device add' task if set to 'True'
      Raises:
         HTTPError -- If the request to onboard the device or the request to
         map the device to the container returns an unsuccessful status code
         CvpError -- If task execution fails
      Returns:
         ( device, taskId )
         device -- successfully connected device
               ( Type: Device ( class ) )
         taskId -- ID of the 'device add' task. 'None' if 'containerName' is
               'Undefined'.
      '''
      # Check whether ipAddress is ipv4
      ipv4Pattern = re.compile( "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" )
      useIpAddress = ipv4Pattern.match( ipAddressOrName )
      # Check whether ipAddress is ipv6
      if not useIpAddress and ':' in ipAddressOrName:
         useIpAddress = True
      if not useIpAddress:
         ipAddress = socket.gethostbyname( ipAddressOrName )
         fqdn = ipAddressOrName
         useIpAddress = False
      else:
         ipAddress = ipAddressOrName
         fqdn = socket.getfqdn( ipAddressOrName )
      macAddress = ''
      dev = Device( ipAddress, fqdn, macAddress, containerName )
      return self._addDevice( dev, useIpAddress, executeTask )

   def _addDevice( self, device, useIpAddress, executeTask=False ):
      '''Add device internal function. This method onboards the device, maps
      the device to the parent container and then executes the 'device add'
      task, if one such task exists and 'executeTask' is set to 'True'.
      Raises:
         HTTPError -- If the request to onboard the device or the request to
         map the device to the container returns an unsuccessful status code
         CvpError -- If task execution fails
      Returns:
         (device, taskId)
         device -- successfully connected device
               ( type: Device ( class ) )
         taskId -- ID of the 'device add' task
      '''
      parentContainerName = device.containerName
      parentContainerInfo = self._getContainerInfo( parentContainerName )
      parentContainerId = parentContainerInfo[ 'key' ]
      if useIpAddress:
         host = device.ipAddress
      else:
         host = device.fqdn
      taskId = self.cvpService.addToInventory( host, parentContainerId )
      connectedDeviceMap = self._getDevicesFromInventory( [ device.ipAddress ] )
      assert device.ipAddress in connectedDeviceMap
      connectedDevice = connectedDeviceMap[ device.ipAddress ]
      if ( not executeTask ) or ( taskId is None ):
         return connectedDevice, taskId
      configletKeyList = []
      for configlet in self.cvpService.getDeviceConfiglets(
              connectedDevice.macAddress ):
         configletKeyList.append( configlet[ 'key' ] )
      if len( configletKeyList ) > 0:
         # Reconciliation is necessary if there are some configlets to be pushed
         # to the device
         reconciledConfiglet = self._getReconciledConfiglet( connectedDevice,
                 configletKeyList )
         if reconciledConfiglet is not None:
            self.addConfiglet( reconciledConfiglet )
      taskInfo = self.cvpService.getTaskById( int( taskId ) )
      task = Task( taskId, taskInfo[ 'workOrderUserDefinedStatus' ],
                  taskInfo[ 'description' ] )
      self.executeTask( task )
      self.monitorTaskStatus( [ task ] )
      return connectedDevice, taskId

   def _checkDCAInstallStatus( self, macAddress, timeout=300 ):
      timeout *= 2
      status =  self.cvpService.getNetElementById( macAddress )[ 'status' ]
      while status == Device.DCA_INSTALLATION_IN_PROGRESS and timeout > 0:
         time.sleep( 0.5 )
         status =  self.cvpService.getNetElementById( macAddress )[ 'status' ]
         timeout -= 1
      if status == Device.DCA_INSTALLATION_FAILED:
         raise cvpServices.CvpError( errorCodes.DCA_INSTALLATION_FAILED )
      elif status == Device.DCA_INSTALLATION_IN_PROGRESS:
         raise cvpServices.CvpError( errorCodes.DCA_INSTALLATION_IN_PROGRESS )
      return status

   def _getTempDeviceStatus( self, device ):
      '''Retrieve the device status from the temp netElement table that \
         is used during device import
      Returns:
         deviceInfo -- Information about the device.( type : Dict )
      '''
      assert isinstance( device, Device )
      _, tempNetElementDevices = self.cvpService.retrieveInventory()
      for deviceInfo in tempNetElementDevices:
         if ( deviceInfo[ 'fqdn' ] == device.fqdn.split('.')[ 0 ] or
              deviceInfo[ 'fqdn' ] == device.fqdn or
              deviceInfo[ 'ipAddress' ] == device.ipAddress ):
            return deviceInfo

   def _checkTempDeviceStatus( self, deviceList, timeout=300 ):
      '''Check the status of devices in the deviceList, wait for the devices to
         reach a terminal state (non-"connecting") and save them to the inventory
      Argument:
         deviceList -- List of devices to be added to the inventory
         Type ( List of Device objects )
         timeout -- wait for a maximum of 'timeout' seconds for each device
      Raises:
         CvpError -- If device status is unauthorized access
         CvpError -- If device is failed after connection attempt
      Returns:
         connectedDeviceList -- List of devices that are successfully connected
         Type ( List of Device objects )
      '''
      assert all( isinstance( device, Device ) for device in deviceList )
      connectedDeviceList = []
      for device in deviceList:
         end = time.time() + timeout
         while time.time() < end:
            status = self._getTempDeviceStatus( device )
            s = Device.REG_IN_PROGRESS if status[ 'status' ] == 'Upgrade required' \
                  else Device.REGISTERED if status[ 'status' ] == 'Connected' \
                  else Device.UNKNOWN
            if status[ 'status' ] != 'Connecting':
               break
            time.sleep( 0.4 )
         if time.time() >= end:
            # raise timeout error
            raise cvpServices.CvpError( errorCodes.TIMEOUT )
         if status[ 'status' ] == 'Connected':
            device = Device( ipAddress=status[ 'ipAddress' ],
                             fqdn=status[ 'fqdn' ],
                             macAddress=status[ 'systemMacAddress' ],
                             containerName=status[ 'containerName' ],
                             imageBundle=None,
                             configlets=None,
                             status=s,
                             model=status[ 'modelName' ],
                             sn=status[ 'serialNumber' ],
                             complianceCode=DEVICE_IN_COMPLIANCE )
            connectedDeviceList.append( device )
         elif status[ 'status' ] == 'Upgrade required':
            device = Device( ipAddress=status[ 'ipAddress' ],
                             fqdn=status[ 'fqdn' ],
                             macAddress=status[ 'systemMacAddress' ],
                             containerName=status[ 'containerName' ],
                             imageBundle=None,
                             configlets=None,
                             status=s,
                             model=status[ 'modelName' ],
                             sn=status[ 'serialNumber' ],
                             complianceCode=DEVICE_IMG_UPGRADE_REQD )
            connectedDeviceList.append( device )
         elif status[ 'status' ] == 'Unauthorized access':
            raise cvpServices.CvpError( errorCodes.DEVICE_LOGIN_UNAUTHORISED )
         elif status[ 'status' ] == 'Duplicate':
            self.cvpService.deleteTempDevice( status[ 'systemMacAddress' ] )
            raise cvpServices.CvpError( errorCodes.DEVICE_ALREADY_EXISTS )
         else:
            raise cvpServices.CvpError(
                                    errorCodes.DEVICE_CONNECTION_ATTEMPT_FAILURE )
      return connectedDeviceList

   def generateConfigletForDevice( self, device, configletBuilder, inputs=None ):
      '''Generate configlet using the configlet builder for the device
      Argument:
      device -- device object ( Type: Device ( class ) )
      configletBuilder -- configletBuilder object
            ( Type: ConfigletBuilder ( class ) )
      inputs -- form inputs to generate the configlet
      Raises:
      CvpError -- If failure occurs while generating the configlet
      Return:
      configlet that is generated ( Type: GeneratedConfiglet ( class ) )
      '''
      assert isinstance( device, Device )
      assert isinstance( configletBuilder, ConfigletBuilder )
      configletBuilderKey = self._getConfigletKeys( [ configletBuilder.name ] )[ 0 ]
      pageType = 'netelement'

      if not configletBuilder.formList:
         resp = self.cvpService.generateAutoConfiglet( [ device.macAddress ],
                                                        configletBuilderKey,
                                                        configletBuilder.name,
                                                        "",
                                                        pageType )
      else:
         formValues = []
         if inputs:
            formValues = [ { 'fieldId' : k, 'value' : v } for k, v in
                        inputs.iteritems() ]
         resp = self.cvpService.generateFormConfiglet( [ device.macAddress ],
                                                        configletBuilderKey,
                                                        configletBuilder.name,
                                                        "",
                                                        formValues,
                                                        pageType )

      configletInfo = resp[ 0 ][ 'configlet' ]
      genConfigMapInfo = self.cvpService.getConfigletMapper()
      containerName = ""
      for genConfiglet in genConfigMapInfo[ 'generatedConfigletMappers' ]:
         if configletInfo[ 'key' ] == genConfiglet[ 'configletId' ]:
            containerInfo = self.cvpService.getContainerInfoByKey(
                                          genConfiglet[ 'containerId' ])
            containerName = containerInfo[ 'name' ]
      return GeneratedConfiglet( configletInfo[ 'name' ],
                                 configletInfo[ 'config' ],
                                 configletBuilder.name,
                                 containerName,
                                 resp[ 0 ][ 'netElementId' ],
                                 user=configletInfo[ 'user' ] )

   def generateConfigletForContainer( self, container, configletBuilder,
                                      devicesList=None, inputs=None ):
      '''Generate configlet using the configlet builder for the container
      Argument:
      container -- container object ( Type: Container ( class ) )
      configletBuilder -- configletBuilder object
            ( Type: ConfigletBuilder ( class ) )
      devicesList -- list of devices that will get the configlets
         under the container; Type ( List of Device ( class ) )
         Default value is None : all devices under the container will
         get the configlet
         Users can specify which devices will get the configlets in the list
      inputs -- dictionary of inputs for form builder for each device
         Format of the inputs:
         { "<device1.macAddress>" : { field1:value, field2:value, .. },
           "<device2.macAddress>" : { field1:value, field2:value, .. },
           ...
         }
         If the devicesList is None, which indicates all devices, and if one of the
         device's input is not specified, inputs will be passed as [] for that
         device. If an additional device input is passed, which is not part of the
         container, the input for that device will be ignored.
      Raises:
      CvpError -- If failure occurs while generating the configlet
      Return:
      List of configlets that are generated
      ( Type: GeneratedConfiglet ( class ) )
      '''
      assert isinstance( container, Container )
      assert isinstance( configletBuilder, ConfigletBuilder )
      if devicesList is None:
         devicesList = []
      containerKey = self._getContainerInfo( container.name )[ 'key' ]
      configletBuilderKey = self._getConfigletKeys( [ configletBuilder.name ] )[ 0 ]
      pageType = 'container'
      devicesMacList = []
      devicesMacList = [ dev.macAddress for dev in devicesList ]

      if not configletBuilder.formList:
         resp = self.cvpService.generateAutoConfiglet( devicesMacList,
                                                        configletBuilderKey,
                                                        configletBuilder.name,
                                                        containerKey,
                                                        pageType )
      else:
         if not devicesMacList:
            devicesMacList = [ d[ 'netElementKey' ] for d in
               self.cvpService.getDevicesInContainer( containerKey,
                  container.name ) ]

         resp = []
         for devMacAddr in devicesMacList:
            formValues = []
            if inputs:
               values = inputs.get( devMacAddr )
               if values is not None:
                  formValues = [ { 'fieldId' : k, 'value' : v } for k, v in
                               values.iteritems() ]
            respPerDev = self.cvpService.generateFormConfiglet( [ devMacAddr ],
                                                            configletBuilderKey,
                                                            configletBuilder.name,
                                                            containerKey,
                                                            formValues,
                                                            pageType )
            resp.append( respPerDev[ 0 ] )

      configletList = []
      for configletInfo in resp:
         configletList.append(
                               GeneratedConfiglet(
                                    configletInfo[ 'configlet' ][ 'name' ],
                                    configletInfo[ 'configlet' ][ 'config' ],
                                    configletBuilder.name,
                                    container.name,
                                    configletInfo[ 'netElementId' ],
                                    user=configletInfo[ 'configlet' ][ 'user' ] )
                              )
      return configletList

   def mapConfigletToDevice( self, device , configletList ):
      '''applying configs mentioned in configletNameList to the device.
      Arguments:
         device -- device information object ( type : Device( class ) )
         configletList -- List of configlets objects to be applied
         ( type : List of Configlet Objects )
      Raises:
         CvpError -- If device information is incorrect
         CvpError -- If configletNameList contains invalid configlet name
      Returns:
         taskIdList -- List of task Ids
      '''
      assert isinstance( device, Device )
      assert all ( isinstance( configlet, Configlet ) for configlet in
                                                                      configletList )
      self.cvpService.saveInventory()
      configletsInfo = self.cvpService.getDeviceConfiglets( device.macAddress )
      actionReqd, cnl, ckl, cbnl, cbkl = self._checkNewConfigMapping( configletsInfo,
                                                   configletList, device )
      if actionReqd :
         return self.cvpService.applyConfigletToDevice( device.ipAddress,
                                                 device.fqdn, device.macAddress, cnl,
                                                 ckl, cbnl, cbkl )

   def executeAllPendingTask( self ):
      '''Executes all the pending tasks.
      '''
      tasksInfo = self.getPendingTasksList()
      for taskInfo in tasksInfo:
         self.executeTask( taskInfo )

   def executeTasks( self, taskList ):
      '''Executes a list of task object.
      Arguments:
         taskList - a list of task object
      Raises:
         CvpError -- if tasks are invalid
      '''
      assert all ( isinstance( task, Task ) for task in taskList )
      taskIds = [ int( task.taskId ) for task in taskList ]
      self.cvpService.executeTasks( taskIds )

   def executeTask( self, task ):
      '''Executes a task object.
      Arguments:
         task - a task object
      Raises:
         CvpError -- if task is invalid
      '''
      self.executeTasks( [ task ] )

   def getTaskLogs( self, task ):
      '''Returns task logs for a specific task'''
      assert isinstance( task, Task )
      return self.cvpService.getLogsById( task.taskId )

   def getPendingTasksList( self ):
      '''Finds all the pending tasks from the Cvp instance '''
      return self.getTasks( Task.PENDING )

   def monitorTaskStatus( self, taskList, status=Task.COMPLETED, timeout=600 ):
      '''Poll for tasks to be in the state described by status
      Returns:
         nothing on success
      Raises:
         CvpError -- on timeout
      '''
      assert all ( isinstance( task, Task ) for task in taskList )
      end = time.time() + timeout
      while time.time() < end and taskList:
         task = self.cvpService.getTaskById( taskList[ -1 ].taskId )
         taskStatus = task[ 'workOrderUserDefinedStatus' ]
         if taskStatus == status:
            taskList = taskList[ :-1 ]
         elif taskStatus in [ Task.FAILED, Task.CANCELED ]:
            raise cvpServices.CvpError( errorCodes.TASK_EXECUTION_ERROR,
                                        'Task %d %s' %
                                        ( taskList[ -1 ].taskId, taskStatus ) )
         else:
            time.sleep( 1 )
      if time.time() >= end:
         # raise timeout error
         raise cvpServices.CvpError( errorCodes.TIMEOUT )

   def monitorEventStatus( self, eventList, status=Event.COMPLETED, timeout=600 ):
      '''Poll for events to be in the state described by status
      Returns:
         nothing on success
      Raises:
         CvpError on timeout or when event status is cancelled
      '''
      assert all( isinstance( event, Event ) for event in eventList )

      for event in eventList:
         end = time.time() + timeout
         while time.time() < end:
            eventStatus = self.getEvent( event.eventId ).status
            # eventStatus can be 'COMPLETED' or 'Completed' for completed events
            if eventStatus.lower() == status.lower():
               break
            elif eventStatus == Event.CANCELED:
               raise cvpServices.CvpError( errorCodes.EVENT_COMPLETION_ERROR,
                                            'Event %s %s' %
                                           ( event.eventId, eventStatus ) )
            # Try again
            time.sleep( 1 )
         if time.time() >= end:
            # Raise timeout error
            raise cvpServices.CvpError( errorCodes.TIMEOUT )

   def _getImageNameList( self, imageBundleInfo ):
      '''Return list of images present in image bundle'''
      imagesInfo = imageBundleInfo[ 'images' ]
      imageNameList = []
      for imageInfo in imagesInfo:
         imageNameList.append( imageInfo[ 'name' ] )
      return imageNameList

   def getImageBundles( self ):
      '''Retrieves information on all the image bundles.Image bundle information
      consist of images information, image bundle name, devices and
      containers to which the image bunudle is mapped to.
      Returns:
         imageBundleList -- List of ImageBundle object, each object providing
         information about an image bundle ( type: List of ImageBundle objects )
      '''
      imageBundlesInfo = self.cvpService.getImageBundles()
      imageBundleList = []
      for bundleInfo in imageBundlesInfo:
         imageBundleInfo = self.cvpService.getImageBundleByName(
                                                               bundleInfo[ 'name' ] )
         imageNameList = self._getImageNameList( imageBundleInfo )
         certified = ( imageBundleInfo[ 'isCertifiedImageBundle' ] == 'true' )
         user = imageBundleInfo[ 'uploadedBy' ]
         imageBundleList.append( ImageBundle( bundleInfo[ 'name' ],
                                 imageNameList, certified,
                                 user=user ) )
      return imageBundleList

   def getImageBundle( self, imageBundleName ):
      '''Retrieves image bundle from Cvp instance. Image bundle information
      consist of images information, image bundle name, devices and
      containers to which the image bunudle is mapped to.
      Arguments:
         imageBundleName -- name of image bundle ( type : String )
      Raises:
         CvpError -- If imageBundleName is invalid
      Returns:
         ImageBundle -- ImageBundle object contains all required image bundle
         information ( type : ImageBundle( class ) )
      '''
      imageBundleInfo = self.cvpService.getImageBundleByName( imageBundleName )
      imageNameList = self._getImageNameList( imageBundleInfo )
      certified = ( imageBundleInfo[ 'isCertifiedImageBundle' ] == 'true' )
      # Here, this field is named 'uploadedBy'
      user = imageBundleInfo[ 'uploadedBy' ]
      return ImageBundle( imageBundleName, imageNameList, certified,
                          user=user )

   def deleteImageBundle( self, imageBundle ):
      '''Deletes image bundle from cvp instance
      Arguments:
         imageBundle -- image bundle to be deleted ( type : ImageBundle( class ) )
      Raises:
         CvpError -- If image bundle key is invalid
         CvpError -- If image bundle is applied to any entity
      '''
      assert isinstance( imageBundle, ImageBundle )
      imageBundleInfo = self.cvpService.getImageBundleByName( imageBundle.name )
      imageBundleKey = imageBundleInfo[ 'key' ]
      self.cvpService.deleteImageBundle( imageBundleKey, imageBundle.name )

   def deviceComplianceCheck( self, device ):
      '''Run compliance check on the device
      Returns:
         deviceComplianceCode -- Code indicating device compliance check result
      Raises:
         CvpError -- If device mac address ( deviceMacAddress ) is invalid
      '''
      assert isinstance( device, Device )
      deviceMacAddress = device.macAddress
      complianceReport = self.cvpService.deviceComplianceCheck( deviceMacAddress )
      if complianceReport[ 'unAuthorized' ]:
         # if 'unAuthorized' is set, don't look at the code
         complianceCode = DEVICE_UNAUTHORIZED_USER
      else:
         complianceCode = complianceReport[ 'complianceCode' ]
      return int( complianceCode )

   def containerComplianceCheck( self, container, wait=True, timeout=0 ):
      '''Initiate a compliance check on 'container'.
      If wait == True, wait for the event to finish, and return the consolidated
      report for all devices under the container. timeout is the number of seconds
      to wait for, or indefinitely if 0.
      If wait == False, Otherwise, just return an event
      ID. The caller can call getEvent*() later to query its status.
      Returns: compliance report or event ID.
      Raises: CvpError in case of any error.
      '''
      assert isinstance( container, Container )
      containerInfo = self._getContainerInfo( container.name )
      if not containerInfo:
         raise cvpServices.CvpError( errorCodes.INVALID_CONTAINER_NAME  )
      containerId = containerInfo.get( 'key' )

      eventId = self.cvpService.complianceCheck( 'container', containerId )[ 'data' ]
      if wait:
         # wait for the event to complete
         end = time.time() + timeout
         while True:
            if timeout != 0 and time.time() >= end:
               break
            parentEventData = self.cvpService.getEvent( eventId )[ 'data' ]
            if parentEventData[ 'status' ] == 'COMPLETED':
               childEventData = self.cvpService.getChildEventData( eventId )
               assert parentEventData[ 'total' ] == childEventData[ 'total' ]
               events = []
               for subEvent in childEventData[ 'data' ]:
                  assert eventId == subEvent[ 'parentKey' ]
                  assert subEvent[ 'status' ] == 'COMPLETED'
                  events.append( Event( subEvent[ 'key' ],
                                        subEvent[ 'parentKey' ],
                                        subEvent[ 'objectId' ],
                                        subEvent[ 'eventType' ],
                                        subEvent[ 'status' ],
                                        int( subEvent[ 'data' ][ 'complianceCode' ] ),
                                        subEvent[ 'message' ],
                                        subEvent[ 'errors' ],
                                        subEvent[ 'warning' ],
                                        subEvent[ 'data' ] ) )
               return events
            else:
               time.sleep( 1 )

         if timeout != 0 and time.time() >= end:
            # raise timeout error
            raise cvpServices.CvpError( errorCodes.TIMEOUT )
      else:
         return eventId

   def renameContainer( self, container, newContainerName ):
      ''' Renames the container to desired new name
      Arguments:
         container -- current information of the container
         newContainerName -- New desired name of the container
      Returns: List of task ids
      Raises:
         CvpError -- If the oldContainerName is invalid
      '''
      assert isinstance( container, Container )
      containerInfo = self._getContainerInfo( container.name )
      containerKey = containerInfo[ 'key' ]
      return self.cvpService.changeContainerName( container.name,
                                                newContainerName, containerKey )

   def getRootContainerInfo( self ):
      ''' Returns information about the root container
      Returns:
         container -- Container object containing information about root container
      '''
      containerKey = cvpServices.ROOT_CONTAINER_KEY
      containerInfo = self.cvpService.getContainerInfoByKey(containerKey)
      imageBundleNameList = self._getImageBundleNameList()
      imageBundleMap = self._getContainerImageBundleMap( imageBundleNameList )
      parentName = ''
      containerName = containerInfo[ 'name' ]
      configletsInfo = self.cvpService.getContainerConfiglets( containerKey )
      configletNames = [ configlet[ 'name' ] for configlet in configletsInfo ]
      appliedImageBundle = None
      if containerName in imageBundleMap:
         appliedImageBundle = imageBundleMap[ containerName ]
      return Container( containerName, parentName, configletNames,
                        appliedImageBundle )

   def deleteContainer( self, container ):
      '''delete the container from the Cvp inventory
      Argument:
         container -- container to be deleted. ( type : Container(class) )
      Raises:
         CvpError -- If parent container name ( parentName )is invalid
         CvpError -- If container name ( name ) is invalid
      Returns: List of task ids
      '''
      assert isinstance( container, Container )
      containerInfo = self._getContainerInfo( container.name )

      # Can't delete the Tenant and undefined containers
      if containerInfo[ 'key' ] in [ cvpServices.UNDEF_CONTAINER_KEY,
                                     cvpServices.ROOT_CONTAINER_KEY ]:
         raise cvpServices.CvpError( errorCodes.INVALID_CONTAINER_NAME )

      containerKey = ''
      parentKey = ''
      containerKey = containerInfo[ 'key' ]
      parentInfo = self._getContainerInfo( container.parentName )
      parentKey = parentInfo[ 'key' ]
      return self.cvpService.deleteContainer( container.name, containerKey,
                                       container.parentName, parentKey )

   def deleteDevice( self, device, wait=True, timeout=90 ):
      '''Delete a single device from cvp inventory. Deletion of device
      will delete all the pending tasks for that device as well. If
      wait is True, wait for the device to be removed from the inventory.
      Arguments:
         device -- Device to be deleted.( type : Device(class) )
         wait -- Flag to wait for device deletion
         timeout -- Time duration to wait for device deletion
      Raises:
         CvpError -- If device isnt present in CVP
      '''
      return self.deleteDevices( [ device ], wait=wait, timeout=timeout )

   def deleteDevices( self, devices, wait=True, timeout=600 ):
      '''Delete multiple devices from cvp inventory. Deletion of a device
      will delete all the pending tasks for that device as well. If wait is
      True, wait for all the devices to be removed from the inventory.
      Arguments:
         devices -- Devices to be deleted( type : Device(class) )
         wait -- Flag to wait for devices deletion
         timeout -- Time duration to wait for devices deletion
      Raises:
         CvpError -- If there was error while trying to delete device(s)
      '''
      assert all( isinstance( device, Device ) for device in devices )
      resp = self.cvpService.deleteDevices( [ dev.macAddress for dev in devices ] )
      if wait:
         end = time.time() + timeout
         pendingDevices = devices[ : ]
         while pendingDevices and time.time() < end:
            pendingDevices[ : ] = [ dev for dev in pendingDevices if self.isDevicePresent( dev ) ]
            if pendingDevices:
               time.sleep( 1 )
         if time.time() >= end:
            raise cvpServices.CvpError( errorCodes.TIMEOUT )
      return resp

   def deployDevice( self, device, deviceTargetIp, container,
                     configletList=None, configletBuilderList=None,
                     imageBundle=None ):
      ''' Move a device from the undefined container to a target container.
      Optionally, apply any device-specific configlets and an image to the device.
      Return a Task that can be executed to complete the action
      Arguments:
         device -- The device to be moved from the undefined container to the
                   targetConatiner
         deviceTargetIp -- The IP address of the device after all the configlets
                           have been applied
         container -- The container to move the device to
         configletList -- Optional, a list of configlets to apply to the device
         configletBuilderList -- Optional, a list of configlet builders to be used to
                                 generate device specific configlets
         image -- Optional, an image to apply to the device
      Returns: A list of Tasks that can be executed to complete the action
      '''
      assert isinstance( device, Device )
      assert isinstance( container, Container )
      assert imageBundle is None or isinstance( imageBundle, ImageBundle )
      ckl = []
      cnl = []
      cbnl = []
      cbkl = []
      if configletList:
         assert all( isinstance( configlet, Configlet ) for configlet in
                     configletList )
         # add in any device specific configlets
         cnl = [ configlet.name for configlet in configletList ]
         if cnl:
            ckl = self._getConfigletKeys( cnl )

      if configletBuilderList:
         assert all( isinstance( builder, ConfigletBuilder ) for builder in
                     configletBuilderList )
         # add in any device specific configlets generated using builders
         cbnl = [ builder.name for builder in configletBuilderList ]
         if cbnl:
            cbkl = self._getConfigletKeys( cbnl )

      containerInfo = self._getContainerInfo( container.name )
      containerKey = containerInfo[ 'key' ]
      imageBundleKey = None
      imageBundleName = None
      if imageBundle:
         imageBundleInfo = self.cvpService.getImageBundleByName( imageBundle.name )
         imageBundleKey = imageBundleInfo[ 'key' ]
         imageBundleName = imageBundle.name

      response = self.cvpService.deployDevice( device.macAddress,
                                       device.fqdn, device.ipAddress, deviceTargetIp,
                                       containerKey, container.name, ckl, cnl, cbkl,
                                       cbnl, imageBundleKey, imageBundleName )

      tids = [ int(t) for t in response[ 'taskIds' ] ]
      assert len( tids ) == 1, "Only one task expected"
      tid = tids[ 0 ]
      info = self.cvpService.getTaskById( tid )
      task = Task( tid, info[ 'workOrderUserDefinedStatus' ], info[ 'description' ] )
      return task

   def getAllEvents( self, isCompleted=True ):
      '''Get all the events from CVP
      Arguments:
         isCompleted -- Flag representing complete/pending events
      Returns:
         events -- A list of events
      '''
      events = self.cvpService.getAllEvents( isCompleted )
      return [ Event( event[ 'key' ], event[ 'parentKey' ], event[ 'objectId' ],
                    event[ 'eventType' ], event[ 'status' ], 0,
                    event[ 'message' ], event[ 'errors' ], event[ 'warning' ],
                    event[ 'data' ] ) for event in events ]

   def getEvent( self, eventId ):
      '''Return the event associated with the event id
      Arguments:
         eventId -- Id of the event
      Returns:
         eventDetails
      '''
      event = self.cvpService.getEvent( eventId )[ 'data' ]
      return Event( event[ 'key' ], event[ 'parentKey' ], event[ 'objectId' ],
                    event[ 'eventType' ], event[ 'status' ], 0,
                    event[ 'message' ], event[ 'errors' ], event[ 'warning' ],
                    event[ 'data' ] )

   def cancelEvent( self, event, timeout=60 ):
      '''Cancel the given event
      Arguments:
         Event object
      Returns:
         'CANCELLED' -- Status of the event
         Raise error -- Cancel fails
      '''
      assert isinstance( event, Event )
      self.cvpService.cancelEvent( event.eventId )
      self.monitorEventStatus( [ event ], status=Event.CANCELED, timeout=timeout )

   def getTasks( self, status=None ):
      ''' Retrieve all tasks filtered by status.
      Arguments:
         status --  None, Task.COMPLETED, Task.PENDING, Task.CANCELED,
                    Task.FAILED, Task.CONFIG_PUSH_IN_PROGRESS,
                    Task.IMAGE_PUSH_IN_PROGRESS,
                    Task.DEVICE_REBOOT_IN_PROGRESS
      Returns: A list of tasks
      '''
      assert status in ( None, Task.COMPLETED, Task.PENDING, Task.CANCELED,
                         Task.FAILED, Task.CONFIG_PUSH_IN_PROGRESS,
                         Task.IMAGE_PUSH_IN_PROGRESS,
                         Task.DEVICE_REBOOT_IN_PROGRESS )
      tasks = self.cvpService.getTasks( status )
      return [ Task( t[ 'workOrderId'], t[ 'workOrderUserDefinedStatus' ],
                     t[ 'description' ] ) for t in  tasks ]

   def cancelTask( self, task ):
      ''' Cancel a pending task
      Raises:
         CvpError -- if the task is invalid
      '''
      self.cancelTasks( [ task ] )

   def cancelTasks( self, taskList ):
      '''Cancels a list of pending tasks
      Raises:
         CvpError -- if the task is invalid
      '''
      assert all( [ isinstance( task, Task ) for task in taskList ] )
      self.cvpService.cancelTasks( [ task.taskId for task in taskList ] )

   def addTaskLog( self, task, log, src ):
      '''Add a log to a Task from an external source
      Arguments:
         task - instance of task to which log is added
         log - log message
         src - external source of log
      '''
      assert isinstance( task, Task)
      self.cvpService.addTaskLog( task.taskId, log, src)

   def addNoteToTask( self, task, note ):
      ''' Add a note to a task
      Raises:
         CvpError -- If task is invalid
      '''
      assert isinstance( task, Task )
      self.cvpService.addNoteToTask( task.taskId, note )

   def getTasksForChangeControl( self ):
      ''' Gets tasks that could be added into a change control. This includes
      pending and failed tasks.
      Returns:
         List of CCTask objects
      '''
      tasks = self.cvpService.getTasksForChangeControl()
      return [ CCTask( t[ 'workOrderId' ], t[ 'workOrderUserDefinedStatus' ],
               t[ 'description' ] ) for t in tasks ]

   def createChangeControl( self, ccName, ccTaskList, snapshotTemplateKey,
                            schedule=None ):
      ''' Creates a ChangeControl instance. It does not add the instance to
      the Cvp. Use addChangeControl to add the change control to the Cvp
      Arguments:
         ccName -- Name of the change control management
         snapshotTemplateKey -- snapshot template key for the change control
         ccTaskList -- List of CCTask objects.
         schedule -- ( optional ) dateTime and timeZone as dict in 3 letter
                     notation when the CC needs to be scheduled.
      Returns:
         cc -- A ChangeControl Object
      '''
      assert all( isinstance( t, CCTask ) for t in ccTaskList )
      cc = ChangeControl( ccName, ccTaskList, schedule, snapshotTemplateKey )
      return cc

   def addChangeControl( self, cc ):
      ''' Addes a change control to the Cvp instance
      Arguments:
         cc -- a ChangeControl object
      '''
      assert isinstance( cc, ChangeControl )

      # Expanding the CCTask object into a list of dicts to be passed into the
      # add Change Control API body
      taskInfo = [ { 'taskId': str( t.taskId ), 'taskOrder': t.taskOrder,
                  'snapshotTemplateKey': cc.snapshotTemplateKey,
                  'clonedCcId': '' if not t.parentCCId else t.parentCCId }
                   for t in cc.taskList ]

      cc.Id = int( self.cvpService.addOrUpdateChangeControl( cc.Id,
                   cc.Name, cc.snapshotTemplateKey,
                   taskInfo, cc.schedule ) )

   def deleteChangeControls( self, cc ):
      ''' Deletes change controls from Cvp instance.Does not raise exception when
      delete is performed on a completed change control
      Arguments:
      cc -- A single or list of ChangeControl objects to be deleted
      '''
      if not isinstance( cc, list ):
         cc = [ cc ]
      assert all( isinstance( ccm, ChangeControl ) for ccm in cc )
      ccList = [ ccm.Id for ccm in cc ]
      for ccmId in ccList:
         try:
            self.cvpService.deleteChangeControls( [ ccmId ] )
         except cvpServices.CvpError as err:
            if err.errorCode == errorCodes.CCM_INVALID_DELETE:
               print err.errorMessage
            else:
               raise

   def executeCC( self, cc ):
      ''' Executes Change Control
      Arguments:
         cc -- A single or list of ChangeControl objects to be executed
      '''
      if not isinstance( cc, list ):
         cc = [ cc ]
      assert all( isinstance( ccm, ChangeControl ) for ccm in cc )
      ccList = [ ccm.Id for ccm in cc ]
      self.cvpService.executeChangeControl( ccList )

   def cancelCC( self, cc ):
      ''' Cancels Change Control
      Arguments:
         cc -- A single or list of ChangeControl objects to be cancelled.
      '''
      if not isinstance( cc, list ):
         cc = [ cc ]
      assert all( isinstance( ccm, ChangeControl ) for ccm in cc )
      ccList = [ ccm.Id for ccm in cc ]
      self.cvpService.cancelChangeControl( ccList )

   def getCCStatus( self, cc ):
      ''' Gets/updates the status of the ChangeControl in the CC state variable
      Arguments:
         cc -- A ChangeControl object
      '''
      assert isinstance( cc, ChangeControl )
      assert ( cc.Id != None ), """Change Control Id not set. Cannot retrieve
         status for non-existing change control. Check if addChangeControl was
         used"""
      ccStatus = self.cvpService.getChangeControlStatus( cc.Id, cc.taskList )
      cc.status = ccStatus
      return cc.status

   def monitorCCStatus( self, cc, status=ChangeControl.COMPLETED, timeout=600 ):
      '''Poll for ChangeControl to be in the state described by status
      Returns:
         nothing on success
      Raises:
         CvpError -- on timeout
      '''
      assert isinstance( cc, ChangeControl )

      end = time.time() + timeout
      while time.time() < end:
         ccStatus = self.getCCStatus( cc )
         if ccStatus == status:
            break
         elif ccStatus in [ ChangeControl.FAILED, ChangeControl.CANCELLED,
                              ChangeControl.ABORTED ]:
            raise cvpServices.CvpError( errorCodes.CCM_EXECUTION_ERROR,
                                           'Change Control  %d %s' %
                                           ( cc.Id, ccStatus ) )
         # back off and try again
         time.sleep( 1 )

         if time.time() >= end:
            # raise timeout error
            raise cvpServices.CvpError( errorCodes.TIMEOUT )


   def cloneCC( self, cc ):
      ''' Clones a Change Control with only failed and pending tasks which have
      not yet been cloned.
      Arguments:
         cc -- parent ChangeControl object.
      Returns:
         clonecc -- Child ChangeControl object as a result of cloning
                    Cloned CC object must be added to the Cvp instance using
                    addChangeControl
      '''
      assert isinstance( cc, ChangeControl )
      clone = self.cvpService.cloneChangeControl( cc.Id )

      # Adding -clone to the name of CC, as the name defaults the name of the
      # parent Change control.
      name = clone[ 'ccName' ] + '-clone'

      tasks = clone[ 'changeControlTasks' ][ 'data' ]
      ccTaskList = [ CCTask( t[ 'workOrderId' ],
         t[ 'workOrderUserDefinedStatus' ], t[ 'description' ],
         cloneId=t[ 'ccId' ] ) for t in tasks ]
      snapshotTemplates = self.getSnapshotTemplates()
      for snap in snapshotTemplates[ 'templateKeys' ] :
         if snap[ 'key' ] == clone[ 'snapshotTemplateKey' ]:
            snapshotTemplateKey = snap[ 'key' ]
            break
      return ChangeControl( name, ccTaskList, scheduleTime=None,
                            snapshotTemplateKey=snapshotTemplateKey )

   def getChangeControl( self, ccId ):
      ''' Creates a ChangeControl object for the ccId provided and populates
      the variables of the ChangeControl instance
      Arguments:
         ccId -- Id of the Change Control
      Returns:
         cc -- Instance of class ChangeControl
      '''
      ccInfo = self.cvpService.getChangeControl( ccId )
      cctasks = ccInfo[ 'changeControlTasks' ][ 'data' ]
      ccTaskList = [ CCTask( t[ 'workOrderId' ],
                  t[ 'workOrderUserDefinedStatus'], t[ 'description' ],
                  t[ 'taskOrder' ] ) for t in cctasks ]
      cc = ChangeControl( ccInfo[ 'ccName' ], ccTaskList )
      cc.Id = ccId

      # Populates the status of the cc
      self.getCCStatus( cc )
      return cc

   def getChangeControls( self ):
      ''' Retrieves all the ChangeControl in Cvp
      Returns:
         changeControlList: List of ChangeControl
      '''
      changeControlInfo = self.cvpService.getChangeControls()
      changeControlList = []
      for changeControl in changeControlInfo[ 'data' ]:
         changeControlList.append( ChangeControl( ccName=changeControl[ 'ccName' ],
                                                  ccTaskList=None,
                                                  scheduleTime=
                                                  changeControl[ 'scheduledTimestamp' ],
                                                  ccId=int( changeControl[ 'ccId' ] ),
                                                  status=changeControl[ 'status' ] ) )
      return changeControlList

   def createRollback( self, rollbackType, rollbackTime, device ):
      ''' Creates an instance of rollback. This rollback object will be used to
      rollback devices to specific time.
      '''
      assert isinstance( device, Device )
      rb = Rollback( rollbackType, rollbackTime, device )
      return rb

   def addRollbackTasks( self, rb ):
      ''' Adds a temp action to rollback the device to a particular
      configuration and/or image.
      Arguments:
         rb -- An instance of Rollback class containing information about the
               rollback being processed
      '''
      assert isinstance( rb, Rollback )
      if not rb.configRollbackInfo:
         rb.configRollbackInfo =  { "timeStamp": str(rb.rollbackTime),
                                    "taskId": ""
                                  }
      if not rb.imageRollbackInfo:
         rb.imageRollbackInfo =  { "timeStamp": str(rb.rollbackTime),
                                   "taskId": ""
                                 }
      self.cvpService.addTempRollbackAction( rb.rollbackTime,
         rb.device.macAddress, rb.rollbackType, rb.device.ipAddress,
                     rb.configRollbackInfo, rb.imageRollbackInfo )

   def createNetworkRollback( self, container, rollbackTime, rollbackType ):
      ''' Creates a NetworkRollback instance
      Arguments:
         container -- An instance of the Container class
         rollbackTime -- The unix time to which the container/network is rolled
                         back to
         rollbackType -- The type of rollback being processed.
      Returns:
         nRb -- An instance of NetworkRollback class
       '''
      assert isinstance( container, Container )
      nRb = NetworkRollback( container, rollbackTime, rollbackType )
      return nRb

   def addNetworkRollbackCC( self, nRb ):
      ''' Creates a Change Control with Tasks to roll back the devices in the
      container specified in the object variables.
      Argument:
         nRb -- An instance of NetworkRollback class
      '''
      assert isinstance( nRb, NetworkRollback )
      containerId = self._getContainerInfo( nRb.container.name )[ 'key' ]
      self.cvpService.addNetworkRollbackTempActions( containerId,
                     nRb.rollbackTime, nRb.rollbackType, nRb.startIndex,
                     nRb.endIndex )
      ccId = self.cvpService.addNetworkRollbackChangeControl()
      cc = self.getChangeControl( ccId )
      nRb.cc = cc

   def getRollbackDeviceConfigs( self, deviceId, current="", timestamp="" ):
      ''' Get the image and running config for rollback
      Arguments:
         deviceId -- Id of the device for which the configs are to be
                     retrieved
         current -- true value of this variable indicates that current
                    running and image configs are to retrieved
         timestamp -- if current is not true, this indicates the time at
                      which the configs are to retrieved from the device
      Returns:
         Rollback image and running configs
      '''
      return self.cvpService.getRollbackDeviceConfigs( deviceId,  current,
                                                        timestamp )

   def captureDeviceSnapshot( self, templateId, deviceId,
                              generatedBy="ChangeControl" ):
      ''' Capture the snapshot on the given device and store the outputs
      under aeris paths
      Arguments:
         templateId -- Template key against which the snapshot will be
                       captured
         deviceId -- DeviceId of the device for which the snapshot is to
                     be captured
         generatedBy -- This field is used to identify the workflow in
                        which the snapshot was captured.
                        If generatedBy field is not passed
                        then the default value of "ChangeControl" will be
                        used. The accepted values of this filed are
                        "ChangeControl" and "User" suggesting that the
                        snapshot was captured either during the change control
                        workflow or explicitly captured by the user.
                        The API will throw an error if any other value is passed
      '''

      self.cvpService.captureDeviceSnapshot( templateId, deviceId, generatedBy )

   def scheduleSnapshotTemplate( self, name, commands, deviceList,
           frequency ):
      ''' Create and schedule the template with given
      configs
      Arguments:
         name -- Name that will be assigned to the template
         commands -- List of commands that will be run as part of
                     this template
         deviceList -- List of devices against which this template will
                       be scheduled
         frequency -- Frequency at which the commands will be executed on
                      the devices
      '''
      return self.cvpService.scheduleSnapshotTemplate( name, commands,
           deviceList, frequency )

   def getSnapshotTemplates( self, searchString='', startIndex=0, endIndex=0 ):
      ''' Get the snapshot templates available in the cvp
      Returns:
         snapshotTemplates -- A list of dicts with information about every
                              snapshot templates
      '''
      return self.cvpService.getSnapshotTemplates( searchString, startIndex,
                                                   endIndex )

   def getTemplateInfo(self, key):
      ''' Get template info for a particular template key.
      Arguments:
        Key --- Template key whose info user wants to retrieve.
      '''
      return self.cvpService.getTemplateInfo(key)

   def getTemplatesInfo(self, keys):
      ''' Get templates info for a list template keys.
      Arguments:
        Keys --- Template keys whose info user wants to retrieve.
      '''
      return self.cvpService.getTemplatesInfo(keys)

   def getCvpVersionInfo( self ):
      ''' Finds the current version of CVP'''
      return self.cvpService.cvpVersionInfo()

   def getRoles( self ):
      '''Downloads information about all the roles'''
      roleList = []
      rolesInfo = self.cvpService.getRoles()
      for roleInfo in rolesInfo:
         roleList.append( Role( roleInfo[ 'name' ], roleInfo[ 'description' ],
                                roleInfo[ 'moduleList' ], key=roleInfo[ 'key' ] ) )
      return roleList

   def getRole( self, roleName ):
      '''Download information about a specific role with name as roleName
      Raises:
         CvpError -- If the role name is invalid
      '''
      roles = self.getRoles()
      for role in roles:
         if role.name == roleName:
            return role

   def addRole( self, role ):
      ''' Add a Role to the Cvp instance
      Raises:
         CvpError -- If the role with same name already exists
      '''
      assert isinstance( role, Role )
      self.cvpService.addRole( role.name, role.moduleList )

   def updateRole( self, role ):
      ''' Update the information about the Role
      Raises:
         CvpError -- if role name is invalid
      '''
      assert isinstance( role, Role )
      rolesInfo = self.cvpService.getRoles()
      for roleInfo in rolesInfo:
         if roleInfo[ 'name' ] == role.name:
            roleKey = roleInfo[ 'key' ]
      self.cvpService.updateRole( role.name, role.description, role.moduleList,
                                  roleKey )

   def deleteRole( self, roleName ):
      '''deletes role from the cvp instance'''
      roleKey = ''
      rolesInfo = self.cvpService.getRoles()
      for roleInfo in rolesInfo:
         if roleInfo[ 'name' ] == roleName:
            roleKey = roleInfo[ 'key' ]
      if roleKey:
         self.cvpService.deleteRole( roleKey )
      else:
         raise cvpServices.CvpError( errorCodes.INVALID_ROLE_NAME )

   def getUsers( self ):
      ''' retrieves all the users from the cvp instance'''
      usersInfo = self.cvpService.getUsers()
      rolesMap = usersInfo[ 'roles' ]
      userList = []
      for uInfo in usersInfo[ 'users' ]:
         userList.append( User( uInfo[ 'userId' ], uInfo[ 'email' ],
                                rolesMap[ uInfo[ 'userId' ] ],
                                uInfo[ 'userStatus' ], uInfo[ 'firstName' ],
                                uInfo[ 'lastName' ], uInfo[ 'contactNumber' ],
                                uInfo[ 'userType' ] ) )
      return userList

   def getUser( self, userId ):
      ''' retrieves user with particular userid from the cvp instance'''
      userInfo = self.cvpService.getUser( userId )
      uInfo = userInfo[ 'user' ]
      userRoles = userInfo[ 'roles' ]
      return User( uInfo[ 'userId' ], uInfo[ 'email' ],
                   userRoles,  uInfo[ 'userStatus' ], uInfo[ 'firstName' ],
                   uInfo[ 'lastName' ], uInfo[ 'contactNumber' ] )

   def addUser( self, user, password ):
      '''Adds a user to a cvp instance.
      User object no longer stores the password for the user,
      the caller should provide the password separately.
      '''
      assert isinstance( user, User )
      self.cvpService.addUser( user.userId, user.email, password, user.roleList,
                               user.firstName, user.lastName, user.userStatus,
                               user.contactNumber, user.userType )

   def updatePassword(self, userId, password):
      '''Changes the password of a user.'''
      return self.cvpService.updatePassword(userId, password)

   def deleteUsers( self, users ):
      '''Deletes the specified users from cvp.'''
      assert all ( isinstance( user, User ) for user in users )
      self.cvpService.deleteUsers( [ user.userId for user in users ] )

   def addAaaServer( self, aaa, secret ):
      '''
      Add AAA Server to cvp
      '''
      assert isinstance( aaa, AaaServer )
      self.cvpService.addAaaServer( aaa.serverType, aaa.status,
            aaa.authMode, aaa.port, aaa.ipAddress,
            secret, aaa.createdDateInLongFormat, aaa.accountPort )

   def updateAaaServer( self, aaa, secret ):
      '''
      Update AAA server.
      '''
      assert isinstance( aaa, AaaServer )
      self.cvpService.updateAaaServer( aaa.serverType, aaa.status,
            aaa.authMode, aaa.port, aaa.ipAddress,
            secret, aaa.createdDateInLongFormat, aaa.key, aaa.accountPort )

   def deleteAaaServer( self, aaaServerId ):
      '''
      Delete AAA server.
      '''
      self.cvpService.deleteAaaServer( aaaServerId )

   def testAaaServerConnectivity( self, aaa, aaaUser, secret ):
      '''
      Test connectivity of AAA server for given
      user.
      '''
      assert isinstance( aaa, AaaServer )
      assert isinstance( aaaUser, AaaUser )
      return self.cvpService.testAaaServerConnectivity( aaa.serverType, aaa.port,
                                aaa.ipAddress, secret, aaa.authMode,
                                aaa.accountPort, aaa.key, aaaUser.userId,
                                aaaUser.password, aaa.status )[ 'data' ] == 'success'

   def getAaaServers( self, serverType, queryParam = '' ):
      '''
      Retrieve AAA servers.
      '''
      aaaServers = [ ]
      assert serverType in AAA_SETTINGS, 'Invalid AAA server type'
      for aaa in self.cvpService.getAaaServers( serverType, queryParam ):
         aaaServer = AaaServer( aaa[ 'serverType' ],
            None, aaa[ 'port' ], aaa[ 'ipAddress' ],
            aaa[ 'authMode' ], aaa[ 'accountPort' ], status=aaa[ 'status' ],
            key=aaa[ 'key' ] )
         aaaServers.append( aaaServer )
      return aaaServers

   def getAaaSettings( self ):
      '''
      Retrieves the information about the authentication and authorization server
      type.
      '''
      aaaInfo = self.cvpService.getAaaSettings()
      return AaaSettings( aaaInfo[ 'authenticationServerType' ],
                          aaaInfo[ 'authorizationServerType' ] )

   def saveAaaSettings( self, aaaSettings ):
      '''
      Save the authentication and authorization server type.
      '''
      assert isinstance( aaaSettings, AaaSettings )
      assert aaaSettings.authenticationServerType in AAA_SETTINGS, \
        'Invalid authentication server type'
      assert aaaSettings.authorizationServerType in AAA_SETTINGS, \
        'Invalid authorization server type'
      self.cvpService.saveAaaSettings( aaaSettings.authenticationServerType,
                                       aaaSettings.authorizationServerType )

   def replaceDevice( self, failed, replacement ):
      '''
      Replace the failed device with the replacement device and returns a list of
      task IDs
      '''
      assert isinstance( failed, Device )
      assert isinstance( replacement, Device )
      return self.cvpService.replaceDevice( failed.macAddress, failed.fqdn,
                                            replacement.macAddress,
                                            replacement.fqdn )

   def generateCsr( self, csr ):
      '''
      Generates a cvp csr.
      '''
      assert isinstance( csr, CSR )
      return self.cvpService.generateCsr( csr.__dict__ )

   def bindCertWithCsr( self, certBytes ):
      '''
      Bind a certificate with the CSR key to use as the CVP certificate.

      Argument:
         certBytes -- Certificate(in PEM/DER format) is passed as bytes.
      '''
      certInfo = { 'publicCertFile' : base64.b64encode( bytes( certBytes ) )
                 }
      r = self.cvpService.bindCertWithCsr( certInfo )
      return Certificate( Certificate.CVP, r[ 'commonName' ],
               r[ 'subjectAlternateNameIPList' ], r[ 'subjectAlternateNameDNSList' ],
               r[ 'organization' ], r[ 'organizationUnit' ], r[ 'location' ],
               r[ 'state' ], r[ 'country' ], r[ 'encryptAlgorithm' ],
               r[ 'digestAlgorithm' ], r[ 'keyLength' ], r[ 'validity' ],
               'Cloudvision Certificate' )

   def importCertificate( self, certType, certBytes, keyBytes, passPhrase="" ):
      '''
      Import a certificate and key to be used for Cloudvision portal certificate or
      as a Device Certificate Authority.

      Argument:
         certBytes -- Certificate(in PEM/DER format) is passed as bytes.
         keyBytes -- Private key(in PEM/DER format) is passed as bytes.
         passPhrase -- The passphrase for a optionally encrypted private key.
      '''
      certInfo = { "certType"    : certType,
                   "passPhrase"  : passPhrase,
                   "privateKey"  : base64.b64encode( bytes( keyBytes ) ),
                   "publicCert"  : base64.b64encode( bytes( certBytes ) )
                 }
      r = self.cvpService.importCertificate( certInfo )
      return Certificate( certType, r[ 'commonName' ],
               r[ 'subjectAlternateNameIPList' ], r[ 'subjectAlternateNameDNSList' ],
               r[ 'organization' ], r[ 'organizationUnit' ], r[ 'location' ],
               r[ 'state' ], r[ 'country' ], r[ 'encryptAlgorithm' ],
               r[ 'digestAlgorithm' ], r[ 'keyLength' ], r[ 'validity' ],
               'Cloudvision Certificate' )

   def exportCertificate( self, certType, passPhrase="" ):
      '''
      Export a certificate and key to be used for Cloudvision portal.

      Argument:
         certType   -- Certificate type can be cvpCert or dcaCert.
         passPhrase -- The private key may be optionally encrypted with a passphrase.

      Return values:
         Tuple ( certBytes, keyBytes ) where
         certBytes -- Certificate(in PEM format) in bytes.
         keyBytes -- Private key(in PEM format) in bytes.
      '''
      certificateInfo = {
                           "certType"   : certType,
                           "passPhrase" : passPhrase
                        }
      r = self.cvpService.exportCertificate( certificateInfo )
      cert = r[ 'cert' ]
      zIO = io.BytesIO( base64.b64decode( bytes( cert ) ) )
      zFile = zipfile.ZipFile( zIO, 'r' )
      keyFile  = r[ 'keyFilename' ]
      certFile = r[ 'certFilename' ]

      keyPem = certPem = None
      with zFile.open( keyFile, 'r' ) as k:
         keyPem = ''.join( k.readlines() )
      with  zFile.open( certFile, 'r' ) as c:
         certPem = ''.join( c.readlines() )
      return ( certPem, keyPem )

   def deleteCsr( self ):
      '''
      Deletes a cvp csr.
      '''
      return self.cvpService.deleteCsr()

   def getCsr( self ):
      '''
      Retrieves a cvp csr.
      '''
      r = self.cvpService.getCertificate( 'csr' )
      return CSR( r[ 'commonName' ], r[ 'subjectAlternateNameIPList' ],
             r[ 'subjectAlternateNameDNSList' ], r[ 'organization' ],
             r[ 'organizationUnit' ], r[ 'location' ], r['state'], r[ 'country' ],
             r[ 'encryptAlgorithm' ], r[ 'digestAlgorithm' ], r[ 'keyLength' ],
             r[ 'emailId' ], 'Csr for Cloudvision Certificate' )

   def getCsrPEM( self ):
      '''
      Retrieves a PEM encoded csr string .
      '''
      return self.cvpService.getCsrPEM()[ 'csr' ]

   def getCertificate( self, certType ):
      '''
      Retrieves a certificate of a given type from the cvp.
      '''
      Certificate.checkCertificateType( certType )
      r = self.cvpService.getCertificate( certType )
      return Certificate( certType, r[ 'commonName' ],
               r[ 'subjectAlternateNameIPList' ], r[ 'subjectAlternateNameDNSList' ],
               r[ 'organization' ], r[ 'organizationUnit' ], r[ 'location' ],
               r[ 'state' ], r[ 'country' ], r[ 'encryptAlgorithm' ],
               r[ 'digestAlgorithm' ], r[ 'keyLength' ],
               r[ 'validity' ], 'Cloudvision Certificate' )

   def generateCertificate( self, certificate, enable=False ):
      '''
      Generates certificate of a given type. Enables it for use in the
      cvp system if needed.
      '''
      Certificate.checkCertificateType( certificate.certType )
      result = self.cvpService.generateCertificate( certificate.__dict__ )
      if not enable:
         return ( result, None )
      return ( result, self.enableCertificate( certificate.certType ) )

   def enableCertificate( self, certType ):
      '''
      Enables a generated certificate for use in the
      cvp system.
      '''
      Certificate.checkCertificateType( certType )
      if certType == Certificate.DCA:
         return self.cvpService.enableDCA()
      return self.cvpService.installCvpCertificate()

   def disableDCA( self ):
      '''
      Disables the DCA feature on cvp.
      '''
      return self.cvpService.disableDCA()

   def isDCAEnabled( self ):
      '''Returns True if DCA is enabled, False otherwise.'''
      result = self.cvpService.isDCAEnabled()
      return result[ 'isDCAEnabled' ]

   def reInstallDeviceCertificate( self, devices ):
      '''Reinstall DCA for devices'''
      devMacs = []
      for dev in devices:
         assert isinstance( dev, Device )
         devMacs.append( dev.macAddress )
      self.cvpService.installDeviceCertificate( True, devMacs )

   def reInstallDeviceCertificateOnContainer( self, container ):
      '''Reinstall DCA on container level'''
      assert isinstance( container, Container )
      containerInfo = self._getContainerInfo( container.name )
      containerId = containerInfo[ 'key' ]
      self.cvpService.reInstallDeviceCertificateOnContainer( containerId )

   def importTrustedCert( self, filename, dirPath ):
      '''Upload a trusted cert into cvp.'''
      self.cvpService.importTrustedCert( filename, dirPath )

   def getTrustedCertsInfo( self ):
      '''Get all trusted certs.'''
      return self.cvpService.getTrustedCertsInfo()

   def _getTrustedCertsFingerprintsByName( self, certName ):
      '''Return fingerprints for corresponding cert name.
         There may be multiple certs for one cert name.'''
      fingerprints = []
      for trustedCertInfo in self.getTrustedCertsInfo():
         if certName == trustedCertInfo[ 'certName' ]:
            fingerprints.append( trustedCertInfo[ 'fingerPrint' ] )
      return fingerprints

   def deleteTrustCertsByFingerprints( self, fingerprints ):
      '''Delete trusted certs by fingerprints.
         A fingerprint is unique for any cert.'''
      self.cvpService.deleteTrustedCertsByFingerprints( fingerprints )

   def deleteTrustedCertsByName( self, certName ):
      '''Delete all trusted certs by the given cert name.
         There may be multiple certs for one cert name.'''
      fingerprints = self._getTrustedCertsFingerprintsByName( certName )
      if fingerprints == []:
         raise cvpServices.CvpError( errorCodes.CERT_DOES_NOT_EXIST )
      self.cvpService.deleteTrustedCertsByFingerprints( fingerprints )

   def exportTrustedCertsByFingerprints( self, fingerprints ):
      '''Export trusted certs by fingerprints.
         Return a list of pems
      '''
      return self.cvpService.exportTrustedCerts( fingerprints )

   def exportTrustedCertsByName( self, certName ):
      '''Export trusted certs by the cert name.
         Return a list of pems
      '''
      fingerprints = self._getTrustedCertsFingerprintsByName( certName )
      return self.cvpService.exportTrustedCerts( fingerprints )
