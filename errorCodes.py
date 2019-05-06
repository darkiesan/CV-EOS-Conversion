# Copyright (c) 2015 Arista Networks, Inc.  All rights :wqreserved.532
# Arista Networks, Inc. Confidential and Proprietary.
'''
@Copyright: 2015-2016 Arista Networks, Inc.
Arista Networks, Inc. Confidential and Proprietary.

Error codes for the cvp python APIs
'''

NO_ERROR_CODE = 0
UNKNOWN_ERROR_CODE = 1
UNKNOWN_REQUEST_RESPONSE = 2
INVALID_ARGUMENT = 3
TIMEOUT = 4
TASK_EXECUTION_ERROR = 5
FILE_DOWNLOAD_ERROR = 6
EVENT_COMPLETION_ERROR = 7
DCA_INSTALLATION_FAILED = 8
DCA_INSTALLATION_IN_PROGRESS = 9
INVALID_CONFIGLET_NAME = 1002
INVALID_CONFIGLET_TYPE = 1003
CONFIGLET_GENERATION_ERROR = 1004
CONFIGLET_BUILDER_PYTHON_ERROR = 1005
INVALID_IMAGE_BUNDLE_NAME = 2002
INVALID_IMAGE_ADDITION = 2003
INVALID_CONTAINER_NAME = 3002
DEVICE_ALREADY_EXISTS = 4001
DEVICE_LOGIN_UNAUTHORISED = 4002
DEVICE_INVALID_LOGIN_CREDENTIALS = 4003
DEVICE_CONNECTION_ATTEMPT_FAILURE = 4005
INVALID_IMAGE_NAME = 5001
INVALID_ROLE_NAME = 6001
ROLLBACK_TASK_CREATION_FAILED = 7001
ROLLBACK_DATA_NOT_AVAILABLE = 7002
NO_DEVICE_ELIGIBLE_FOR_ROLLBACK = 272922
EAPI_AUTHENTICATION_FAILED = 122401
UNABLE_TO_LOGIN = 112955
DATA_ALREADY_EXISTS = 122518
CANNOT_UNASSIGN_SSL_CONFIG = 122785
INVALID_NETELEMENT_ID = 122851
CONFIGLET_ALREADY_EXIST = 132518
ENTITY_DOES_NOT_EXIST = 132801
NETELEMENT_ENTITY_DOES_NOT_EXIST = 122801
CONFIG_BUILDER_ALREADY_EXSIST = 132823
CANNOT_DELETE_NON_EDITABLE_CONFIGLET = 132782
IMAGE_BUNDLE_ALREADY_EXIST = 162518
CANNOT_DELETE_IMAGE_BUNDLE = 162854
ROLE_ALREADY_EXISTS = 232518
IMAGE_ALREADY_EXISTS = 162876
UNSUPPORTED_IMAGE_VERSION = 161815
USER_ALREADY_EXISTS = 202518
INVALID_TASK_ID = 142951
AAASERVER_ALREADY_EXISTS = 212521
CCM_INVALID_DELETE = 2721019
CCM_EXECUTION_ERROR = 7
CCM_DATA_EXISTS = 272518
CCM_DATA_NOT_FOUND = 272532
CCM_NAME_EMPTY = 272810
CCM_CREATION_FAILED = 272905
CCM_INVALID_UPDATE = 272907
CCM_UPDATE_FAILED = 272909
CCM_INVALID_TIME = 272910
CCM_NAME_TOO_LONG = 272921
DEFAULT_TEMPLATE_CANT_BE_DELETED = 282721
FORWARD_SLASH_NOT_ALLOWED = 282722
TEMPLATE_COMMAND_LIST_EMPTY = 282723
TEMPLATE_NAME_EXISTS = 282724
TEMPLATE_NAME_EMPTY = 282810
TEMPLATE_COMMANDS_DUPLICATED = 282901
TEMPLATE_ILLEGAL_COMMANDS = 2821000
RESTORE_IN_PROGRESS = 112883
ACCESS_DENIED = 92407
CVP_AUTHENTICATION_FAILED = 112498
RUNTIME_EXCEPTION = 322500
DATABASE_RETRIEVAL_FAILED = 322504
EXCEPTION_JSON_PARSING = 92702
INVALID_CERTIFICATE_TYPE = 322762
RC_CANNOT_BE_REORDERED = 122959
MANDATORY_FIELD_EMPTY = 132523
INVALID_DATA_FOR_FIELD = 132889
CSR_ALREADY_EXISTS = 322763
CSR_NOT_FOUND = 322532
READ_CERTIFICATE_FAILED = 322767
CERTIFICATE_EXPIRED = 322752
DEFAULT_CERTS_CANT_BE_DELETED = 322795
CERT_DOES_NOT_EXIST = 322726
CSR_PEM_DOWNLOAD_ERROR = 322727
CANNOT_ENABLE_DEVICE_CERTIFICATE = 322788
CERT_ALREADY_EXISTS = 322798

ERROR_MAPPING = { NO_ERROR_CODE : "No error code provided",
                  UNKNOWN_ERROR_CODE : "Unknown error code",
                  TASK_EXECUTION_ERROR : "Task did not complete",
                  EVENT_COMPLETION_ERROR: "Event did not complete",
                  UNKNOWN_REQUEST_RESPONSE : "Request response is not Json",
                  INVALID_ARGUMENT : "Unsupported parameter type",
                  TIMEOUT : "Timeout" ,
                  FILE_DOWNLOAD_ERROR: "File download error",
                  INVALID_CONFIGLET_NAME : "Invalid Configlet name",
                  INVALID_CONFIGLET_TYPE : "Configlet type is not correct",
                  CONFIGLET_GENERATION_ERROR : "Unable to generate configlet using"
                     " configlet builder",
                  INVALID_IMAGE_BUNDLE_NAME : "Invalid Image Bundle name",
                  INVALID_IMAGE_ADDITION : "Image name or directory path containing"
                     " image is incorrect",
                  INVALID_CONTAINER_NAME : "Invalid container name",
                  DEVICE_ALREADY_EXISTS : "Device already exists",
                  DEVICE_LOGIN_UNAUTHORISED : "User unauthorised to login into the"
                     " device",
                  DEVICE_INVALID_LOGIN_CREDENTIALS : "Incorrect device login"
                     " credentials",
                  DEVICE_CONNECTION_ATTEMPT_FAILURE : "Failure to setup connection"
                     " with device",
                  INVALID_IMAGE_NAME : "Invalid Image Name",
                  INVALID_ROLE_NAME : "Invalid Role Name",
                  EAPI_AUTHENTICATION_FAILED : "Eapi user authentication failed",
                  UNABLE_TO_LOGIN : "Unable to login",
                  CONFIGLET_ALREADY_EXIST : "Configlet already exists ",
                  CONFIG_BUILDER_ALREADY_EXSIST : "Configlet Builder already exists",
                  CANNOT_DELETE_NON_EDITABLE_CONFIGLET : "Non editable configlet cannot be deleted",
                  IMAGE_BUNDLE_ALREADY_EXIST : "Image bundle already exists",
                  ROLE_ALREADY_EXISTS : "Role already exists ",
                  CANNOT_DELETE_IMAGE_BUNDLE : "image bundle is applied to object in"
                     " cvp",
                  DATA_ALREADY_EXISTS : "Data already exists in Database",
                  INVALID_NETELEMENT_ID : "Invalid NetElement Id.",
                  INVALID_TASK_ID : "Invalid Task Id",
                  ENTITY_DOES_NOT_EXIST: "Entity does not exist",
                  NETELEMENT_ENTITY_DOES_NOT_EXIST: "Entity does not exist",
                  IMAGE_ALREADY_EXISTS : "Image already exists",
                  UNSUPPORTED_IMAGE_VERSION : "Unsupported image version",
                  USER_ALREADY_EXISTS : "User already exists.",
                  CCM_DATA_EXISTS : "Change Control data already exists",
                  CCM_DATA_NOT_FOUND : "Change Control data not found - Wrong ccId",
                  CCM_NAME_EMPTY : "Failed to Create Change Control - Change"
                     " Control name cannot be empty",
                  CCM_CREATION_FAILED : "Failed to Create Change Control -"
                     " Remove non-executable tasks and/or tasks associated"
                     " with other Change Controls",
                  CCM_INVALID_UPDATE : "Failed to Update Change Control -"
                     " Only pending Change Control can be updated",
                  CCM_UPDATE_FAILED : "Failed to Update Change Control -"
                     " Invalid Task Id",
                  CCM_INVALID_TIME : "Scheduling time must be in future"
                     " date/time",
                  CCM_NAME_TOO_LONG : "Change Control Name can be only 32"
                     " characters long",
                  CCM_EXECUTION_ERROR : "Change control management did not"
                     " complete",
                  CCM_INVALID_DELETE : "Only pending change control can be"
                  " deleted",
                  ROLLBACK_TASK_CREATION_FAILED : "Rollback action did not"
                                         " succeed",
                  ROLLBACK_DATA_NOT_AVAILABLE : "Data for Rollback not"
                                         " available",
                  NO_DEVICE_ELIGIBLE_FOR_ROLLBACK: "No Device eligible for"
                                          "rollback",
                  DEFAULT_TEMPLATE_CANT_BE_DELETED: "The default snapshot"
                           "template can't be deleted",
                  FORWARD_SLASH_NOT_ALLOWED: "Forward slash are not allowed in"
                              "commands",
                  TEMPLATE_COMMAND_LIST_EMPTY: "Snapshot template has no"
                                       "commands",
                  TEMPLATE_NAME_EXISTS: "Snapshot template name exists",
                  TEMPLATE_NAME_EMPTY: "Snapshot template name empty",
                  TEMPLATE_COMMANDS_DUPLICATED: "Snapshot template commands"
                           "duplicated",
                  TEMPLATE_ILLEGAL_COMMANDS: "No non-show and non-bash"
                           "commands are permitted",
                  RESTORE_IN_PROGRESS: "Backup Restore in progress",
                  ACCESS_DENIED : "Access denied",
                  CVP_AUTHENTICATION_FAILED : "Cvp authentication failed",
                  RUNTIME_EXCEPTION : "A runtime exception occurred in cvp",
                  DATABASE_RETRIEVAL_FAILED : "Unable to retrieve entity from database",
                  EXCEPTION_JSON_PARSING : "Exception in json data parsing",
                  INVALID_CERTIFICATE_TYPE : "Invalid certificate type",
                  RC_CANNOT_BE_REORDERED : "Reconcile configlet cannot be reordered",
                  CANNOT_UNASSIGN_SSL_CONFIG : "Cannot unassign SSL config",
                  MANDATORY_FIELD_EMPTY : "Field cannot be empty",
                  INVALID_DATA_FOR_FIELD : "Invalid data",
                  CONFIGLET_BUILDER_PYTHON_ERROR : "Python error in configlet builder",
                  CSR_ALREADY_EXISTS : "Could not add CSR since it already exists",
                  READ_CERTIFICATE_FAILED : "Error reading certificate",
                  CERTIFICATE_EXPIRED : "Certificate expired",
                  DEFAULT_CERTS_CANT_BE_DELETED : "Default certs cannot be deleted",
                  CERT_DOES_NOT_EXIST : "Cert does not exist",
                  CSR_PEM_DOWNLOAD_ERROR : "Error in downloading CSR certificate",
                  CSR_NOT_FOUND : "CSR not found",
                  DCA_INSTALLATION_FAILED : "Certificate installation failed",
                  DCA_INSTALLATION_IN_PROGRESS : "Certificate installation in progress",
                  CANNOT_ENABLE_DEVICE_CERTIFICATE : "Cannot enable device certificate "
                           "authority due to <number> active events",
                  CERT_ALREADY_EXISTS: "Cert already exists"
                }

