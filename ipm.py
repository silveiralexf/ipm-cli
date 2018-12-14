#!/usr/bin/env python
# ------------------------------------------------------------------------------------------------------
# API Client for communicating with IBM Application Performance Management (IPM) REST API
# Requirements: - Python3
#               - Python Requests Module
#               - Access to an active IPM subscription (cloud/private).
# ------------------------------------------------------------------------------------------------------
# Author        : Felipe Silveira (fsilveir@br.ibm.com)
# Repository    : https://github.com/fsilveir/ipm-cli
# ------------------------------------------------------------------------------------------------------

import os
import sys
import json
import hashlib
import base64
import getpass
import requests
import socket
import time
import uuid
import binascii
from urllib3.exceptions import InsecureRequestWarning

# ------------------------------------------------------------------------------------------------------------

class Subscription:

    @staticmethod
    def login():
        """Main login function, interactively asks for IPM subscription information and credentials."""

        try:
            ipm_accounts = os.path.expanduser("~/.ipmaccounts")
            ipm_config = os.path.expanduser("~/.ipmconfig")

            with open(ipm_accounts, "r") as f:
                data = json.load(f)
                data_choice = []
                n = 0

                for _ in data:
                    id_num = str(data[n]["id"])
                    alias = str(data[n]["alias"])
                    ipm_type = str(data[n]["type"])
                    subscription = str(data[n]["subscription"])
                    region = str(data[n]["region"])
                    print ("{0:<2} - IPM Account: {1:<25} Subscription: {2:<32}    region: {3:>2}".format(id_num,alias,subscription,region))
                    n += 1
                choice = input("\nChoose the number of the subscription you want to login, or type the subscription \n(ex. fea2ea0f40c71c59d11c5a49d9269d0e / 9.212.149.105:8091 ):")

                n = 0
                for _ in data:
                    id_num = str(data[n]["id"])
                    if choice == id_num:
                        alias = str(data[n]["alias"])
                        subscription = str(data[n]["subscription"])
                        region = str(data[n]["region"])
                        ipm_type = str(data[n]["type"])
                        data_choice = (id_num, ipm_type, alias, subscription, region)
                    n += 1
                if not data_choice:
                    subscription = choice

                    type_flag, region_flag = False, False

                    while (type_flag != True):
                        ipm_type = input('ipm_type your subscription type (cloud / private): ')
                        if (ipm_type == "cloud" or ipm_type == "private"):
                            type_flag = True
                            if (ipm_type == "private"):
                                region_flag = True
                                region = "pv"

                    while (region_flag != True):
                        region = input('ipm_type the region of your IPM subscription (eu, na, ap, la): ')
                        if (region == 'na' or region == "eu" or region == "ap" or region == "la"):
                            region_flag = True
                    alias = input('ipm_type an alias for your IPM subscription (ex. trial-na, sla-eu): ')
                else:
                    subscription = data_choice[3]
                    region = data_choice[4]

        except KeyboardInterrupt:
            sys.exit (0)
        except os.error:
            subscription  = input("\nNo subscription was found on '%s'. \r\nType your IPM subscription number (ex. fea2ea0f40c71c59d11c5a49d9269d0e): " % ipm_accounts)

            type_flag, region_flag = False, False

            while (type_flag != True):
                ipm_type = input('Type your subscription type (cloud / private): ')
                if (ipm_type == "cloud" or ipm_type == "private"):
                    type_flag = True
                    if (ipm_type == "private"):
                        region_flag = True
                        region = "pv"

            while (region_flag != True):
                region = input('Type the region of your IPM subscription (eu, na, ap, la): ')
                if (region == 'na' or region == "eu" or region == "ap" or region == "la"):
                    region_flag = True

            alias = input('Type an alias for your IPM subscription (ex. trial-na, sla-eu): ')

        username = input('Type your IPM username (ex.: fsilveir@br.ibm.com / apmadmin): ')
        password = getpass.getpass('Type your password: ')
        credentials = (subscription + "," + region + "," + alias + "," + username + "," + password + "," + ipm_type)

        token = Subscription.create_token()

        encoded_credentials = base64.b64encode(credentials.encode('utf-8'))
        secret = (str(token) + Subscription.create_hash(str(encoded_credentials)) + str(token) + str(encoded_credentials) + str(token))

        if Subscription.check_connection(subscription,region,alias,username,password,ipm_type):
            try:
                with open(ipm_config, "w") as f:
                    f.write(secret)
                    print ("SUCCESS - You're logged on '%s.%s' (%s) as user '%s' " % (alias, region, subscription, username))
                    sys.exit (0)
            except IOError:
                print ("ERROR - Failed to login with the credentials provided. Please try again.\n")
                checks_out_on_error(ipm_config)
        else:
            print ("ERROR - Failed to login with the credentials provided. Please try again.\n")
            checks_out_on_error(ipm_config)

        return subscription, region, alias, username, password, ipm_type

    @staticmethod
    def check_connection(subscription, region, alias, username, password, ipm_type):
        """Check if the provided crendials are valid to authenticate on IPM API."""

        ipm_config = os.path.expanduser("~/.ipmconfig")
        queystring = '/1.0/thresholdmgmt/threshold_types/itm_private_situation/thresholds?_offset=1&_limit=1'
        if (ipm_type == "cloud"):
            url = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com' + queystring
            r = Subscription.IPMlogin(ipm_type,url,username,password)
        elif (ipm_type == "private"):
            url = 'https://' + subscription + queystring
            r = Subscription.IPMlogin(ipm_type,url,username,password)

        if (r.status_code == 200):
            error = b"Your subscription has expired and is now suspended from the <b>IBM Performance Management (SaaS) service"
            if (error in r.content):
                print ("Your subscription has expired and is now suspended from the IBM Performance Management (SaaS) service\n\n")
                Subscription.login()
            return subscription, region, alias, username, password, ipm_type
        elif (r.status_code == 401):
            print ("ERROR - Failed to login with the credentials provided. Please try again.\n")
            checks_out_on_error(ipm_config)
        else:
            print ("ERROR - Failed to perform login. Please confirm you can log directly to your subscription.\n")
            print ("HTTP STATUS CODE ", r.status_code)
            print (r.text)
            sys.exit(1)

    @staticmethod
    def logout():
        """Logs out from the IPM subscription and removes the cached secret."""
        ipm_config = os.path.expanduser("~/.ipmconfig")

        if os.path.exists(ipm_config) == True:
            os.remove(ipm_config)
        print ("You have successfully logged out.")

    @staticmethod
    def IPMlogin(ipm_type,url,username,password):
        """ Performs Login request to IPM API to validate the connection."""
        try:
            if (ipm_type == "cloud"):
                r = requests.get(url, auth=(username, password), timeout=60)
                return r
            elif (ipm_type == "private"):
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                r = requests.get(url, auth=(username, password), verify=False, timeout=60)
                return r
        except requests.ConnectionError as e:
            print("ERROR - Connection Error. Make sure you have connectivity to the IPM subscription. Technical Details given below.\n")
            print(str(e))
            sys.exit(1)
        except requests.Timeout as e:
            print("ERROR - HTTP Timeout Error")
            print(str(e))
            sys.exit(1)
        except requests.RequestException as e:
            print("ERROR - General Error")
            print(str(e))
            sys.exit(1)
        except requests.SSLError:
            print("ERROR - An SSL error occurred. %s" % r.status_code)
            sys.exit(1)
        except requests.HTTPError:
            print("ERROR - An HTTP Error occurred with status code %s" % r.status_code)
            sys.exit(1)
        except KeyboardInterrupt:
            print("ERROR - Program closed unexpectedly.")
            sys.exit(1)

    @staticmethod
    def validate_session(session_type):
        """ Validate user's credention during a session."""

        ipm_config = os.path.expanduser("~/.ipmconfig")
        if os.path.exists(ipm_config) == True:
            ipm_config_age = os.path.getatime(ipm_config)
            half_hour = time.time() - 240 * 60

            ## DEBUG --> Uncomment values below for converting from epoch to human readable time
            # file_age = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ipm_config_age))
            # file_age_limit = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(half_hour))

            if ipm_config_age < half_hour:
                #print ("DEBUG --> KEY IS OLDER THAN 240 MINUTES - FILE_AGE", file_age, "AGE_LIMIT", file_age_limit )
                os.remove(ipm_config)

        try:
            with open(ipm_config, "r") as f:
                revelations = []
                revelation = f.read().strip()
                token = Subscription.create_token()
                revelation = revelation.replace(str(token),'')
                revelation = str(revelation[66:][:-1])

                try:
                    secret = (base64.b64decode(revelation).decode().split(","))
                except (binascii.Error):
                    print ("INFO - Your session expired. please proceed with authentication.")
                    os.remove(ipm_config)
                    Subscription.login()
                for item in secret:
                    revelations.append(item)

                subscription = revelations[0]
                region = revelations[1]
                alias = revelations[2]
                username = revelations[3]
                password = revelations[4]
                ipm_type =  revelations[5]

                if session_type == 'login':
                    print ("INFO - Your're already logged to IPM Subscription: '%s' (%s.%s) as user: '%s' \n" %(alias, subscription, region, username))
                    relogin = input("Press 'R' to relogin or enter any other key to proceed with the same credentials: ").lower()

                    if (relogin == 'R'.lower()):
                        print ('\n')
                        os.remove(ipm_config)
                        Subscription.login()
                    else:
                        subscription, region, alias, username, password, ipm_type = Subscription.check_connection(subscription, region, alias, username, password, ipm_type)
                        return subscription, region, alias, username, password, ipm_type

                return subscription, region, alias, username, password, ipm_type

        except (OSError, IOError):
            print ("INFO - You're not authenticated, please proceed with authentication")
            Subscription.login()

    @staticmethod
    def create_hash(password):
        """Creates sha256 hash to encrypt the credentials."""
        return hashlib.sha256(str.encode(password)).hexdigest()

    @staticmethod
    def create_token():
        """Generates unique token based on network info to be used as part of the password hash/secret."""
        hostname = socket.gethostname()
        token = socket.getaddrinfo(hostname, 0)
        token = (str(token))
        token = base64.b64encode(token.encode('utf-8'))
        return token

class Agents:

    @staticmethod
    def get_agents(arguments):
        """Get the list of monitored agents from the API and display it on the screen."""

        session_type = 'get_agents'

        # If function is being called from login, there will be no values assigned to vars so, we must first give it a try
        try:
            subscription, region, alias, username, password, ipm_type = Subscription.validate_session(session_type)
        except TypeError:
            sys.exit (0)

        href_complement = "/1.0/topology/mgmt_artifacts"
        r = Agents.make_agent_request(ipm_type,session_type,href_complement,subscription,region,username,password)

        json_agt_dict = json.loads(r.content)
        num_arguments = (len(arguments))

        # Displays all agents in the subscription matching a given string
        n = 0
        agents = []
        if (num_arguments > 3):
            print ("'agent_name','hostname','product_code','description','version','status'")
            for _ in json_agt_dict['_items']:
                try:
                    agt_name = json_agt_dict['_items'][n]['keyIndexName']
                    hostname = json_agt_dict['_items'][n]['hostname']
                    product_code =  json_agt_dict['_items'][n]['productCode']
                    description =  json_agt_dict['_items'][n]['description']
                    version =  json_agt_dict['_items'][n]['version']
                    status =  json_agt_dict['_items'][n]['online']
                except KeyError:
                    hostname = "unknown"
                    product_code = "unknown"
                    description = "unknown"
                    version = "unknown"
                    status = "N"

                for num in range(3, num_arguments):
                    if arguments[num].lower() in agt_name.lower():
                        #print ('\'' + agt_name + '\'' + "," + \
                        agents.append('\'' + agt_name + '\'' + "," + \
                            '\'' + hostname + '\'' + "," + \
                            '\'' + product_code + '\'' + "," + \
                            '\'' + description + '\'' + "," + \
                            '\'' + version + '\'' + "," + \
                            '\'' + status + '\'' )
                n += 1

            for line in (sorted(agents)):
                print (line)
            sys.exit(0)

        # Display all the agents in the subscription
        print ("'agent_name','hostname','product_code','description','version','status'")
        n = 0
        for _ in json_agt_dict['_items']:
            try:
                agt_name = json_agt_dict['_items'][n]['keyIndexName']
                hostname = json_agt_dict['_items'][n]['hostname']
                product_code =  json_agt_dict['_items'][n]['productCode']
                description =  json_agt_dict['_items'][n]['description']
                version =  json_agt_dict['_items'][n]['version']
                status =  json_agt_dict['_items'][n]['online']
            except KeyError:
                try:
                    #product_code, version, description =  'unknown', 'unknown', 'unknown'
                    status =  json_agt_dict['_items'][n]['online']
                except NameError:
                    version, hostname, product_code, status, description = 'unknown', 'unknown', 'unknown', 'N', 'unknown'
            n += 1
            #print ('\'' + agt_name + '\'' + "," + \
            agents.append('\'' + agt_name + '\'' + "," + \
                    '\'' + hostname + '\'' + "," + \
                    '\'' + product_code + '\'' + "," + \
                    '\'' + description + '\'' + "," + \
                    '\'' + version + '\'' + "," + \
                    '\'' + status + '\'' )

        for line in (sorted(agents)):
            print (line)
        sys.exit(0)

    @staticmethod
    def make_agent_request(ipm_type,session_type,href_complement,subscription,region,username,password):
        """ Executes GET request to the Agent API."""
        if (ipm_type == "cloud"):
            href = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com'
            headers, querystring = set_querystring(href,session_type)
            url = href + href_complement
            r = requests.get(url, params=querystring , headers=headers, auth=(username,password), timeout=60)
            return r
        elif (ipm_type == "private"):
            href = 'https://' + subscription
            headers, querystring = set_querystring(href,session_type)
            url = href + href_complement
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            r = requests.get(url, params=querystring , headers=headers, auth=(username,password), timeout=60, verify=False)
            return r
        else:
            print ("ERROR - Could not determine IPM subscription type. Exiting!")
            sys.exit(1)


    @staticmethod
    def add_del_agt(arguments):
        """Adds an agent to a Resource Group."""

        session_type = "get_agents"

        if (len(arguments) == 5):
            operation_type = arguments[1]
            search_agent_name = arguments[3]
            rg_id = arguments[4]

            # If function is being called from login, there will be no values assigned to vars so, we must first give it a try
            try:
                subscription, region, alias, username, password, ipm_type = Subscription.validate_session(session_type)
            except TypeError:
                sys.exit (0)

            href_complement = "/1.0/topology/mgmt_artifacts"
            r = Agents.make_agent_request(ipm_type,session_type,href_complement,subscription,region,username,password)

            json_agt_dict = json.loads(r.content)

            n = 0
            session_type = "add_agents"
            encoded_credentials = base64.b64encode(("%s:%s" % (username, password)).encode()).decode()

            for _ in json_agt_dict['_items']:
                try:
                    agt_id =  json_agt_dict['_items'][n]['_id']
                    agt_name = json_agt_dict['_items'][n]['keyIndexName']
                except KeyError:
                    agt_id = "unknown"
                    agt_name = "unknown"

                if search_agent_name in agt_name:
                    r = Agents.make_agt_post_del_request(ipm_type,session_type,agt_id,rg_id,subscription,region,encoded_credentials,operation_type)

                    if (r.status_code == 200 or r.status_code == 204 ):
                        if (operation_type == "add"):
                            print ("SUCCESS - '%s' was successfully added to Resource Group '%s'." %(agt_name, rg_id))
                        elif (operation_type == "del"):
                            print ("SUCCESS - '%s' was successfully removed from Resource Group '%s'." %(agt_name, rg_id))
                    else:
                        print ("ERROR - Script failed with 'HTTP Status code %s' when trying to perform the operation on Resource Group '%s'." %(r.status_code, rg_id))

                n += 1
        else:
            usage()

    @staticmethod
    def make_agt_post_del_request(ipm_type,session_type,agt_id,rg_id,subscription,region,encoded_credentials,operation_type):
        """ Executes POST or DEL request to the Agent API."""

        if (operation_type == "add"):
            method = "POST"
        elif (operation_type == "del"):
            method = "DELETE"
        else:
            print ("ERROR - Could not determine session type. Exiting!")
            sys.exit(1)

        if (ipm_type == "cloud"):
            href = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com'
            url = href + '/1.0/topology/mgmt_artifacts/' + rg_id + "/references/to/contains/" + agt_id
            headers = set_headers_for_post_deletion(href,session_type,rg_id,encoded_credentials)

            r = requests.request(method, url, headers=headers, timeout=60)
            return r

        elif (ipm_type == "private"):
            href = 'https://' + subscription
            url = href + '/1.0/topology/mgmt_artifacts/' + rg_id + "/references/to/contains/" + agt_id
            headers = set_headers_for_post_deletion(href,session_type,rg_id,encoded_credentials)

            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            r = requests.request(method, url, headers=headers, timeout=60, verify=False)
            return r

class Thresholds:

    @staticmethod
    def get_usage():
        """ Display threshold usage instructions when wrong arguments are used."""
        print ("""
    You did not specify a valid command or failed to pass the proper options. Exiting!
    Usage:
            ----------------------------------------------------------------------------------------------------
            ./ipm.py get thr <all / product code / thr_name> / -f <threshold_list>
            ----------------------------------------------------------------------------------------------------
            get thr all                     : List all existing thresholds in the subscription.
            get thr <product_code>          : List all thresholds of a particular product code (ex: lz, nt, etc)
            get thr <thr_name>              : Displays a single threshold in JSON format.
            get thr -f  <threshold_list>    : Displays multiple thresholds from a list in JSON format.
            get thr -rg <rg_id>             : Displays all the thresholds assigned to this Resource Group.
    """)
        sys.exit(1)

    @staticmethod
    def add_del_usage():
        """ Display threshold usage instructions when wrong arguments are used."""
        print ("""
    You did not specify a valid command or failed to pass the proper options. Exiting!
    Usage:
            ----------------------------------------------------------------------------------------------------
            ./ipm.py add thr <threshold_name/json_file> [ -rg <rg_id> ]
            ----------------------------------------------------------------------------------------------------
            add thr <threshold_json_file>         : Creates a threshold from an IPM8 JSON export file
            add thr <threshold_name> -rg <rg_id>  : Adds a threshold to a Resource Group.

            ----------------------------------------------------------------------------------------------------
            ./ipm.py del thr <threshold_name> [ -rg <rg_id> ]
            ----------------------------------------------------------------------------------------------------
            del thr <threshold_name>              : Deletes a threshold by name.
            del thr <threshold_name> -rg <rg_id>  : Removes a threshold to a Resource Group (*)
    """)
        sys.exit(1)

    @staticmethod
    def get_thresholds():
        """Get the list of thresholds from API and display it on the screen."""

        session_type = 'get_thresholds'

        # If function is being called from login, there will be no values assigned to vars so, we must first give it a try
        try:
            subscription, region, alias, username, password, ipm_type = Subscription.validate_session(session_type)
        except TypeError:
            sys.exit (0)

        arguments = get_arg(sys.argv)
        if (len(arguments) == 3):
            Thresholds.get_usage()

        # Check if user wants to display all thresholds or all by product code (***NEEDS IMPROVEMENT***)
        elif (len(arguments) >= 4):

            if arguments[3] == 'all':
                thr_type_list = ("GSMA Windows OS", "GSMA AIX OS", "GSMA Linux OS", "GSMA IBM Spectrum Protect", "GSMA IBM Workload Scheduler", "GSMA Oracle DB Agent",\
                "Active Directory","MS Exchange", "MS IIS", "Windows OS", "AIX OS", "Linux OS", "Bluemix Integration", "DB2", "Virtual Servers" "Transaction Tracking", \
                "Synthetic Transaction" , "Web Response Time", "WebSphere Application Servers", "WebSphere Agent", "Oracle Database Extended", "Cassandra", \
                "Microsoft SQL Server", "HTTP Server", "HMC Base", "PostgreSQL", "MongoDB", "Ruby Application", "Tomcat", "VMWare VI", "WebSphere MQ")
            elif arguments[3].lower() == '06':
                thr_type_list = ("GSMA Windows OS",)
            elif arguments[3].lower() == '07':
                thr_type_list = ("GSMA AIX OS",)
            elif arguments[3].lower() == '08':
                thr_type_list = ("GSMA Linux OS",)
            elif arguments[3].lower() == '11':
                thr_type_list = ("GSMA IBM Workload Scheduler",)
            elif arguments[3].lower() == '13':
                thr_type_list = ("GSMA IBM Spectrum Protect",)
            elif arguments[3].lower() == '3z':
                thr_type_list = ("Active Directory",)
            elif arguments[3].lower() == 'bi':
                thr_type_list = ("Bluemix Integration",)
            elif arguments[3].lower() == 'hu':
                thr_type_list = ("HTTP Server",)
            elif arguments[3].lower() == 'kj':
                thr_type_list = ("MongoDB",)
            elif arguments[3].lower() == 'km':
                thr_type_list = ("Ruby Application",)
            elif arguments[3].lower() == 'lz':
                thr_type_list = ("Linux OS",)
            elif arguments[3].lower() == 'mq':
                thr_type_list = ("WebSphere MQ",)
            elif arguments[3].lower() == 'nt':
                thr_type_list = ("Windows OS",)
            elif arguments[3].lower() == 'oq':
                thr_type_list = ("Microsoft SQL Server",)
            elif arguments[3].lower() == 'ot':
                thr_type_list = ("Tomcat",)
            elif arguments[3].lower() == 'ph':
                thr_type_list = ("HMC Base",)
            elif arguments[3].lower() == 'PostgreSQL':
                thr_type_list = ("pn",)
            elif arguments[3].lower() == 'rz':
                thr_type_list = ("Oracle Database",)
            elif arguments[3].lower() == 'Response Time':
                thr_type_list = ("t5",)
            elif arguments[3].lower() == 'vm':
                thr_type_list = ("Virtual Servers",)
            elif arguments[3].lower() == 'yn':
                thr_type_list = ("WebSphere Agent",)
            elif arguments[3].lower() == 'zc':
                thr_type_list = ("Cassandra",)
            elif arguments[3].lower() == 'ux':
                thr_type_list = ("UNIX OS",)
            elif arguments[3].lower() == 'ud':
                thr_type_list = ("db2",)
            elif arguments[3].lower() == 'sn':
                thr_type_list = ("Synthetic Transaction",)
            else:

                # prints multiple thresholds for a list informed by the user
                if arguments[3] == '-f':
                    if (len(arguments) != 5):
                        Thresholds.get_usage()

                    filename = arguments[4]
                    if os.path.exists(arguments[4]):
                        threshold_list = []
                        with open(filename, "r") as f:
                            for line in f:
                                threshold_list.append(line)
                        #return(threshold_list)

                        jsonOutputList = []
                        for threshold_name in threshold_list:

                            payload = '/1.0/thresholdmgmt/threshold_types/itm_private_situation/thresholds/?_filter=label%3D' + threshold_name.strip()
                            r = Thresholds.make_threshold_request(ipm_type,session_type,payload,subscription,region,username,password)


                            if (r.status_code == 200):
                                json_thr_dict = json.loads(r.content)
                                n = 0
                                thresholds_found = len(json_thr_dict['_items'])

                                if thresholds_found > 0:
                                    for _ in json_thr_dict['_items']:
                                        threshold = {}
                                        threshold['label'] = json_thr_dict['_items'][n]['label']
                                        threshold['configuration'] = json_thr_dict['_items'][n]['configuration']
                                        threshold['description'] = json_thr_dict['_items'][n]['description']
                                        #print (json.dumps(threshold, indent=4))
                                        jsonOutputList.append(threshold)
                                        n += 1
                                else:
                                    print ("INFO - Threshold '%s' was not found." % threshold_name.strip())

                            else:
                                print ("Failed to extract information. Script is aborting! ")
                                sys.exit(1)

                        print (json.dumps(jsonOutputList, indent=4, sort_keys=True))
                    else:
                        print ("ERROR - File '%s' was not found or can't be accessed. Exiting!" % filename)
                        sys.exit(1)
                    sys.exit(0)

                # Prints all existing thresholds assigned to a specific Resource Group
                elif arguments[3] == '-rg':
                    if (len(arguments) != 5):
                        Thresholds.get_usage()

                    rg_id = arguments[4]
                    payload = '/1.0/thresholdmgmt/resource_assignments?_offset=1&_limit=99999'
                    r = Thresholds.make_threshold_request(ipm_type,session_type,payload,subscription,region,username,password)

                    if (r.status_code == 200):
                        json_thr_assignments = json.loads(r.content)
                    else:
                        print ("Resource Group \'%s\' is invalid or empty. Exiting!" % rg_id)
                        sys.exit(1)

                    n = 0
                    matches = 0
                    count_of_rgs = len(json_thr_assignments['_items'])

                    if (count_of_rgs > 0):
                        for _ in json_thr_assignments['_items']:
                            if (rg_id in (json_thr_assignments['_items'][n]['resource']['_id'])):
                                matches += 1
                                if (matches == 1):
                                    print ("'threshold_name','product_code','threshold_type','description'")

                                payload = json_thr_assignments['_items'][n]['threshold']['_href']
                                r = Thresholds.make_threshold_request(ipm_type,session_type,payload,subscription,region,username,password)

                                if (r.status_code == 200):
                                    thresholds_dic = json.loads(r.content)
                                else:
                                    print ("ERROR - Failed to complete request on given item. Exiting!")
                                    sys.exit(1)
                                print ("'" + thresholds_dic['label'] + "','" + thresholds_dic['_appliesToAgentType'] + "','" + thresholds_dic['description'] + "'")
                            n += 1
                        if (matches == 0):
                            print ("ERROR - Resource Group '%s' is invalid or doesn't have any resources assigned." %(rg_id))
                            sys.exit(1)
                    sys.exit(0)

                # prints a single threshold that was informed
                threshold_name = arguments[3]
                payload = '/1.0/thresholdmgmt/threshold_types/itm_private_situation/thresholds/?_filter=label%3D' + threshold_name
                r = Thresholds.make_threshold_request(ipm_type,session_type,payload,subscription,region,username,password)

                if (r.status_code == 200):
                    json_thr_dict = json.loads(r.content)
                    n = 0
                    thresholds_found = len(json_thr_dict['_items'])

                    if thresholds_found > 0:
                        for _ in json_thr_dict['_items']:
                            threshold = {}
                            threshold['label'] = json_thr_dict['_items'][n]['label']
                            threshold['configuration'] = json_thr_dict['_items'][n]['configuration']
                            threshold['description'] = json_thr_dict['_items'][n]['description']
                            print (json.dumps(threshold, indent=4))
                            n += 1
                    else:
                        print ("ERROR - Threshold '%s' was not found." % threshold_name)
                        sys.exit(1)

                    sys.exit(0)
                else:
                    print ("Failed to extract information. Script is aborting! ")
                    sys.exit(1)

        # Display thresholds by type
        print ("'threshold_name','product_code','threshold_type','description'")
        for thr_type in thr_type_list:
            payload = '/1.0/thresholdmgmt/threshold_types/itm_private_situation/thresholds?_filter=_uiThresholdType%3D' + thr_type + '&_offset=1&_limit=99999'
            r = Thresholds.make_threshold_request(ipm_type,session_type,payload,subscription,region,username,password)

            # Avoids errors in case user is asking for 'all' thresholds
            if (r.status_code == 200):
                json_thr_dict = json.loads(r.content)
            else:
                continue

            counter = 0
            thresholds = []
            for _ in json_thr_dict['_items']:
                try:
                    product_code = "'unknown"
                    label = "'unknown"
                    description = "unknown"
                    threshold_type = "Unknown"

                    product_code = Thresholds.if_not_empty(json_thr_dict['_items'][counter]['_appliesToAgentType'])
                    label = Thresholds.if_not_empty(json_thr_dict['_items'][counter]['label'])
                    description = Thresholds.if_not_empty(json_thr_dict['_items'][counter]['description'])
                    threshold_type = Thresholds.if_not_empty(json_thr_dict['_items'][counter]['_uiThresholdType'])

                except KeyError:
                    pass
                counter +=1
                thresholds.append(label + "," + product_code + "," + threshold_type + "," + description)

            for item in (sorted(thresholds)):
                print (item)

    @staticmethod
    def make_threshold_request(ipm_type,session_type,payload,subscription,region,username,password):
        """ Executes GET request to the Thresholds API."""
        if (ipm_type == "cloud"):
            url = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com' + payload
            r = requests.get(url, auth=(username, password), timeout=60)
            return r
        elif (ipm_type == "private"):
            url = 'https://' + subscription + payload
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            r = requests.get(url, auth=(username, password), verify=False, timeout=60)
            return r
        else:
            print ("ERROR - Could not determine IPM subscription type. Exiting!")
            sys.exit(1)

    @staticmethod
    def if_not_empty(value):
        """Sets a dummy value if _uiThresholdType value is None to avoid errors, added this additional check due to GSMA Monitoring Agent missed _uiThresholdType value bug."""
        if value is None:
            var = "unknown"
            return "\'" + var + "\'"
        else:
            return "\'" + value + "\'"

    @staticmethod
    def set_threshold_payload(session_type,href,encoded_credentials):
        """Sets the header for POST requests to add a new threshold from JSON file."""

        if (session_type == "add_threshold") or (session_type == "del_threshold"):
            headers = {
            'Referer' : '%s' % href,
            'Authorization' : 'Basic %s' % encoded_credentials,
            'content-type': 'application/json',
            'accept': 'application/json',
            'cache-control': 'no-cache',
            }
            return headers
        else:
            print ("ERROR - Could not determine IPM subscription type. Exiting!")
            sys.exit(1)

    @staticmethod
    def make_add_del_request(session_type,ipm_type,subscription,region,payload,encoded_credentials,username,password):
        """ Executes POST/DELETE request to the Thresholds API."""

        if (ipm_type == "cloud"):
            href = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com'
            headers = Thresholds.set_threshold_payload(session_type,href,encoded_credentials)

            if (session_type == "add_threshold"):
                url = href + '/1.0/thresholdmgmt/threshold_types/itm_private_situation/thresholds'
                r = requests.request("POST", url, json=payload, headers=headers, auth=(username,password), timeout=60)
                return r

            elif (session_type == "del_threshold"):
                threshold_id = payload
                url = href + '/1.0/thresholdmgmt/threshold_types/itm_private_situation/thresholds/' + threshold_id
                r = requests.request("DELETE", url, headers=headers, auth=(username,password), timeout=60)
                return r

        elif (ipm_type == "private"):
            href = 'https://' + subscription
            headers = Thresholds.set_threshold_payload(session_type,href,encoded_credentials)
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

            if (session_type == "add_threshold"):
                url = href + '/1.0/thresholdmgmt/threshold_types/itm_private_situation/thresholds'
                r = requests.request("POST", url, json=payload, headers=headers, auth=(username,password), timeout=60, verify=False)
                return r

            elif (session_type == "del_threshold"):
                threshold_id = payload
                url = href + '/1.0/thresholdmgmt/threshold_types/itm_private_situation/thresholds/' + threshold_id
                r = requests.request("DELETE", url, headers=headers, auth=(username,password), timeout=60, verify=False)
                return r
        else:

            print ("ERROR - Could not determine IPM subscription type. Exiting!")
            sys.exit(1)

    @staticmethod
    def add_threshold(arguments):
        """Add a new threshold from a JSON file."""

        session_type = 'add_threshold'

        # If function is being called from login, there will be no values assigned to vars so, we must first give it a try
        try:
            subscription, region, alias, username, password, ipm_type = Subscription.validate_session(session_type)
        except TypeError:
            sys.exit (0)

        if (len(arguments) == 4):
            try:
                filename = arguments[3]
                with open(filename, "r") as f:
                    payload = json.load(f)
                    encoded_credentials = base64.b64encode(("%s:%s" % (username, password)).encode()).decode()

                    r = Thresholds.make_add_del_request(session_type,ipm_type,subscription,region,payload,encoded_credentials,username,password)

                    if (r.status_code == 201):
                        print ("SUCCESS - Threshold from file '%s' was successfully created." %(filename))
                    elif (r.status_code == 409):
                        print ("WARNING - An existing threshold with the same label is already defined on file '%s'. No action was taken!" %(filename))
                        sys.exit(2)
                    else:
                        print ("ERROR - Script failed with 'HTTP Status code %s' when trying to create resource group '%s'." %(r.status_code, filename))
                        sys.exit(1)

            except json.decoder.JSONDecodeError:
                print ("ERROR - JSON file is wrongly formatted, please check the syntax and try again. Aborting!")
                sys.exit(1)
            except (IOError, OSError):
                print ("ERROR - File '%s' was not found or can't be accessed. Exiting!" % filename)
        
        # Add a threshold to a specific resource group
        elif (len(arguments) == 6):
            if (arguments[4] != '-rg'):
                Thresholds.add_del_usage()
            
            threshold_name = arguments[3]
            rg_id = arguments[5]
            
            payload = '/1.0/thresholdmgmt/threshold_types/itm_private_situation/thresholds/?_filter=label%3D' + threshold_name
            r = Thresholds.make_threshold_request(ipm_type,session_type,payload,subscription,region,username,password)

            threshold_content = json.loads(r.content)
            threshold_id = threshold_content['_items'][0]['_id']

            encoded_credentials = base64.b64encode(("%s:%s" % (username, password)).encode()).decode()

            href = "/1.0/thresholdmgmt/resource_assignments"
            if (ipm_type == "cloud"):
                url = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com' + href
                
                headers = Thresholds.set_threshold_payload(session_type,url,encoded_credentials)
                payload = Thresholds.set_body(rg_id,threshold_id)
                r = requests.post(url, data=payload, headers=headers, timeout=60)

            elif (ipm_type == "private"):
                href = 'https://' + subscription + payload
                headers = Thresholds.set_threshold_payload(session_type,url,encoded_credentials)
                payload = Thresholds.set_body(rg_id,threshold_id)
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                r = requests.post(url, data=payload, headers=headers, verify=False, timeout=60)

            if (r.status_code == 201):
                print ("SUCCESS - Threshold '%s' was successfully added to Resource Group '%s'." %(threshold_name, rg_id))
            else:
                print ("ERROR - Script failed with 'HTTP Status code %s' when trying to add threshold '%s' to Resource Group '%s'." %(r.status_code, threshold_name, rg_id))
            return r
        else:
            Thresholds.add_del_usage()

    def set_body(rg_id,threshold_id):

        payload = "{\n  \"resource\": {\n    \"_id\": \"%s\"\n  }, \
                    \n  \"threshold\": {\n    \"_id\": \"%s\"\n  }\n}" %(rg_id, threshold_id)
        return payload

    @staticmethod
    def del_threshold(arguments):
        """Deletes a new Threshold based on user's input."""

        session_type = "del_threshold"

        # If function is being called from login, there will be no values assigned to vars so, we must first give it a try to avoid errors
        try:
            subscription, region, alias, username, password, ipm_type = Subscription.validate_session(session_type)
        except TypeError:
            sys.exit (0)

        # Check the arguments and make sure Threshold is informed
        if ((len(arguments)) != 4):
            Thresholds.add_del_usage()
        else:
            threshold_name = sys.argv[3]
            encoded_credentials = base64.b64encode(("%s:%s" % (username, password)).encode()).decode()

            payload = '/1.0/thresholdmgmt/threshold_types/itm_private_situation/thresholds/?_filter=label%3D' + threshold_name
            r = Thresholds.make_threshold_request(ipm_type,session_type,payload,subscription,region,username,password)

            if (r.status_code == 200):
                json_thr_dict = json.loads(r.content)
                n = 0
                thresholds_found = len(json_thr_dict['_items'])

                if thresholds_found > 0:
                    for _ in json_thr_dict['_items']:
                        payload = json_thr_dict['_items'][n]['_id']
                        r = Thresholds.make_add_del_request(session_type,ipm_type,subscription,region,payload,encoded_credentials,username,password)

                        if (r.status_code == 204):
                            print ("SUCCESS - '%s' was successfully removed." %(threshold_name))
                        else:
                            print ("ERROR - Script failed with 'HTTP Status code %s' when trying to delete threshold '%s'." %(r.status_code, threshold_name))
                        n += 1
                else:
                    print ("ERROR - Threshold '%s' was not found." % threshold_name)
                    sys.exit(1)

                sys.exit(0)
            else:
                print ("Failed to extract information. Script is aborting! ")
                sys.exit(1)


class ResourceGroups:

    @staticmethod
    def get_resource_groups():
        """Get the list of resource groups from API and display it on the screen."""

        session_type = 'agts_from_resource_group'

        # If function is being called from login, there will be no values assigned to vars so, we must first give it a try
        try:
            subscription, region, alias, username, password, ipm_type = Subscription.validate_session(session_type)
        except TypeError:
            sys.exit (0)

        subscription, region, alias, username, password, ipm_type = Subscription.validate_session(session_type)
        arguments = get_arg(sys.argv)

        # Get list of agents assigned to a single resource group
        if (len(arguments) > 3):
            rg_id = arguments[3]
            r = ResourceGroups.make_rg_get_request(ipm_type,session_type,rg_id,subscription,region,username,password)

            if (r.status_code == 200):
                json_rg_dict = json.loads(r.content)
            else:
                print ("Resource Group \'%s\' is invalid or empty. Exiting!" % rg_id)
                sys.exit(1)

            n = 0
            agents = []
            print ("\'agent_name\',\'product_code\',\'version\',\'status\'")
            for _ in json_rg_dict['_items']:
                try:
                    agt_name = '\'' + (json_rg_dict['_items'][n]['keyIndexName']) + '\''
                    pc = '\'' + (json_rg_dict['_items'][n]['productCode']) + '\''
                    version = '\'' + (json_rg_dict['_items'][n]['version']) + '\''
                    status = '\'' + (json_rg_dict['_items'][n]['online']) + '\''
                except KeyError:
                    pc = 'unknown'
                    version = 'unknown'
                    status = 'unknown'

                n += 1
                agents.append(agt_name + "," + pc + "," + version + "," + status)

            for item in (sorted(agents)):
                print (item)

        else:
            session_type = 'get_resource_group'

            # If function is being called from login, there will be no values assigned to vars so, we must first give it a try
            try:
                subscription, region, alias, username, password, ipm_type = Subscription.validate_session(session_type)
            except TypeError:
                sys.exit (0)

            # Get list of all Resource Groups
            rg_id = "Null"
            r = ResourceGroups.make_rg_get_request(ipm_type,session_type,rg_id,subscription,region,username,password)

            json_rg_dict = json.loads(r.content)

            # Check if subscription is completely empty
            try:
                json_rg_dict['_items']
            except KeyError:
                print ("INFO - There are no Resource Groups at this IPM subscription.")
                sys.exit(1)

            n = 0
            sorted_resource_groups = []
            resource_groups = []
            print ("\'resource_group_id\',\'display_label\',\'description\'")
            for _ in json_rg_dict['_items']:
                try:
                    rg_id = json_rg_dict['_items'][n]['_id']
                    displayLabel = json_rg_dict['_items'][n]['displayLabel']
                    description = json_rg_dict['_items'][n]['description']
                except KeyError:
                    version = "unknown"
                n += 1

                resource_groups = ("\'" + rg_id, displayLabel , description)
                sorted_resource_groups.append(resource_groups)

            # Sort list by second item (RG name)
            for item in sorted(sorted_resource_groups, key=lambda x: x[1]):
                print ('\',\''.join(map(str, item) ) + "\'")

    @staticmethod
    def make_rg_get_request(ipm_type,session_type,rg_id,subscription,region,username,password):
        """ Executes GET request to the Resource Groups API."""

        if (ipm_type == "cloud"):
            href = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com'
            if (rg_id == "Null"):
                url = href + '/1.0/topology/mgmt_artifacts/'
            else:
                url = href + '/1.0/topology/mgmt_artifacts/' + rg_id + '/references/to/contains'
            headers, querystring = set_querystring(href,session_type)
            r = requests.get(url, params=querystring , headers=headers, auth=(username,password), timeout=60)
            return r
        elif (ipm_type == "private"):
            href = 'https://' + subscription
            if (rg_id == "Null"):
                url = href + '/1.0/topology/mgmt_artifacts/'
            else:
                url = href + '/1.0/topology/mgmt_artifacts/' + rg_id + '/references/to/contains'
            headers, querystring = set_querystring(href,session_type)
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            r = requests.get(url, params=querystring , headers=headers, auth=(username,password), timeout=60, verify=False)
            return r
        else:
            print ("ERROR - Could not determine IPM subscription type. Exiting!")
            sys.exit(1)

    @staticmethod
    def make_rg_put_request(ipm_type,session_type,rg_identification,rg_description,subscription,region,username,password):
        """ Executes POST request to the Resource Groups API."""

        if (ipm_type == "cloud"):
            href = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com'
            url = href + '/1.0/topology/mgmt_artifacts'
            headers, payload = set_payload(href,session_type,rg_identification,rg_description)
            r = requests.post(url, json=payload, headers=headers, auth=(username,password), timeout=60)
            return r
        elif (ipm_type == "private"):
            href = 'https://' + subscription
            url = href + '/1.0/topology/mgmt_artifacts'
            headers, payload = set_payload(href,session_type,rg_identification,rg_description)
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            r = requests.post(url, json=payload, headers=headers, auth=(username,password), timeout=60, verify=False)
            return r
        else:
            print ("ERROR - Could not determine IPM subscription type. Exiting!")
            sys.exit(1)

    @staticmethod
    def make_rg_del_request(ipm_type,session_type,rg_identification,subscription,region,encoded_credentials):
        """ Executes DEL request to the Resource Groups API."""

        if (ipm_type == "cloud"):
            href = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com'
            url = href + '/1.0/topology/mgmt_artifacts'
            headers = set_headers_for_post_deletion(href,session_type,rg_identification,encoded_credentials)
            url = url + "/" + rg_identification
            r = requests.request("DELETE", url, headers=headers, timeout=60)
            return r

        elif (ipm_type == "private"):
            href = 'https://' + subscription
            url = href + '/1.0/topology/mgmt_artifacts'
            headers = set_headers_for_post_deletion(href,session_type,rg_identification,encoded_credentials)

            url = url + "/" + rg_identification
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            r = requests.request("DELETE", url, headers=headers, verify=False, timeout=60)
            return r
        else:
            print ("ERROR - Could not determine IPM subscription type. Exiting!")
            sys.exit(1)

    @staticmethod
    def add_rg(arguments):
        """Creates a new Resource Group based on user's input."""

        session_type = "add_rg"

        # If function is being called from login, there will be no values assigned to vars so, we must first give it a try to avoid errors
        try:
            subscription, region, alias, username, password, ipm_type = Subscription.validate_session(session_type)
        except TypeError:
            sys.exit (0)

        # Check the arguments and make sure RG id is informed
        if ((len(arguments)) != 5):
            usage()
        else:
            rg_identification = sys.argv[3]
            rg_description = sys.argv[4]
            r = ResourceGroups.make_rg_put_request(ipm_type,session_type,rg_identification,rg_description,subscription,region,username,password)

            if (r.status_code == 201):
                print ("SUCCESS - Resource Group '%s' was successfully created." %(rg_identification))
            else:
                print ("ERROR - Script failed with 'HTTP Status code %s' when trying to create resource group '%s'." %(r.status_code, rg_identification))

    @staticmethod
    def del_rg(arguments):
        """Deletes a new Resource Group based on user's input."""

        session_type = "del_rg"

        # If function is being called from login, there will be no values assigned to vars so, we must first give it a try to avoid errors
        try:
            subscription, region, alias, username, password, ipm_type = Subscription.validate_session(session_type)
        except TypeError:
            sys.exit (0)

        # Check the arguments and make sure RG id is informed
        if ((len(arguments)) != 4):
            usage()
        else:
            rg_identification = sys.argv[3]
            encoded_credentials = base64.b64encode(("%s:%s" % (username, password)).encode()).decode()
            r = ResourceGroups.make_rg_del_request(ipm_type,session_type,rg_identification,subscription,region,encoded_credentials)

            if (r.status_code == 204):
                print ("SUCCESS - Resource Group '%s' was successfully removed." %(rg_identification))
            else:
                print ("ERROR - Script failed with 'HTTP Status code %s' when trying to delete this resource group '%s'." %(r.status_code, rg_identification))

#-----------------------------------------------------------------------------------------------------------


def usage():
    """Usage instructions, will be shown to user every time a wrong syntax happens."""

    print ("""
You did not specify a valid command or failed to pass the proper options. Exiting!

Usage:
---------------------------------------------------------------------------------------------------------
ipm login                                 : Perform login on your IPM subscription
ipm logout                                : Logout from the current IPM subscription

ipm get <object> / <object_id>
    get agt                               : List all existing agents on the subscription.
    get thr                               : List of all available thresholds.
    get thr <thr_name>                    : Displays a single threshold in JSON format.
    get thr -f  <threshold_list>          : Displays multiple thresholds from a list in JSON format.
    get thr -rg <rg_id>                   : Displays all the thresholds assigned to this Resource Group.
    get rg                                : List of all available Resource Groups.
    get rg <rg_id>                        : List of all Managed Systems assigned to this Resource Group.

ipm add <object> <object_id>
    add rg  <rg_id> "<rg_description>"    : Creates a Resource Group
    add agt <agt_name> <rg_id>            : Adds an agent to a Resource Group
    add thr <threshold_json_file>         : Creates a threshold from an IPM8 JSON export file
    add thr <threshold_name> -rg <rg_id>  : Adds a threshold to a Resource Group.

ipm del <object> <object_id>
    del thr <threshold_name>              : Deletes a threshold by name
    del rg  <resourcegroup_id>            : Deletes a Resource Group by Id
    del agt <agt_name> <rg_id>            : Removes an agent from a Resource Group
    del thr <threshold_name> -rg <rg_id>  : Removes a threshold to a Resource Group (*)

---------------------------------------------------------------------------------------------------------
    """)
    sys.exit(1)

def get_arg(argv):
    """Get the arguments from stdin and store them in a list or redirect them to other functions."""
    arguments = []
    if len (argv) == 1:
        usage()

    if (argv[1] == "login"):
        session_type = 'login'
        Subscription.validate_session(session_type)

        sys.exit(0)
    elif (argv[1] == "logout"):
        Subscription.logout()
        sys.exit(0)
    if len (argv) >= 3:
        for v in argv:
            arguments.append(v)
    else:
        usage()
    return arguments

def set_headers_for_post_deletion(href,session_type,rg_identification,encoded_credentials):
    """ Define headers content for POST/DEL request to the Resource Groups API."""

    if (session_type == 'del_rg' or session_type == 'add_agents'):
        rg_uuid = str(uuid.uuid4())
        headers = {
        'Referer' : '%s' % href,
        'Authorization' : 'Basic %s' % encoded_credentials,
        'entityTypes' : 'AgentGroup',
        'content-type': 'application/json',
        'accept': 'application/json',
        'cache-control': 'no-cache',
        'IPMSessionUUID' : '%s' % rg_uuid
        }
        return headers
    else:
        print ("ERROR - Could not determine session origin. Exiting!")
        sys.exit(1)

def set_querystring(href,session_type):
    """Set the headers and API query string based on the type of session and/or method."""

    headers = {
    'content-type': "application/json",
    'accept': "application/json",
    'Referer': href
    }

    if (session_type == 'get_agents' or session_type == 'agts_from_resource_group'):
        entityTpe = "Agent"
    elif (session_type == 'get_resource_group'):
        entityTpe = "AgentGroup"

    querystring = {"_filter":"entityTypes=" + entityTpe, "_field":["hostname",\
                "keyIndexName",\
                "displayLabel", \
                "parentNode", \
                "OSPlatformDescription", \
                "description", \
                "online", \
                "version", \
                "productCode"]}

    return headers, querystring

def set_payload(href,session_type,rg_identification, rg_description):
    """Set the headers and Paylod based on the type of session and/or method to be sent to the Resource Groups API."""

    rg_uuid = str(uuid.uuid4())
    headers = {
    'content-type': "application/json",
    'accept': "application/json",
    'Referer': href
    }

    if (session_type == 'add_rg'):
        entityTpe = ["AgentGroup"]
        payload = {"entityTypes" : entityTpe, \
                    "arbitraryStringProperty" : "RG created by IPM-CLI",\
                    "displayLabel" : rg_identification,\
                    "description" : rg_description,\
                    "keyIndexName" : rg_uuid}
        return headers, payload
    else:
        print ("ERROR - Could not determine session origin. Exiting!")
        sys.exit(1)

def checks_out_on_error(ipm_config):
    if os.path.exists(ipm_config) == True:
        os.remove(ipm_config)
    sys.exit (1)

def main():
    """Main function, will get arguments from user through 'get_arg' function and redirect according to what the user wants to accomplish."""
    try:
        arguments = get_arg(sys.argv)

        # GET ACTIONS
        if arguments[1] == "get":
            cmd = arguments[2]
            if (cmd == 'agents' or cmd == 'agent' or cmd == 'agt' or cmd == 'agts'):
                Agents.get_agents(arguments)
            elif (cmd == 'thresholds' or cmd == 'threshold' or cmd == 'thres' or cmd == 'thr' or cmd == 'thrs'):
                Thresholds.get_thresholds()
            elif (cmd == 'resourcegroup' or cmd == 'resourcegroups' or cmd == 'rg'):
                ResourceGroups.get_resource_groups()
            else:
                usage()

        # ADD ACTIONS
        elif arguments[1] == "add":
            cmd = arguments[2]
            if (cmd == "rg"):
                ResourceGroups.add_rg(arguments)
            elif (cmd == "agt"):
                Agents.add_del_agt(arguments)
            elif (cmd == "thr"):
                Thresholds.add_threshold(arguments)

        # DEL ACTIONS
        elif arguments[1] == "del":
            cmd = arguments[2]
            if (cmd == "rg"):
                ResourceGroups.del_rg(arguments)
            elif (cmd == "agt"):
                Agents.add_del_agt(arguments)
            elif (cmd == "thr"):
                Thresholds.del_threshold(arguments)
    except KeyboardInterrupt:
        sys.exit(1)

#-----------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    main()

# --------------------------------------------------------------------------------
# END OF SCRIPT
# --------------------------------------------------------------------------------

