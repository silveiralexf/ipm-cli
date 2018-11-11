#!/bin/env python


# from pprint import pprint
import os, sys, json, hashlib, base64, getpass, requests, socket, time,uuid
#from urllib3.exceptions import InsecureRequestWarning

# ------------------------------------------------------------------------------------------------------------

def usage():
    """Usage instructions, will be shown to user every time a wrong syntax happens."""
    print ("""
You did not specify a valid command or failed to pass the proper options. Exiting!

Usage:
---------------------------------------------------------------------------------------------------------
ipm login                               : Perform login on your IPM subscription
ipm logout                              : Logout from the current IPM subscription
ipm setaccount                          : Creates quick login profile with your IPM accounts (*)

ipm get <object> / <object_id>
    get agt                             : List all existing agents on the subscription.
    get thr                             : List of all available thresholds.
    get thr <thr_name>                  : Export a single threshold to json format.
    get thr -f <threshold_list>         : Export a list of thresholds to json format. (*)
    get rg                              : List of all available Resource Groups.
    get rg <rg_id>                      : List of all Managed Systems assigned to this Resource Group.

ipm add <object> <object_id>
    add rg  <rg_id> "<rg_description>"  : Creates a Resource Group

ipm del <object> <object_id>
    del thr <threshold_id>              : Deletes a threshold (*)
    del rg  <resourcegroup_id>          : Deletes a Resource Group

(*) All marked items are still pending implementation
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
        check_login(session_type)
        sys.exit(0)
    elif (argv[1] == "logout"):
        logout()
        sys.exit(0)
    if len (argv) >= 3:
        for v in argv:
            arguments.append(v)
    else:
        usage()
    return arguments

def logout():
    """Logs out from the IPM subscription and removes the cached secret."""
    ipm_config = os.path.expanduser("~/.ipmconfig")
    if os.path.exists(ipm_config) == True:
        os.remove(ipm_config)
    print ("You have successfully logged out.")

def get_token():
    """Generates unique token based network info to be used as part of the password hash/secret."""
    hostname = socket.gethostname()
    token = socket.getaddrinfo(hostname, 0)
    token = (str(token))
    token = base64.b64encode(token.encode('utf-8'))
    return token

def make_pw_hash(password):
    """Creates sha256 hash to encrypt the credentials. This function should be called by other login functions."""
    return hashlib.sha256(str.encode(password)).hexdigest()

def check_login(session_type):
    """Check if user is currently logged on an IPM subscription, and if token is still valid."""
    ipm_config = os.path.expanduser("~/.ipmconfig")
    if os.path.exists(ipm_config) == True:
        ipm_config_age = os.path.getatime(ipm_config)
        half_hour = time.time() - 120 * 60
        
        ## DEBUG --> Uncomment values below for converting from epoch to human readable time
        # file_age = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ipm_config_age))
        # file_age_limit = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(half_hour))

        if ipm_config_age < half_hour:
            #print ("DEBUG --> KEY IS OLDER THAN 60 MINUTES - FILE_AGE", file_age, "AGE_LIMIT", file_age_limit )
            os.remove(ipm_config)

    try:
        with open(ipm_config, "r") as f:
            revelations = []
            revelation = f.read().strip()
            token = get_token()
            revelation = revelation.replace(str(token),'')
            revelation = str(revelation[66:][:-1])

            for item in base64.b64decode(revelation).decode().split(","):
                revelations.append(item)

            subscription = revelations[0]
            region = revelations[1]
            alias = revelations[2]
            username = revelations[3]
            password = revelations[4]

            if session_type == 'login':
                print ("Your're already logged to IPM Subscription: '%s' (%s.%s) as user: '%s' \n" %(alias, subscription, region, username))
                relogin = input("Press 'R' to relogin or enter any other key to proceed with the same credentials: ").lower()
                if (relogin == 'R'.lower()):
                    print ('\n')
                    login()
                else:
                    check_connection(subscription, region, alias, username, password)
                    return subscription, region, alias, username, password

            return subscription,region,alias,username,password
    except:
        print ("You're not authenticated, please proceed with authentication.")
        login()
# --------------------------------------------------------------------------

def check_connection(subscription,region,alias,username,password):
    """Check if the provided crendials are valid to authenticate on IPM API."""

    queystring = '1.0/topology/mgmt_artifacts'
    url = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com/' + queystring
    ipm_config = os.path.expanduser("~/.ipmconfig")

    res = requests.get(url, auth=(username, password))

    if (res.status_code == 200):
        text = b"Your subscription has expired and is now suspended from the <b>IBM Performance Management (SaaS) service"
        if (text in res.content):
            print ("Your subscription has expired and is now suspended from the IBM Performance Management (SaaS) service\n\n")
            login()
        return subscription, region, alias, username, password
    else:
        print ("ERROR: Failed to login with the credentials provided. Please try again:\n")
        login()


def login():
    """Main login function, interactively asks for IPM subscription information and credentials."""
    try:
        ipm_accounts = os.path.expanduser("~/.ipmaccounts")
        ipm_config = os.path.expanduser("~/.ipmconfig")

        with open(ipm_accounts, "r") as f:
            data = json.load(f)
            data_choice = []
            n = 0
            table = []
            for _ in data:
                id_num = str(data[n]["id"])
                alias = str(data[n]["alias"])
                subscription = str(data[n]["subscription"])
                region = str(data[n]["region"])                
                print ("{0:<2} - IPM Account: {1:<14} Subscription: {2:>32}    Region: {3:>2}".format(id_num,alias,subscription,region))
                n += 1
            choice = input("\nChoose the number of the subscription you want to login, or type the subscription (ex. fea2ea0f40c71c59d11c5a49d9269d0e):")

            n = 0
            for _ in data:
                id_num = str(data[n]["id"])
                if choice == id_num:
                    alias = str(data[n]["alias"])
                    subscription = str(data[n]["subscription"])
                    region = str(data[n]["region"])
                    data_choice = (id_num, alias, subscription, region)
                n += 1
            if not data_choice:
                subscription = choice
                region = input('Type the region of your IPM subscription (eu, na, ap): ')
                alias = input('Type an alias for your IPM subscription (ex. trial-na, sla-eu): ')
            else:
                alias = data_choice[1]
                subscription = data_choice[2]
                region = data_choice[3]
    except KeyboardInterrupt:
        sys.exit (0)
    except os.error:
        subscription  = input("\nNo subscription was found on '%s', type your IPM subscription number (ex. fea2ea0f40c71c59d11c5a49d9269d0e): " % ipm_accounts)
        region = input('Type the region of your IPM subscription (eu, na, ap): ')
        alias = input('Type an alias for your IPM subscription (ex. trial-na, sla-eu): ')
        pass

    username = input('Type your IPM username (ex.: fsilveir@br.ibm.com): ')
    password = getpass.getpass('Type your password: ')
    credentials = (subscription + "," + region + "," + alias + "," + username + "," + password)

    token = get_token()

    encoded_credentials = base64.b64encode(credentials.encode('utf-8'))
    secret = (str(token) + make_pw_hash(str(encoded_credentials)) + str(token) + str(encoded_credentials) + str(token))

    if check_connection(subscription,region,alias,username,password):
        with open(ipm_config, "w") as f:
            f.write(secret)
            print ("SUCCESS: You're logged on '%s.%s' (%s) as user '%s' " % (alias, region, subscription, username))
    else:
        print ("ERROR: Failed to login with the credentials provided. Please try again:\n")
        sys.exit (1)
    
    return subscription, region, alias, username, password

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
    """Set the headers and API query string based on the type of session and/or method."""
    
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
        print ("ERROR: Could not determine session origin. Exiting!")
        sys.exit(1)

def set_headers_for_rg_deletion(href,session_type,rg_identification,encoded_credentials):
    if (session_type == 'del_rg'):    
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
        print ("ERROR: Could not determine session origin. Exiting!")
        sys.exit(1)

def get_agents(arguments):
    """Get the list of monitored agents from API and display it on the screen."""

    session_type = 'get_agents'

    # If function is being called from login, there will be no values assigned to vars so, we must first give it a try
    try:
        subscription, region, alias, username, password = check_login(session_type)
    except:
        sys.exit (1)

    href = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com'
    #href = subscription + '.customers.' + region + '.apm.ibmserviceengage.com'
    url = href + '/1.0/topology/mgmt_artifacts'
    headers, querystring = set_querystring(href,session_type)
    
    r = requests.get(url, params=querystring , headers=headers, auth=(username,password))
        
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
                #hostname = json_agt_dict['_items'][n]['hostname']
                product_code =  json_agt_dict['_items'][n]['productCode']
                description =  json_agt_dict['_items'][n]['description']
                version =  json_agt_dict['_items'][n]['version']
                status =  json_agt_dict['_items'][n]['online']
            except KeyError:
                #hostname = "unknown"
                product_code = "unknown"
                description = "unknown"
                version = "unknown"
                status = "N"

            for num in range(3, num_arguments):
                if arguments[num].lower() in agt_name.lower():
                    #print ('\'' + agt_name + '\'' + "," + \
                    agents.append('\'' + agt_name + '\'' + "," + \
                        #'\'' + hostname + '\'' + "," + \
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
            #hostname = json_agt_dict['_items'][n]['hostname']
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
            pass
        n += 1
        #print ('\'' + agt_name + '\'' + "," + \
        agents.append('\'' + agt_name + '\'' + "," + \
                #'\'' + hostname + '\'' + "," + \
                '\'' + product_code + '\'' + "," + \
                '\'' + description + '\'' + "," + \
                '\'' + version + '\'' + "," + \
                '\'' + status + '\'' )

    for line in (sorted(agents)):
        print (line)
    sys.exit(0)

def get_thresholds():
    """Get the list of thresholds from API and display it on the screen."""

    session_type = 'get_thresholds'
    
    # If function is being called from login, there will be no values assigned to vars so, we must first give it a try
    try:
        subscription, region, alias, username, password = check_login(session_type)
    except:
        sys.exit (1)

    arguments = get_arg(sys.argv)
    if (len(arguments) == 3):
        print ("""
You did not specify a valid command or failed to pass the proper options. Exiting!
Usage:
        ----------------------------------------------------------------------------------------------------
        ./ipm.py get thr <all / product code / thr_name>
        ----------------------------------------------------------------------------------------------------
        get thr all                     : List all existing thresholds in the subscription.
        get thr <product_code>          : List all thresholds of a particular product code (ex: lz, nt, etc)
        get thr <thr_name>              : Displays threshold on json format.
        get thr -f <threshold_list>     : Export a list of thresholds to json format. (*)
""")
        sys.exit(0)

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
            # prints a single threshold that was informed
            threshold_name = arguments[3]
            payload = '1.0/thresholdmgmt/threshold_types/itm_private_situation/thresholds/?_filter=label%3D' + threshold_name
            url = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com/' + payload
            res = requests.get(url, auth=(username, password))
            if (res.status_code == 200):
                json_thr_dict = json.loads(res.content)
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
                    print ("ERROR: Threshold '%s' was not found." % threshold_name)
                    sys.exit(1)

                sys.exit(0)
            else:
                print ("Failed to extract information. Script is aborting! ")
                sys.exit(1)

    # Display thresholds by type
    print ("'threshold_name','product_code','threshold_type','description'")
    for thr_type in thr_type_list:
        payload = '1.0/thresholdmgmt/threshold_types/itm_private_situation/thresholds?_filter=_uiThresholdType%3D' + thr_type + '&_offset=1&_limit=99999'
        url = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com/' + payload
        res = requests.get(url, auth=(username, password))

        # Avoids errors in case user is asking for 'all' thresholds
        if (res.status_code == 200):
            json_thr_dict = json.loads(res.content)
        else:
            continue

        counter = 0
        thresholds = []
        for _ in json_thr_dict['_items']:
            try:
                product_code = '\'' +  json_thr_dict['_items'][counter]['_appliesToAgentType'] + '\''
                label = '\'' + json_thr_dict['_items'][counter]['label'] + '\''
                description = '\'' + json_thr_dict['_items'][counter]['description'] + '\''
                threshold_type = '\'' + json_thr_dict['_items'][counter]['_uiThresholdType'] + '\''
            except KeyError:
                pass
            counter +=1
            thresholds.append(label + "," + product_code + "," + threshold_type + "," + description)

        for item in (sorted(thresholds)):
            print (item)

def get_resource_groups():
    """Get the list of resource groups from API and display it on the screen."""

    session_type = 'agts_from_resource_group'

    # If function is being called from login, there will be no values assigned to vars so, we must first give it a try
    try:
        subscription, region, alias, username, password = check_login(session_type)
    except:
        sys.exit (1)

    subscription, region, alias, username, password = check_login(session_type)
    arguments = get_arg(sys.argv)

    # Get list of agents assigned to a single resource group
    if (len(arguments) > 3):
        rg_id = arguments[3]
        
        href = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com'
        url = href + '/1.0/topology/mgmt_artifacts/' + rg_id + '/references/to/contains'
        headers, querystring = set_querystring(href,session_type)

        r = requests.get(url, params=querystring , headers=headers, auth=(username,password))

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
                pass
            n += 1
            #print (agt_name + "," + pc + "," + version + "," + status)
            agents.append(agt_name + "," + pc + "," + version + "," + status)

        for item in (sorted(agents)):
            print (item)

    else:
        session_type = 'get_resource_group'

        # If function is being called from login, there will be no values assigned to vars so, we must first give it a try
        try:
            subscription, region, alias, username, password = check_login(session_type)
        except:
            sys.exit (1)

        href = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com'
        url = href + '/1.0/topology/mgmt_artifacts/'
        headers, querystring = set_querystring(href,session_type)
        r = requests.get(url, params=querystring , headers=headers, auth=(username,password))

        json_rg_dict = json.loads(r.content)

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
                pass
            n += 1
            
            resource_groups = ("\'" + rg_id, displayLabel , description)
            sorted_resource_groups.append(resource_groups)
        
        # Sort list by second item (RG name)
        for item in sorted(sorted_resource_groups, key=lambda x: x[1]):
            print ('\',\''.join(map(str, item) ) + "\'")


# --------------------------------------------------------------------------------

def add_rg(arguments):
    """Creates a new Resource Group based on user's input."""
    
    session_type = "add_rg"
    
    # If function is being called from login, there will be no values assigned to vars so, we must first give it a try to avoid errors
    try:
        subscription, region, alias, username, password = check_login(session_type)
    except:
        sys.exit (1)
    
    # Check the arguments and make sure RG id is informed
    if ((len(arguments)) != 5):
        usage()
    else:
        rg_identification = sys.argv[3]
        rg_description = sys.argv[4]

        href = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com'
        url = href + '/1.0/topology/mgmt_artifacts'
        headers, payload = set_payload(href,session_type,rg_identification,rg_description)
        r = requests.post(url, json=payload, headers=headers, auth=(username,password))

        if (r.status_code == 201):
            print ("SUCCESS: '%s' was successfully created. \n\nNotice that it may take a few seconds before the group starts to show-up.\n" %(rg_identification))
        else:
            print ("ERROR: Script failed with 'HTTP Status code %s' when trying to create resource group '%s'." %(r.status_code, rg_identification))
        
def del_rg(arguments):
    """Deletes a new Resource Group based on user's input."""

    session_type = "del_rg"

    # If function is being called from login, there will be no values assigned to vars so, we must first give it a try to avoid errors
    try:
        subscription, region, alias, username, password = check_login(session_type)
    except:
        sys.exit (1)
    
    # Check the arguments and make sure RG id is informed
    if ((len(arguments)) != 4):
        usage()
    else:
        rg_identification = sys.argv[3]

        href = 'https://' + subscription + '.customers.' + region + '.apm.ibmserviceengage.com'
        url = href + '/1.0/topology/mgmt_artifacts'

        encoded_credentials = base64.b64encode(("%s:%s" % (username, password)).encode()).decode()
        headers = set_headers_for_rg_deletion(href,session_type,rg_identification,encoded_credentials)

        url = url + "/" + rg_identification
        r = requests.request("DELETE", url, headers=headers)
        
        if (r.status_code == 204):
            print ("SUCCESS: '%s' was successfully removed. \n\nNotice that it may take a few seconds before the group disappears.\n" %(rg_identification))
        else:
            print ("ERROR: Script failed with 'HTTP Status code %s' when trying to delete this resource group '%s'." %(r.status_code, rg_identification))               

def main():
    """Main function, will get arguments from user through 'get_arg' function and redirect accordingly to what he wants to accomplish."""
    try:
        arguments = get_arg(sys.argv)
        if arguments[1] == "get":
            cmd = arguments[2]
            if (cmd == 'agents' or cmd == 'agent' or cmd == 'agt' or cmd == 'agts'):
                get_agents(arguments)
            elif (cmd == 'thresholds' or cmd == 'threshold' or cmd == 'thres' or cmd == 'thr' or cmd == 'thrs'):
                get_thresholds()
            elif (cmd == 'resourcegroup' or cmd == 'resourcegroups' or cmd == 'rg'):
                get_resource_groups()
            else:
                usage()
        elif arguments[1] == "add":
            cmd = arguments[2]
            add_rg(arguments)
        elif arguments[1] == "del":
            cmd = arguments[2]
            del_rg(arguments)
    except KeyboardInterrupt:
        sys.exit(1)

# --------------------------------------------------------------------------------

if __name__ == '__main__':
    main()

# --------------------------------------------------------------------------------
# END OF SCRIPT
# --------------------------------------------------------------------------------