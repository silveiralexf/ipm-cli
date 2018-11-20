# ipm-cli

IPM-CLI script is a simple API client built in Python3 intended to assist interacting with IBM Performance Management (IPM) Rest API. 

The idea is that users may interact with IPM from the command line for simple operations, to perform actions in bulk or even to create simple automations for the day to day tasks that are not possible through the IPM Dashboard.

## Download

|Release             |Binaries                                                                                                     |Source Code                                                                         |
|--------------------|-------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|
|v0.2.0 (Nov-18-2018)|[ipm-cli_v0.2.0 Binaries](https://github.com/fsilveir/ipm-cli/releases/download/v0.2.0/ipm-cli_v0.2.0.tar.gz)|[ipm-cli_v0.2.0 Source Code](https://github.com/fsilveir/ipm-cli/archive/v0.2.0.zip)|
|v0.1.0 (Nov-06-2018)|[ipm-cli_v0.1.0 Binaries](https://github.com/fsilveir/ipm-cli/releases/download/v0.1.0/ipm-cli_v0.1.0.tar.gz)|[ipm-cli_v0.1.0 Source Code](https://github.com/fsilveir/ipm-cli/archive/v0.1.0.zip)|

## Functionality

 *  List of monitoring agents by status, version and type.
 *  List and details of monitored thresholds
 *  Export threshold contents to JSON format 
 *  List of Resource Groups
 *  List the Monitored Agents that are part of a Resource Group
 *  Add or Remove one or more agents to a Resource Group
 *  Add or Delete a Resource Group

## Key Features

 *  You can login and logout on different IPM subscriptions and the script will store an encrypted password for your session without the need of multiple logins each time you communicate with the API.
 *  You encrypted password is unique and cannot be used by other users.
 *  You can store the information of multiple subscriptions so that you can pick and choose the subscriptions you'll log to through a quick-menu.
 *  The compiled version of the script allows you to use the script regardless of having Python3 and its required modules installed.
 *  Open-souce, free to use, modify and distribute as you see fit. (don't forget to give some feedback too!)

## Key Benefits

This script is intended to assist IPM administrators and users to easily interact with its API from the command line. The main benefit is not having to manually handle the API's response and to memorize the different API calls and paths. The script provides an easy to read help funcion and does all the rest for you.

## Install Instructions

There are 2 different ways of using the script, from source and from the compiled version.

### To use the script from source:

Be sure you meet the following requirements:

 *  Python3.x
 *  Python Requests Module (requests==2.19.1)

 If the requirements are properly installed, you can execute the script directly from the command line as shown below: 

```bash
$ chmod 755 ipm.py
$ ./ipm.py
```

### To use the script compiled version:

In case you don't have Python3 and the required requests module installed, you can also use the compiled version from the [latest release](https://github.com/fsilveir/ipm-cli/releases). With the compiled version you can execute the script on any Linux-64 server even without Python3 installed or with a different Python versions installed, since the package include all the required dependencies.

Just extract the package to your local machine, for instance under`/opt/ibm/ipm-cli`, and create a symbolic link to `/usr/bin/ipm` so you can execute the script directly from any path, as shown below:

```bash
$ tar xvfz ipm-cli_v0.1.0.tar.gz
$ mkdir -p /opt/ibm/ipm-cli
$ cp -R ipm-cli/ /opt/ibm/ipm-cli
$ sudo ln -s /opt/ibm/ipm-cli/ipm /usr/bin/ipm
$ sudo chmod 755 /usr/bin/ipm
$ ipm
```

## Usage Instructions

The following functions are available:

```shell
ipm login                               : Perform login on your IPM subscription
ipm logout                              : Logout from the current IPM subscription
ipm setaccount                          : Creates quick login profile with your IPM accounts (*)

ipm get <object> / <object_id>
    get agt                             : List all existing agents on the subscription.
    get thr                             : List of all available thresholds.
    get thr <thr_name>                  : Displays a single threshold in JSON format.
    get thr -f <threshold_list>         : Displays multiple thresholds from a list in JSON format.
    get rg                              : List of all available Resource Groups.
    get rg <rg_id>                      : List of all Managed Systems assigned to this Resource Group.

ipm add <object> <object_id>
    add rg  <rg_id> "<rg_description>"  : Creates a Resource Group
    add agt <agt_name> <rg_id>          : Adds an agent to a Resource Group

ipm del <object> <object_id>
    del thr <threshold_id>              : Deletes a threshold (*)
    del rg  <resourcegroup_id>          : Deletes a Resource Group
    del agt <agt_name> <rg_id>          : Removes an agent from a Resource Group

(*) All marked items are still pending implementation
---------------------------------------------------------------------------------------------------------
```

## Setting-up a quick-login menu

To assist logging on the most common IPM subscription, you can use a configuration file with the subscription information and an alias to which your account will be referred as. The file should use JSON format with the following structure:

```json
[
  {
    "id": "1",
    "alias": "saas-account",
    "type": "cloud",
    "subscription": "fea2ea0f40c71c59d11c5a49d9269d0e",
    "region": "na"
  },
  {
     "id": "2",
     "alias": "private-account",
     "type": "private",
     "subscription": "192.198.254.1:8091",
     "region": "eu"
   }
]
```

The file should be named stored at `~/.ipmaccounts` at home directory of the user executing the script. If your file was correctly set-up you should see a similar menu when trying to perform `ipm login`:

```shell
$ ipm login
You're not authenticated, please proceed with authentication.
1  - IPM Account: saas-account       Subscription: fea2ea0f40c71c59d11c5a49d9269d0e    Region: na
2  - IPM Account: private-account    Subscription: 192.168.254.1:8091                  Region: eu

Choose the number of the subscription you want to login, or type the subscription 
(ex. fea2ea0f40c71c59d11c5a49d9269d0e / 192.168.254.1:8091 ):
```

## Compile from Source

In order to create a new distrubution package from the source, execute the following:

```shell
$ pip install nuitka
$ python -m nuitka --follow-imports --standalone ipm.py
```

## Get support

Create an [issue](https://github.com/fsilveir/ipm-cli/issues) if you want to report a problem or ask for a new functionality, any feedback is highly appreciated!