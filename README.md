# ipm-cli

This script is intended to assist interacting with IBM Performance Management (IPM) Rest API.

#### Download Here

- [ipm-cli](https://github.com/fsilveir/ipm-cli/releases)


#### Requirements

- Python3.x
- Python Requests Module (requests==2.19.1)

#### Install Instructions

There are 2 ways of using this script, first requires Python3 (with requests module installed). To do that, execute the script directly from the command line as shown below: 

```bash
$ chmod 755 ipm.py
$ ./ipm.py
```

In case you don't have Python3 and the required requests module installed, you can also use the compiled version included in this repository under `ipm-cli` directory. With the compiled version you can execute the script on any Linux-64 server even without Python3 installed or with different Python versions installed, since the package include all the required dependencies.

Just copy the `ipm-cli` directory to `/opt/ibm/ipm-cli` and create a symbolic link to `/usr/bin/ipm` so you can execute the script directly from any path.

```bash
$ sudo cp -R ipm-cli/ /opt/ibm/ipm-cli
$ sudo ln -s /opt/ibm/ipm-cli/ipm /usr/bin/ipm
$ /usr/bin/ipm
```

#### Usage Instructions

The following functions are available:

```
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
    add agt <agt_name> <rg_id>          : Adds an agent to a Resource Group

ipm del <object> <object_id>
    del thr <threshold_id>              : Deletes a threshold (*)
    del rg  <resourcegroup_id>          : Deletes a Resource Group
    del agt <agt_name> <rg_id>          : Removes an agent from a Resource Group

(*) All marked items are still pending implementation
---------------------------------------------------------------------------------------------------------

```

##### Setting-up a quick-login menu

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

```bash
$ ipm login
You're not authenticated, please proceed with authentication.
1  - IPM Account: saas-account       Subscription: fea2ea0f40c71c59d11c5a49d9269d0e    Region: na
2  - IPM Account: private-account    Subscription: 192.168.254.1:8091                  Region: eu

Choose the number of the subscription you want to login, or type the subscription 
(ex. fea2ea0f40c71c59d11c5a49d9269d0e / 192.168.254.1:8091 ):
```

##### Compile from Source

In order to create a new distrubution package from the source, execute the following:

```
$ pip install nuitka
$ python -m nuitka --follow-imports --standalone ipm.py
```


