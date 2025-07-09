"""
Azure-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

import re
import requests
from enum_tools import utils
from enum_tools import azure_regions

BANNER = '''
++++++++++++++++++++++++++
       azure checks
++++++++++++++++++++++++++
'''

# Known Azure domain names
BLOB_URL = 'blob.core.windows.net'
FILE_URL= 'file.core.windows.net'
QUEUE_URL = 'queue.core.windows.net'
TABLE_URL = 'table.core.windows.net'
MGMT_URL = 'scm.azurewebsites.net'
VAULT_URL = 'vault.azure.net'
WEBAPP_URL = 'azurewebsites.net'
DATABASE_URL = 'database.windows.net'
COGNITIVE_URL = 'api.cognitive.microsoft.com'
AAD_URL = 'microsoftonline.com'
SERVICEBUS_URL = 'servicebus.windows.net'
API_MGMT_URL = 'azure-api.net'
AKS_URL = 'azurecontainer.io'
MONITOR_URL = 'monitor.azure.com'
LOGIC_APPS_URL = 'logic.azure.com'
REDIS_URL = 'redis.cache.windows.net'

# Additional Azure domain names
ACR_URL = 'azurecr.io'
VNET_URL = 'virtualnetwork.azure.com'
CDN_URL = 'azureedge.net'
EVENTGRID_URL = 'eventgrid.azure.net'
DATALAKE_URL = 'dfs.core.windows.net'
EXPRESSROUTE_URL = 'expressroute.trafficmanager.net'
VIRTUALDESKTOP_URL = 'wvd.microsoft.com'
SEARCH_URL = 'search.windows.net'
STREAMANALYTICS_URL = 'streamanalytics.azure.com'
IOT_URL = 'azure-devices.net'

# Virtual machine DNS names are actually:
#   {whatever}.{region}.cloudapp.azure.com
VM_URL = 'cloudapp.azure.com'


def print_account_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404 or 'The requested URI does not represent' in reply.reason:
        pass
    elif 'Server failed to authenticate the request' in reply.reason:
        data['msg'] = 'Auth-Only Account'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif 'The specified account is disabled' in reply.reason:
        data['msg'] = 'Disabled Account'
        data['target'] = reply.url
        data['access'] = 'disabled'
        utils.fmt_output(data)
    elif 'Value for one of the query' in reply.reason:
        data['msg'] = 'HTTP-OK Account'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif 'The account being accessed' in reply.reason:
        data['msg'] = 'HTTPS-Only Account'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif 'Unauthorized' in reply.reason:
        data['msg'] = 'Unathorized Account'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    else:
        print("    Unknown status codes being received from " + reply.url +":\n"
              "       "+ str(reply.status_code)+" : "+ reply.reason)

def check_storage_accounts(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks storage account names
    """
    print("[+] Checking for Azure Storage Accounts")
    
    if verbose:
        print(f"[*] Storage Accounts use format: accountname.{BLOB_URL}")
        print(f"[*] Real example: mycompany-storage.{BLOB_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTP validation")
        print(f"[*] DNS resolution = Account exists, then HTTP test for access level")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    # As Azure Storage Accounts can contain only letters and numbers,
    # discard those not matching to save time on the DNS lookups.
    regex = re.compile('[^a-zA-Z0-9]')
    for name in names:
        if not re.search(regex, name):
            candidates.append(f'{name}.{BLOB_URL}')

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(valid_names, use_ssl=False,
                        callback=print_account_response,
                        threads=threads, verbose=verbose)

    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_file_accounts(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks File account names
    """
    print("[+] Checking for Azure File Accounts")
    
    if verbose:
        print(f"[*] File Accounts use format: accountname.{FILE_URL}")
        print(f"[*] Real example: mycompany-files.{FILE_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTP validation")
        print(f"[*] DNS resolution = Account exists, then HTTP test for access level")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    # As Azure Storage Accounts can contain only letters and numbers,
    # discard those not matching to save time on the DNS lookups.
    regex = re.compile('[^a-zA-Z0-9]')
    for name in names:
        if not re.search(regex, name):
            candidates.append(f'{name}.{FILE_URL}')

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(valid_names, use_ssl=False,
                        callback=print_account_response,
                        threads=threads, verbose=verbose)

    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_queue_accounts(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks Queue account names
    """
    print("[+] Checking for Azure Queue Accounts")
    
    if verbose:
        print(f"[*] Queue Accounts use format: accountname.{QUEUE_URL}")
        print(f"[*] Real example: mycompany-queues.{QUEUE_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTP validation")
        print(f"[*] DNS resolution = Account exists, then HTTP test for access level")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    # As Azure Storage Accounts can contain only letters and numbers,
    # discard those not matching to save time on the DNS lookups.
    regex = re.compile('[^a-zA-Z0-9]')
    for name in names:
        if not re.search(regex, name):
            candidates.append(f'{name}.{QUEUE_URL}')

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(valid_names, use_ssl=False,
                        callback=print_account_response,
                        threads=threads, verbose=verbose)

    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_table_accounts(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks Table account names
    """
    print("[+] Checking for Azure Table Accounts")
    
    if verbose:
        print(f"[*] Table Accounts use format: accountname.{TABLE_URL}")
        print(f"[*] Real example: mycompany-tables.{TABLE_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTP validation")
        print(f"[*] DNS resolution = Account exists, then HTTP test for access level")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    # As Azure Storage Accounts can contain only letters and numbers,
    # discard those not matching to save time on the DNS lookups.
    regex = re.compile('[^a-zA-Z0-9]')
    for name in names:
        if not re.search(regex, name):
            candidates.append(f'{name}.{TABLE_URL}')

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(valid_names, use_ssl=False,
                        callback=print_account_response,
                        threads=threads, verbose=verbose)

    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_mgmt_accounts(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks App Management account names
    """
    print("[+] Checking for Azure App Management Accounts")
    
    if verbose:
        print(f"[*] App Management uses format: accountname.{MGMT_URL}")
        print(f"[*] Real example: mycompany-scm.{MGMT_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTP validation")
        print(f"[*] DNS resolution = Account exists, then HTTP test for access level")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    # As Azure Storage Accounts can contain only letters and numbers,
    # discard those not matching to save time on the DNS lookups.
    regex = re.compile('[^a-zA-Z0-9]')
    for name in names:
        if not re.search(regex, name):
            candidates.append(f'{name}.{MGMT_URL}')

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(valid_names, use_ssl=False,
                        callback=print_account_response,
                        threads=threads, verbose=verbose)

    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_vault_accounts(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks Key Vault account names
    """
    print("[+] Checking for Azure Key Vault Accounts")
    
    if verbose:
        print(f"[*] Key Vault uses format: vaultname.{VAULT_URL}")
        print(f"[*] Real example: mycompany-secrets.{VAULT_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTP validation")
        print(f"[*] DNS resolution = Vault exists, then HTTP test for access level")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    # As Azure Storage Accounts can contain only letters and numbers,
    # discard those not matching to save time on the DNS lookups.
    regex = re.compile('[^a-zA-Z0-9]')
    for name in names:
        if not re.search(regex, name):
            candidates.append(f'{name}.{VAULT_URL}')

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(valid_names, use_ssl=False,
                        callback=print_account_response,
                        threads=threads, verbose=verbose)

    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))


def print_container_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    # Stop brute forcing disabled accounts
    if 'The specified account is disabled' in reply.reason:
        print("    [!] Breaking out early, account disabled.")
        return 'breakout'

    # Stop brute forcing accounts without permission
    if ('not authorized to perform this operation' in reply.reason or
            'not have sufficient permissions' in reply.reason or
            'Public access is not permitted' in reply.reason or
            'Server failed to authenticate the request' in reply.reason):
        print("    [!] Breaking out early, auth required.")
        return 'breakout'

    # Stop brute forcing unsupported accounts
    if 'Blob API is not yet supported' in reply.reason:
        print("    [!] Breaking out early, Hierarchical namespace account")
        return 'breakout'

    # Handle other responses
    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN AZURE CONTAINER'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
        utils.list_bucket_contents(reply.url)
    elif 'One of the request inputs is out of range' in reply.reason:
        pass
    elif 'The request URI is invalid' in reply.reason:
        pass
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")

    return None


def brute_force_containers(storage_accounts, brute_list, threads):
    """
    Attempts to find public Blob Containers in valid Storage Accounts

    Here is the URL format to list Azure Blog Container contents:
    <account>.blob.core.windows.net/<container>/?restype=container&comp=list
    """

    # We have a list of valid DNS names that might not be worth scraping,
    # such as disabled accounts or authentication required. Let's quickly
    # weed those out.
    print(f"[*] Checking {len(storage_accounts)} accounts for status before brute-forcing")
    valid_accounts = []
    for account in storage_accounts:
        try:
            reply = requests.get(f'https://{account}/')
            if 'Server failed to authenticate the request' in reply.reason:
                storage_accounts.remove(account)
            elif 'The specified account is disabled' in reply.reason:
                storage_accounts.remove(account)
            else:
                valid_accounts.append(account)
        except requests.exceptions.ConnectionError as error_msg:
            print(f"    [!] Connection error on https://{account}:")
            print(error_msg)

    # Read the brute force file into memory
    clean_names = utils.get_brute(brute_list, mini=3)

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    print(f"[*] Brute-forcing container names in {len(valid_accounts)} storage accounts")
    for account in valid_accounts:
        print(f"[*] Brute-forcing {len(clean_names)} container names in {account}")

        # Initialize the list of correctly formatted urls
        candidates = []

        # Take each mutated keyword and craft a url with correct format
        for name in clean_names:
            candidates.append(f'{account}/{name}/?restype=container&comp=list')

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(candidates, use_ssl=True,
                            callback=print_container_response,
                            threads=threads)

    # Stop the timer
    utils.stop_timer(start_time)


def print_website_response(hostname):
    """
    This function is passed into the DNS brute force as a callback,
    so we can get real-time results.
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    data['msg'] = 'Registered Azure Website DNS Name'
    data['target'] = hostname
    data['access'] = 'public'
    utils.fmt_output(data)


def check_azure_websites(names, nameserver, threads, nameserverfile=False, verbose=False):
    """
    Checks for Azure Websites (PaaS)
    """
    print("[+] Checking for Azure Websites")
    
    if verbose:
        print(f"[*] Azure Websites use format: sitename.{WEBAPP_URL}")
        print(f"[*] Real example: mycompany-webapp.{WEBAPP_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS A record lookups")
        print(f"[*] DNS resolution = Website exists (publicly accessible)")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = [name + '.' + WEBAPP_URL for name in names]

    # Azure Websites use DNS sub-domains. If it resolves, it is registered.
    utils.fast_dns_lookup(candidates, nameserver,
                          nameserverfile,
                          callback=print_website_response,
                          threads=threads, verbose=verbose)

    # Stop the timer
    utils.stop_timer(start_time)


def print_database_response(hostname):
    """
    This function is passed into the DNS brute force as a callback,
    so we can get real-time results.
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    data['msg'] = 'Registered Azure Database DNS Name'
    data['target'] = hostname
    data['access'] = 'public'
    utils.fmt_output(data)


def check_azure_databases(names, nameserver, threads, nameserverfile=False, verbose=False):
    """
    Checks for Azure Databases
    """
    print("[+] Checking for Azure Databases")
    
    if verbose:
        print(f"[*] Azure Databases use format: dbname.{DATABASE_URL}")
        print(f"[*] Real example: mycompany-db.{DATABASE_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS A record lookups")
        print(f"[*] DNS resolution = Database exists (check ports 1433/SQL)")
        
    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = [name + '.' + DATABASE_URL for name in names]

    # Azure databases use DNS sub-domains. If it resolves, it is registered.
    utils.fast_dns_lookup(candidates, nameserver,
                          nameserverfile,
                          callback=print_database_response,
                          threads=threads, verbose=verbose)

    # Stop the timer
    utils.stop_timer(start_time)


def print_vm_response(hostname):
    """
    This function is passed into the DNS brute force as a callback,
    so we can get real-time results.
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    data['msg'] = 'Registered Azure Virtual Machine DNS Name'
    data['target'] = hostname
    data['access'] = 'public'
    utils.fmt_output(data)


def check_azure_vms(names, nameserver, threads, nameserverfile=False, verbose=False):
    """
    Checks for Azure Virtual Machines
    """
    print("[+] Checking for Azure Virtual Machines")
    
    if verbose:
        print(f"[*] Azure VMs use format: vmname.<region>.{VM_URL}")
        print(f"[*] Real example: mycompany-vm.eastus.{VM_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS A record lookups")
        print(f"[*] DNS resolution = VM exists (check SSH/RDP ports)")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Pull the regions from a config file
    regions = azure_regions.REGIONS

    print(f"[*] Testing across {len(regions)} regions defined in the config file")

    for region in regions:

        # Initialize the list of domain names to look up
        candidates = [name + '.' + region + '.' + VM_URL for name in names]

        # Azure VMs use DNS sub-domains. If it resolves, it is registered.
        utils.fast_dns_lookup(candidates, nameserver,
                              nameserverfile,
                              callback=print_vm_response,
                              threads=threads, verbose=verbose)

    # Stop the timer
    utils.stop_timer(start_time)


def print_cognitive_response(reply):
    """
    Parses the HTTP reply for Azure Cognitive Services enumeration
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Service doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Cognitive Service Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN Cognitive Service'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Cognitive Service Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        data['msg'] = f'Cognitive Service Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_cognitive_services(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure Cognitive Services
    """
    print("[+] Checking for Azure Cognitive Services")
    
    if verbose:
        print(f"[*] Cognitive Services use format: servicename.{COGNITIVE_URL}")
        print(f"[*] Real example: mycompany-textapi.{COGNITIVE_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] 200 = Open API, 403 = Auth required, 404 = Not found")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{COGNITIVE_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_cognitive_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_aad_response(reply):
    """
    Parses the HTTP reply for Azure Active Directory enumeration
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Tenant doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Azure AD Tenant Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'ACCESSIBLE Azure AD Tenant'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Azure AD Tenant Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        data['msg'] = f'Azure AD Tenant Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_aad_tenants(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure Active Directory tenants
    """
    print("[+] Checking for Azure AD tenants")
    
    if verbose:
        print(f"[*] Azure AD uses format: tenantname.{AAD_URL}")
        print(f"[*] Real example: mycompany.{AAD_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] 200 = Open tenant, 403 = Auth required, 404 = Not found")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{AAD_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_aad_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_servicebus_response(reply):
    """
    Parses the HTTP reply for Azure Service Bus / Event Hubs enumeration
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Namespace doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Service Bus/Event Hub Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'ACCESSIBLE Service Bus/Event Hub'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Service Bus/Event Hub Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        data['msg'] = f'Service Bus/Event Hub Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_service_bus(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure Service Bus and Event Hubs
    """
    print("[+] Checking for Azure Service Bus and Event Hubs")
    
    if verbose:
        print(f"[*] Service Bus uses format: namespace.{SERVICEBUS_URL}")
        print(f"[*] Real example: mycompany-events.{SERVICEBUS_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] 200 = Open namespace, 403 = Auth required, 404 = Not found")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{SERVICEBUS_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_servicebus_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_api_mgmt_response(reply):
    """
    Parses the HTTP reply for Azure API Management enumeration
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # API doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'API Management Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN API Management Service'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'API Management Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        data['msg'] = f'API Management Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_api_management(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure API Management services
    """
    print("[+] Checking for Azure API Management services")
    
    if verbose:
        print(f"[*] API Management uses format: apiname.{API_MGMT_URL}")
        print(f"[*] Real example: mycompany-api.{API_MGMT_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] 200 = Open API, 403 = Auth required, 404 = Not found")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{API_MGMT_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_api_mgmt_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_aks_response(reply):
    """
    Parses the HTTP reply for Azure Kubernetes Service enumeration
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # AKS cluster doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'AKS Cluster Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'ACCESSIBLE AKS Cluster'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'AKS Cluster Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        data['msg'] = f'AKS Cluster Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_aks_clusters(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure Kubernetes Service clusters
    """
    print("[+] Checking for Azure Kubernetes Service clusters")
    
    if verbose:
        print(f"[*] AKS uses format: clustername.{AKS_URL}")
        print(f"[*] Real example: mycompany-k8s.{AKS_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] 200 = Open cluster, 403 = Auth required, 404 = Not found")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{AKS_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_aks_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_monitor_response(reply):
    """
    Parses the HTTP reply for Azure Monitor enumeration
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Monitor resource doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Azure Monitor Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'ACCESSIBLE Azure Monitor'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Azure Monitor Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        data['msg'] = f'Azure Monitor Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_monitor_services(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure Monitor services
    """
    print("[+] Checking for Azure Monitor services")
    
    if verbose:
        print(f"[*] Monitor uses format: resource.{MONITOR_URL}")
        print(f"[*] Real example: mycompany-monitoring.{MONITOR_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] 200 = Open resource, 403 = Auth required, 404 = Not found")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{MONITOR_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_monitor_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_logic_apps_response(reply):
    """
    Parses the HTTP reply for Azure Logic Apps enumeration
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Logic App doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Logic App Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'ACCESSIBLE Logic App'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Logic App Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        data['msg'] = f'Logic App Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_logic_apps(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure Logic Apps
    """
    print("[+] Checking for Azure Logic Apps")
    
    if verbose:
        print(f"[*] Logic Apps use format: appname.{LOGIC_APPS_URL}")
        print(f"[*] Real example: mycompany-workflow.{LOGIC_APPS_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] 200 = Open app, 403 = Auth required, 404 = Not found")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{LOGIC_APPS_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_logic_apps_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_redis_response(reply):
    """
    Parses the HTTP reply for Azure Redis Cache enumeration
    NOTE: Redis primarily uses non-HTTP protocols, but domain existence is valuable
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Redis cache doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Redis Cache Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'ACCESSIBLE Redis Cache'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Redis Cache Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        # Any other response indicates Redis domain exists (check Redis ports)
        data['msg'] = f'Redis Cache Domain Found (HTTP {reply.status_code}) - Check Port 6380'
        data['target'] = reply.url.replace('http://', '').replace('https://', '').split('/')[0]
        data['access'] = 'investigate'
        utils.fmt_output(data)
    return None


def check_redis_cache(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure Redis Cache instances
    """
    print("[+] Checking for Azure Redis Cache instances")
    
    if verbose:
        print(f"[*] Redis Cache uses format: cachename.{REDIS_URL}")
        print(f"[*] Real example: mycompany-cache.{REDIS_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] Any response = Redis exists (then check port 6380)")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{REDIS_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_redis_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_acr_response(reply):
    """
    Parses the HTTP reply for Azure Container Registry enumeration
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Registry doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Container Registry Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'ACCESSIBLE Container Registry'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Container Registry Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        data['msg'] = f'Container Registry Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_acr(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure Container Registry instances
    """
    print("[+] Checking for Azure Container Registry instances")
    
    if verbose:
        print(f"[*] Container Registry uses format: registryname.{ACR_URL}")
        print(f"[*] Real example: mycompany-registry.{ACR_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] 200 = Open registry, 403 = Auth required, 404 = Not found")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{ACR_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_acr_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_vnet_response(hostname):
    """
    This function is passed into the DNS brute force as a callback for VNets
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    data['msg'] = 'Registered Azure Virtual Network DNS Name'
    data['target'] = hostname
    data['access'] = 'investigate'
    utils.fmt_output(data)


def check_vnets(names, nameserver, threads, nameserverfile=False, selected_regions=None, verbose=False):
    """
    Checks for Azure Virtual Networks
    """
    print("[+] Checking for Azure Virtual Networks")
    
    if verbose:
        print(f"[*] Virtual Networks use format: vnetname.<region>.{VNET_URL}")
        print(f"[*] Real example: mycompany-vnet.eastus.{VNET_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS A record lookups")
        print(f"[*] DNS resolution = VNet exists (network infrastructure)")

    start_time = utils.start_timer()

    # Use selected regions or all regions
    regions = selected_regions if selected_regions else azure_regions.REGIONS

    if verbose:
        print(f"[*] Testing across {len(regions)} regions")

    for region in regions:
        candidates = [name + '.' + region + '.' + VNET_URL for name in names]
        utils.fast_dns_lookup(candidates, nameserver,
                              nameserverfile,
                              callback=print_vnet_response,
                              threads=threads, verbose=verbose)

    utils.stop_timer(start_time)


def print_cdn_response(reply):
    """
    Parses the HTTP reply for Azure CDN enumeration
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # CDN doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Azure CDN Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'ACCESSIBLE Azure CDN'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Azure CDN Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        data['msg'] = f'Azure CDN Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_cdn(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure CDN endpoints
    """
    print("[+] Checking for Azure CDN endpoints")
    
    if verbose:
        print(f"[*] Azure CDN uses format: endpointname.{CDN_URL}")
        print(f"[*] Real example: mycompany-cdn.{CDN_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] 200 = Open CDN, 403 = Auth required, 404 = Not found")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{CDN_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_cdn_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_eventgrid_response(reply):
    """
    Parses the HTTP reply for Azure Event Grid enumeration
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Event Grid doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Event Grid Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'ACCESSIBLE Event Grid'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Event Grid Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        data['msg'] = f'Event Grid Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_eventgrid(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure Event Grid instances
    """
    print("[+] Checking for Azure Event Grid instances")
    
    if verbose:
        print(f"[*] Event Grid uses format: topicname.{EVENTGRID_URL}")
        print(f"[*] Real example: mycompany-events.{EVENTGRID_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] 200 = Open topic, 403 = Auth required, 404 = Not found")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{EVENTGRID_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_eventgrid_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_datalake_response(reply):
    """
    Parses the HTTP reply for Azure Data Lake Storage enumeration
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Data Lake doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Data Lake Storage Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'ACCESSIBLE Data Lake Storage'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Data Lake Storage Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        data['msg'] = f'Data Lake Storage Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_datalake(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure Data Lake Storage Gen2 instances
    """
    print("[+] Checking for Azure Data Lake Storage Gen2 instances")
    
    if verbose:
        print(f"[*] Data Lake Storage uses format: accountname.{DATALAKE_URL}")
        print(f"[*] Real example: mycompany-datalake.{DATALAKE_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] 200 = Open storage, 403 = Auth required, 404 = Not found")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{DATALAKE_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_datalake_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_search_response(reply):
    """
    Parses the HTTP reply for Azure Cognitive Search enumeration
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Search service doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Cognitive Search Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'ACCESSIBLE Cognitive Search'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Cognitive Search Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        data['msg'] = f'Cognitive Search Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_search(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure Cognitive Search services
    """
    print("[+] Checking for Azure Cognitive Search services")
    
    if verbose:
        print(f"[*] Cognitive Search uses format: servicename.{SEARCH_URL}")
        print(f"[*] Real example: mycompany-search.{SEARCH_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] 200 = Open search, 403 = Auth required, 404 = Not found")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{SEARCH_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_search_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_iot_response(reply):
    """
    Parses the HTTP reply for Azure IoT Hub enumeration
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # IoT Hub doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'IoT Hub Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'ACCESSIBLE IoT Hub'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'IoT Hub Found (Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        data['msg'] = f'IoT Hub Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_iot(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for Azure IoT Hub instances
    """
    print("[+] Checking for Azure IoT Hub instances")
    
    if verbose:
        print(f"[*] IoT Hub uses format: hubname.{IOT_URL}")
        print(f"[*] Real example: mycompany-iot.{IOT_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS + HTTPS validation")
        print(f"[*] 200 = Open hub, 403 = Auth required, 404 = Not found")
        
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{IOT_URL}')
    
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    utils.get_url_batch(valid_names, use_ssl=True,
                        callback=print_iot_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


# Service mapping for user selections
SERVICE_FUNCTIONS = {
    'storage-accounts': 'check_storage_accounts',
    'file-accounts': 'check_file_accounts',
    'queue-accounts': 'check_queue_accounts',
    'table-accounts': 'check_table_accounts',
    'app-management': 'check_mgmt_accounts',
    'key-vault': 'check_vault_accounts',
    'websites': 'check_azure_websites',
    'databases': 'check_azure_databases',
    'virtual-machines': 'check_azure_vms',
    'cognitive-services': 'check_cognitive_services',
    'active-directory': 'check_aad_tenants',
    'service-bus': 'check_service_bus',
    'api-management': 'check_api_management',
    'aks': 'check_aks_clusters',
    'monitor': 'check_monitor_services',
    'logic-apps': 'check_logic_apps',
    'redis-cache': 'check_redis_cache',
    'container-registry': 'check_acr',
    'virtual-networks': 'check_vnets',
    'cdn': 'check_cdn',
    'event-grid': 'check_eventgrid',
    'data-lake': 'check_datalake',
    'cognitive-search': 'check_search',
    'iot-hub': 'check_iot'
}


def check_azure_vms_filtered(names, nameserver, threads, nameserverfile=False, selected_regions=None, verbose=False):
    """
    Checks for Azure Virtual Machines with optional region filtering
    """
    print("[+] Checking for Azure Virtual Machines")
    
    if verbose:
        print(f"[*] Azure VMs use format: vmname.<region>.{VM_URL}")
        print(f"[*] Real example: mycompany-vm.eastus.{VM_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS A record lookups")
        print(f"[*] DNS resolution = VM exists (check SSH/RDP ports)")

    start_time = utils.start_timer()

    # Use selected regions or all regions
    regions = selected_regions if selected_regions else azure_regions.REGIONS

    if verbose:
        print(f"[*] Testing across {len(regions)} regions")

    for region in regions:
        candidates = [name + '.' + region + '.' + VM_URL for name in names]
        utils.fast_dns_lookup(candidates, nameserver,
                              nameserverfile,
                              callback=print_vm_response,
                              threads=threads, verbose=verbose)

    utils.stop_timer(start_time)


def run_all(names, args):
    """
    Function is called by main program
    """
    print(BANNER)

    # Determine which services to run
    services_to_run = SERVICE_FUNCTIONS.keys()
    if hasattr(args, 'azure_services') and args.azure_services:
        services_to_run = args.azure_services
        print(f"[*] Running selected Azure services: {', '.join(services_to_run)}")
    else:
        print(f"[*] Running all {len(services_to_run)} Azure services")

    # Determine which regions to use
    selected_regions = None
    if hasattr(args, 'azure_regions') and args.azure_regions:
        selected_regions = args.azure_regions
        print(f"[*] Using selected Azure regions: {', '.join(selected_regions)}")

    # Check for verbose mode
    verbose = hasattr(args, 'verbose') and args.verbose
    if verbose:
        print(f"[*] Verbose mode enabled - showing detailed enumeration process")

    # Execute selected services
    valid_accounts = None
    
    for service in services_to_run:
        if service in SERVICE_FUNCTIONS:
            func_name = SERVICE_FUNCTIONS[service]
            
            # Special handling for different function signatures and region usage
            if service == 'storage-accounts':
                valid_accounts = check_storage_accounts(names, args.threads,
                                                      args.nameserver, args.nameserverfile, verbose)
                # Container brute forcing for storage accounts
                if valid_accounts and not args.quickscan and 'storage-accounts' in services_to_run:
                    brute_force_containers(valid_accounts, args.brute, args.threads)
                    
            elif service == 'file-accounts':
                check_file_accounts(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'queue-accounts':
                check_queue_accounts(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'table-accounts':
                check_table_accounts(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'app-management':
                check_mgmt_accounts(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'key-vault':
                check_vault_accounts(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'websites':
                check_azure_websites(names, args.nameserver, args.threads, args.nameserverfile, verbose)
            elif service == 'databases':
                check_azure_databases(names, args.nameserver, args.threads, args.nameserverfile, verbose)
            elif service == 'virtual-machines':
                # Special handling for VMs with region filtering
                check_azure_vms_filtered(names, args.nameserver, args.threads, 
                                       args.nameserverfile, selected_regions, verbose)
            elif service == 'cognitive-services':
                check_cognitive_services(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'active-directory':
                check_aad_tenants(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'service-bus':
                check_service_bus(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'api-management':
                check_api_management(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'aks':
                check_aks_clusters(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'monitor':
                check_monitor_services(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'logic-apps':
                check_logic_apps(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'redis-cache':
                check_redis_cache(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'container-registry':
                check_acr(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'virtual-networks':
                # Special handling for VNets with region filtering
                check_vnets(names, args.nameserver, args.threads, 
                          args.nameserverfile, selected_regions, verbose)
            elif service == 'cdn':
                check_cdn(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'event-grid':
                check_eventgrid(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'data-lake':
                check_datalake(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'cognitive-search':
                check_search(names, args.threads, args.nameserver, args.nameserverfile, verbose)
            elif service == 'iot-hub':
                check_iot(names, args.threads, args.nameserver, args.nameserverfile, verbose)
