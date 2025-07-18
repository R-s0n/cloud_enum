"""
Helper functions for network requests, etc
"""

import time
import sys
import datetime
import re
import csv
import json
import ipaddress
from multiprocessing.dummy import Pool as ThreadPool
from functools import partial
from urllib.parse import urlparse
try:
    import requests
    import dns
    import dns.resolver
    from concurrent.futures import ThreadPoolExecutor
    from requests_futures.sessions import FuturesSession
    from concurrent.futures._base import TimeoutError
except ImportError:
    print("[!] Please pip install requirements.txt.")
    sys.exit()

LOGFILE = False
LOGFILE_FMT = ''


def init_logfile(logfile, fmt):
    """
    Initialize the global logfile if specified as a user-supplied argument
    """
    if logfile:
        global LOGFILE
        LOGFILE = logfile

        global LOGFILE_FMT
        LOGFILE_FMT = fmt

        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        with open(logfile, 'a', encoding='utf-8') as log_writer:
            log_writer.write(f"\n\n#### CLOUD_ENUM {now} ####\n")


def is_valid_domain(domain):
    """
    Checks if the domain has a valid format and length
    """
    # Check for domain total length
    if len(domain) > 253:  # According to DNS specifications
        return False

    # Check each label in the domain
    for label in domain.split('.'):
        # Each label should be between 1 and 63 characters long
        if not (1 <= len(label) <= 63):
            return False
        
    return True


def get_url_batch(url_list, use_ssl=False, callback='', threads=5, redir=True, verbose=False):
    """
    Processes a list of URLs, sending the results back to the calling
    function in real-time via the `callback` parameter
    """

    # Start a counter for a status message
    tick = {}
    tick['total'] = len(url_list)
    tick['current'] = 0

    # Filter out invalid URLs
    url_list = [url for url in url_list if is_valid_domain(url)]

    # Break the url list into smaller lists based on thread size
    queue = [url_list[x:x+threads] for x in range(0, len(url_list), threads)]

    # Define the protocol
    if use_ssl:
        proto = 'https://'
    else:
        proto = 'http://'

    # Using the async requests-futures module, work in batches based on
    # the 'queue' list created above. Call each URL, sending the results
    # back to the callback function.
    for batch in queue:
        # I used to initialize the session object outside of this loop, BUT
        # there were a lot of errors that looked related to pool cleanup not
        # happening. Putting it in here fixes the issue.
        # There is an unresolved discussion here:
        # https://github.com/ross/requests-futures/issues/20
        session = FuturesSession(executor=ThreadPoolExecutor(max_workers=threads+5))
        batch_pending = {}
        batch_results = {}

        # First, grab the pending async request and store it in a dict
        for url in batch:
            batch_pending[url] = session.get(proto + url, allow_redirects=redir)

        # Then, grab all the results from the queue.
        # This is where we need to catch exceptions that occur with large
        # fuzz lists and dodgy connections.
        connection_errors = 0
        for url in batch_pending:
            try:
                # Timeout is set due to observation of some large jobs simply
                # hanging forever with no exception raised.
                batch_results[url] = batch_pending[url].result(timeout=30)
                if verbose:
                    print(f"    [*] {proto}{url} -> {batch_results[url].status_code}")
            except requests.exceptions.ConnectionError:
                # Count connection errors but don't print each one (too verbose)
                # These are expected when scanning for non-existent resources
                connection_errors += 1
                if verbose:
                    print(f"    [*] {proto}{url} -> Connection Error")
            except TimeoutError:
                if verbose:
                    print(f"    [*] {proto}{url} -> Timeout")
                print(f"    [!] Timeout on {url}. Investigate if there are"
                      " many of these")
        
        # Only report connection errors if there are significant numbers
        if connection_errors > 0 and connection_errors == len(batch):
            # All connections in batch failed - might indicate network issues
            if connection_errors > 20:
                print(f"    [*] {connection_errors} connection errors in batch (likely non-existent resources)")
        elif connection_errors > 10:
            # Some connections failed but not all
            print(f"    [*] {connection_errors} connection errors in batch")

        # Now, send all the results to the callback function for analysis
        # We need a way to stop processing unnecessary brute-forces, so the
        # callback may tell us to bail out.
        for url in batch_results:
            check = callback(batch_results[url])
            if check == 'breakout':
                return

        # Refresh a status message
        tick['current'] += threads
        sys.stdout.flush()
        sys.stdout.write(f"    {tick['current']}/{tick['total']} complete...")
        sys.stdout.write('\r')

    # Clear the status message
    sys.stdout.write('                            \r')

def read_nameservers(file_path):
    """
    Reads nameservers from a given file.
    Each line in the file should contain one nameserver IP address.
    Lines starting with '#' will be ignored as comments.
    """
    try:
        with open(file_path, 'r') as file:
            nameservers = [line.strip() for line in file if line.strip() and not line.startswith('#')]
        if not nameservers:
            raise ValueError("Nameserver file is empty or only contains comments")
        return nameservers
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        exit(1)
    except ValueError as e:
        print(e)
        exit(1)

def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def dns_lookup(nameserver, name):
    """
    This function performs the actual DNS lookup when called in a threadpool
    by the fast_dns_lookup function.
    """
    nameserverfile = False
    if not is_valid_ip(nameserver):
        nameserverfile = nameserver

    res = dns.resolver.Resolver()
    res.timeout = 10
    if nameserverfile:
        nameservers = read_nameservers(nameserverfile)
        res.nameservers = nameservers
    else:
        res.nameservers = [nameserver]

    try:
        res.query(name)
        # If no exception is thrown, return the valid name
        return name
    except dns.resolver.NXDOMAIN:
        # Domain doesn't exist - normal for enumeration
        return ''
    except dns.resolver.NoNameservers as exc_text:
        # Check if this is a SERVFAIL (common with AWS services that don't exist)
        if "SERVFAIL" in str(exc_text):
            # SERVFAIL is normal for non-existent AWS resources, treat as NXDOMAIN
            return ''
        else:
            # True nameserver error - report but don't exit
            print("    [!] Warning: DNS nameserver issue detected")
            print("    [!] If you're using a VPN, try setting --ns to your VPN's nameserver.")
            print(f"    [!] Continuing with remaining checks. Error: {exc_text}")
            return ''
    except (dns.exception.Timeout, dns.resolver.NoAnswer):
        # Timeout or no answer - not uncommon in cloud enumeration
        return ''
    except Exception as exc_text:
        # Catch any other DNS exceptions without crashing
        print(f"    [!] DNS lookup error for {name}: {exc_text}")
        return ''


def fast_dns_lookup(names, nameserver, nameserverfile, callback='', threads=5, verbose=False):
    """
    Helper function to resolve DNS names. Uses multithreading.
    """
    total = len(names)
    current = 0
    valid_names = []

    print(f"[*] Brute-forcing a list of {total} possible DNS names")

    # Filter out invalid domains
    names = [name for name in names if is_valid_domain(name)]

    # Break the url list into smaller lists based on thread size
    queue = [names[x:x+threads] for x in range(0, len(names), threads)]

    for batch in queue:
        pool = ThreadPool(threads)

        # Because pool.map takes only a single function arg, we need to
        # define this partial so that each iteration uses the same ns
        if nameserverfile:
            dns_lookup_params = partial(dns_lookup, nameserverfile)
        else:
            dns_lookup_params = partial(dns_lookup, nameserver)

        results = pool.map(dns_lookup_params, batch)

        # We should now have the batch of results back, process them.
        for i, name in enumerate(batch):
            result = results[i]
            if verbose:
                if result:
                    print(f"    [*] {name} -> FOUND")
                else:
                    print(f"    [*] {name} -> NXDOMAIN")
            if result:
                if callback:
                    callback(result)
                valid_names.append(result)

        current += threads

        # Update the status message
        if not verbose:  # Only show progress bar if not verbose
            sys.stdout.flush()
            sys.stdout.write(f"    {current}/{total} complete...")
            sys.stdout.write('\r')
        pool.close()

    # Clear the status message
    if not verbose:
        sys.stdout.write('                            \r')

    return valid_names


def list_bucket_contents(bucket):
    """
    Provides a list of full URLs to each open bucket
    """
    key_regex = re.compile(r'<(?:Key|Name)>(.*?)</(?:Key|Name)>')
    reply = requests.get(bucket)

    # Make a list of all the relative-path key name
    keys = re.findall(key_regex, reply.text)

    # Need to remove URL parameters before appending file names
    # from Azure buckets
    sub_regex = re.compile(r'(\?.*)')
    bucket = sub_regex.sub('', bucket)

    # Format them to full URLs and print to console
    if keys:
        print("      FILES:")
        for key in keys:
            url = bucket + key
            print(f"      ->{url}")
    else:
        print("      ...empty bucket, so sad. :(")


def fmt_output(data):
    """
    Handles the output - printing and logging based on a specified format
    """
    # ANSI escape sequences are set based on accessibility of target
    # (basically, how public it is))
    bold = '\033[1m'
    end = '\033[0m'
    ansi = bold + '\033[37m'  # default white
    
    if data['access'] == 'public':
        ansi = bold + '\033[92m'  # green
    elif data['access'] == 'protected':
        ansi = bold + '\033[33m'  # orange
    elif data['access'] == 'disabled':
        ansi = bold + '\033[31m'  # red
    elif data['access'] == 'investigate':
        ansi = bold + '\033[94m'  # blue
    elif data['access'] == 'unknown':
        ansi = bold + '\033[95m'  # magenta
    elif data['access'] == 'rate-limited':
        ansi = bold + '\033[33m'  # orange (same as protected)

    sys.stdout.write('  ' + ansi + data['msg'] + ': ' + data['target'] + end + '\n')

    if LOGFILE:
        with open(LOGFILE, 'a', encoding='utf-8') as log_writer:
            if LOGFILE_FMT == 'text':
                log_writer.write(f'{data["msg"]}: {data["target"]}\n')
            if LOGFILE_FMT == 'csv':
                writer = csv.DictWriter(log_writer, data.keys())
                writer.writerow(data)
            if LOGFILE_FMT == 'json':
                log_writer.write(json.dumps(data) + '\n')


def get_brute(brute_file, mini=1, maxi=63, banned='[^a-z0-9_-]'):
    """
    Generates a list of brute-force words based on length and allowed chars
    """
    # Read the brute force file into memory
    with open(brute_file, encoding="utf8", errors="ignore") as infile:
        names = infile.read().splitlines()

    # Clean up the names to usable for containers
    banned_chars = re.compile(banned)
    clean_names = []
    for name in names:
        name = name.lower()
        name = banned_chars.sub('', name)
        if maxi >= len(name) >= mini:
            if name not in clean_names:
                clean_names.append(name)

    return clean_names


def start_timer():
    """
    Starts a timer for functions in main module
    """
    # Start a counter to report on elapsed time
    start_time = time.time()
    return start_time


def stop_timer(start_time):
    """
    Stops timer and prints a status
    """
    # Stop the timer
    elapsed_time = time.time() - start_time
    formatted_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))

    # Print some statistics
    print("")
    print(f" Elapsed time: {formatted_time}")
    print("")
