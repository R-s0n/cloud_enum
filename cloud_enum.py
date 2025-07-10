#!/usr/bin/env python3

"""
cloud_enum by initstring (github.com/initstring)

Multi-cloud OSINT tool designed to enumerate storage and services in AWS,
Azure, and GCP.

Enjoy!
"""

import os
import sys
import argparse
import re
from enum_tools import aws_checks
from enum_tools import azure_checks
from enum_tools import gcp_checks
from enum_tools import utils

BANNER = '''
##########################
        cloud_enum
   github.com/initstring
forked by github.com/R-s0n
##########################

'''

# Define available services for each cloud provider
AWS_SERVICES = [
    's3', 'awsapps', 'sqs', 
    'eks', 
    'workdocs', 'emr', 'elastic-beanstalk', 
    'cognito', 'cloud9', 'workmail', 
    'cloudtrail', 'iot-core',
    'sagemaker', 'quicksight'
]

AZURE_SERVICES = [
    'storage-accounts', 'file-accounts', 'queue-accounts', 'table-accounts',
    'app-management', 'key-vault', 'websites', 'databases', 'virtual-machines',
    'cognitive-services', 'active-directory', 'service-bus', 'api-management',
    'aks', 'monitor', 'logic-apps', 'redis-cache', 'container-registry',
    'virtual-networks', 'cdn', 'event-grid', 'data-lake', 'cognitive-search',
    'iot-hub'
]

GCP_SERVICES = [
    'gcp-buckets', 'firebase-rtdb', 'firebase-apps', 'app-engine', 
    'cloud-functions', 'pubsub', 'bigquery', 'spanner', 'cloud-sql',
    'vision-api', 'identity-platform', 'firestore', 'datastore',
    'text-to-speech', 'ai-platform'
]

# Define available regions (imported from region files)
from enum_tools.aws_checks import AWS_REGIONS
from enum_tools.azure_regions import REGIONS as AZURE_REGIONS
from enum_tools.gcp_regions import REGIONS as GCP_REGIONS

# Clean up region lists for user display
AWS_REGION_NAMES = [region.replace('.amazonaws.com', '').replace('.amazonaws.com.cn', '') for region in AWS_REGIONS if region != 'amazonaws.com']
AZURE_REGION_NAMES = AZURE_REGIONS
GCP_REGION_NAMES = GCP_REGIONS


def parse_arguments():
    """
    Handles user-passed parameters
    """
    desc = "Multi-cloud enumeration utility. All hail OSINT!"
    parser = argparse.ArgumentParser(description=desc)

    # Grab the current dir of the script, for setting some defaults below
    script_path = os.path.split(os.path.abspath(sys.argv[0]))[0]

    kw_group = parser.add_mutually_exclusive_group(required=False)

    # Keyword can given multiple times
    kw_group.add_argument('-k', '--keyword', type=str, action='append',
                          help='Keyword. Can use argument multiple times.')

    # OR, a keyword file can be used
    kw_group.add_argument('-kf', '--keyfile', type=str, action='store',
                          help='Input file with a single keyword per line.')

    # Use included mutations file by default, or let the user provide one
    parser.add_argument('-m', '--mutations', type=str, action='store',
                        default=os.path.join(script_path, 'enum_tools', 'fuzz_small.txt'),
                        help='Mutations. Default: enum_tools/fuzz_small.txt')

    # Use include container brute-force or let the user provide one
    parser.add_argument('-b', '--brute', type=str, action='store',
                        default=os.path.join(script_path, 'enum_tools', 'fuzz_small.txt'),
                        help='List to brute-force Azure container names.'
                        '  Default: enum_tools/fuzz_small.txt')

    parser.add_argument('-t', '--threads', type=int, action='store',
                        default=5, help='Threads for HTTP brute-force.'
                        ' Default = 5')

    parser.add_argument('-ns', '--nameserver', type=str, action='store',
                        default='1.1.1.1',
                        help='DNS server to use in brute-force.')
    parser.add_argument('-nsf', '--nameserverfile', type=str, 
                        help='Path to the file containing nameserver IPs')
    parser.add_argument('-l', '--logfile', type=str, action='store',
                        help='Appends found items to specified file.')
    parser.add_argument('-f', '--format', type=str, action='store',
                        default='text',
                        help='Format for log file (text,json,csv)'
                             ' - default: text')

    parser.add_argument('--disable-aws', action='store_true',
                        help='Disable Amazon checks.')

    parser.add_argument('--disable-azure', action='store_true',
                        help='Disable Azure checks.')

    parser.add_argument('--disable-gcp', action='store_true',
                        help='Disable Google checks.')

    parser.add_argument('-qs', '--quickscan', action='store_true',
                        help='Disable all mutations and second-level scans')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output showing detailed enumeration process')

    # Keyword processing logic
    parser.add_argument('--keyword-logic', type=str, action='store',
                        choices=['seq', 'conc'], default='conc',
                        help='Keyword processing logic: seq (sequential - current behavior) or conc (concurrent - mutations between keywords). Default: conc')

    # AWS credential arguments
    parser.add_argument('--aws-access-key', type=str, action='store',
                        help='AWS access key ID for authenticated requests')
    parser.add_argument('--aws-secret-key', type=str, action='store',
                        help='AWS secret access key for authenticated requests')
    parser.add_argument('--aws-account-id', type=str, action='store',
                        help='AWS account ID for SQS queue enumeration (12-digit number)')

    # Region control arguments
    parser.add_argument('--aws-regions', type=str, action='store',
                        help='Comma-separated list of AWS regions to check')
    parser.add_argument('--azure-regions', type=str, action='store',
                        help='Comma-separated list of Azure regions to check')
    parser.add_argument('--gcp-regions', type=str, action='store',
                        help='Comma-separated list of GCP regions to check')

    # Service control arguments
    parser.add_argument('--aws-services', type=str, action='store',
                        help='Comma-separated list of AWS services to check')
    parser.add_argument('--azure-services', type=str, action='store',
                        help='Comma-separated list of Azure services to check')
    parser.add_argument('--gcp-services', type=str, action='store',
                        help='Comma-separated list of GCP services to check')

    # Information display arguments
    parser.add_argument('--show-regions', action='store_true',
                        help='Display available regions for all cloud providers')
    parser.add_argument('--show-services', action='store_true',
                        help='Display available services for all cloud providers')

    args = parser.parse_args()

    # Handle information display requests
    if args.show_regions:
        show_available_regions()
        sys.exit()
    
    if args.show_services:
        show_available_services()
        sys.exit()

    # Check that keywords are provided when not using info display flags
    if not args.keyword and not args.keyfile:
        print("[!] Error: Must provide keywords with -k or --keyfile (unless using --show-regions or --show-services)")
        parser.print_help()
        sys.exit(1)

    # Validate and process region selections
    if args.aws_regions:
        args.aws_regions = validate_regions(args.aws_regions, AWS_REGION_NAMES, 'AWS')
    if args.azure_regions:
        args.azure_regions = validate_regions(args.azure_regions, AZURE_REGION_NAMES, 'Azure')
    if args.gcp_regions:
        args.gcp_regions = validate_regions(args.gcp_regions, GCP_REGION_NAMES, 'GCP')

    # Validate and process service selections
    if args.aws_services:
        args.aws_services = validate_services(args.aws_services, AWS_SERVICES, 'AWS')
    if args.azure_services:
        args.azure_services = validate_services(args.azure_services, AZURE_SERVICES, 'Azure')
    if args.gcp_services:
        args.gcp_services = validate_services(args.gcp_services, GCP_SERVICES, 'GCP')

    # Validate AWS account ID if provided
    if args.aws_account_id:
        if not re.match(r'^\d{12}$', args.aws_account_id):
            print("[!] AWS Account ID must be a 12-digit number")
            sys.exit(1)
        print(f"[+] Using AWS Account ID: {args.aws_account_id}")

    # Ensure mutations file is readable
    if not os.access(args.mutations, os.R_OK):
        print(f"[!] Cannot access mutations file: {args.mutations}")
        sys.exit()

    # Ensure brute file is readable
    if not os.access(args.brute, os.R_OK):
        print("[!] Cannot access brute-force file, exiting")
        sys.exit()

    # Ensure keywords file is readable
    if args.keyfile:
        if not os.access(args.keyfile, os.R_OK):
            print("[!] Cannot access keyword file, exiting")
            sys.exit()

        # Parse keywords from input file
        with open(args.keyfile, encoding='utf-8') as infile:
            args.keyword = [keyword.strip() for keyword in infile]

    # Ensure log file is writeable
    if args.logfile:
        if os.path.isdir(args.logfile):
            print("[!] Can't specify a directory as the logfile, exiting.")
            sys.exit()
        if os.path.isfile(args.logfile):
            target = args.logfile
        else:
            target = os.path.dirname(args.logfile)
            if target == '':
                target = '.'

        if not os.access(target, os.W_OK):
            print("[!] Cannot write to log file, exiting")
            sys.exit()

        # Set up logging format
        if args.format not in ('text', 'json', 'csv'):
            print("[!] Sorry! Allowed log formats: 'text', 'json', or 'csv'")
            sys.exit()
        # Set the global in the utils file, where logging needs to happen
        utils.init_logfile(args.logfile, args.format)

    return args


def validate_regions(user_regions, valid_regions, cloud_name):
    """
    Validates user-provided regions against available regions
    """
    user_list = [region.strip() for region in user_regions.split(',')]
    validated_regions = []
    invalid_regions = []

    for region in user_list:
        if region in valid_regions:
            validated_regions.append(region)
        else:
            invalid_regions.append(region)

    if invalid_regions:
        print(f"[!] Invalid {cloud_name} regions removed: {', '.join(invalid_regions)}")
        print(f"[*] Use --show-regions to see available {cloud_name} regions")

    if not validated_regions:
        print(f"[!] No valid {cloud_name} regions provided, using all regions")
        return None

    print(f"[+] Using {cloud_name} regions: {', '.join(validated_regions)}")
    return validated_regions


def validate_services(user_services, valid_services, cloud_name):
    """
    Validates user-provided services against available services
    """
    user_list = [service.strip().lower() for service in user_services.split(',')]
    validated_services = []
    invalid_services = []

    for service in user_list:
        if service in valid_services:
            validated_services.append(service)
        else:
            invalid_services.append(service)

    if invalid_services:
        print(f"[!] Invalid {cloud_name} services removed: {', '.join(invalid_services)}")
        print(f"[*] Use --show-services to see available {cloud_name} services")

    if not validated_services:
        print(f"[!] No valid {cloud_name} services provided, using all services")
        return None

    print(f"[+] Using {cloud_name} services: {', '.join(validated_services)}")
    return validated_services


def show_available_regions():
    """
    Display available regions for all cloud providers
    """
    print("\n=== AVAILABLE REGIONS ===\n")
    
    print("AWS Regions:")
    for i, region in enumerate(AWS_REGION_NAMES, 1):
        print(f"  {i:2d}. {region}")
    
    print(f"\nAzure Regions:")
    for i, region in enumerate(AZURE_REGION_NAMES, 1):
        print(f"  {i:2d}. {region}")
    
    print(f"\nGCP Regions:")
    for i, region in enumerate(GCP_REGION_NAMES, 1):
        print(f"  {i:2d}. {region}")
    
    print("\nExample usage:")
    print("  --aws-regions us-east-1,us-west-2,eu-west-1")
    print("  --azure-regions eastus,westus2,northeurope")
    print("  --gcp-regions us-central1,europe-west1,asia-east1")


def show_available_services():
    """
    Display available services for all cloud providers
    """
    print("\n=== AVAILABLE SERVICES ===\n")
    
    print("AWS Services:")
    for i, service in enumerate(AWS_SERVICES, 1):
        print(f"  {i:2d}. {service}")
    
    print(f"\nAzure Services:")
    for i, service in enumerate(AZURE_SERVICES, 1):
        print(f"  {i:2d}. {service}")
    
    print(f"\nGCP Services:")
    for i, service in enumerate(GCP_SERVICES, 1):
        print(f"  {i:2d}. {service}")
    
    print("\nExample usage:")
    print("  --aws-services s3,sqs,eks")
    print("  --azure-services storage-accounts,websites,databases")
    print("  --gcp-services gcp-buckets,app-engine,cloud-functions")


def print_status(args):
    """
    Print a short pre-run status message
    """
    print(f"Keywords:    {', '.join(args.keyword)}")
    if args.quickscan:
        print("Mutations:   NONE! (Using quickscan)")
    else:
        print(f"Mutations:   {args.mutations}")
    print(f"Brute-list:  {args.brute}")
    print(f"Keyword Logic: {args.keyword_logic} ({'sequential' if args.keyword_logic == 'seq' else 'concurrent - mutations between keywords'})")
    
    # Show AWS account ID if provided
    if hasattr(args, 'aws_account_id') and args.aws_account_id:
        print(f"AWS Account ID: {args.aws_account_id}")
    
    # Show region/service selections
    if args.aws_regions:
        print(f"AWS Regions: {', '.join(args.aws_regions)}")
    if args.azure_regions:
        print(f"Azure Regions: {', '.join(args.azure_regions)}")
    if args.gcp_regions:
        print(f"GCP Regions: {', '.join(args.gcp_regions)}")
    
    if args.aws_services:
        print(f"AWS Services: {', '.join(args.aws_services)}")
    if args.azure_services:
        print(f"Azure Services: {', '.join(args.azure_services)}")
    if args.gcp_services:
        print(f"GCP Services: {', '.join(args.gcp_services)}")
    
    print("")


def check_windows():
    """
    Fixes pretty color printing for Windows users. Keeping out of
    requirements.txt to avoid the library requirement for most users.
    """
    if os.name == 'nt':
        try:
            import colorama
            colorama.init()
        except ModuleNotFoundError:
            print("[!] Yo, Windows user - if you want pretty colors, you can"
                  " install the colorama python package.")


def read_mutations(mutations_file):
    """
    Read mutations file into memory for processing.
    """
    with open(mutations_file, encoding="utf8", errors="ignore") as infile:
        mutations = infile.read().splitlines()

    print(f"[+] Mutations list imported: {len(mutations)} items")
    return mutations


def clean_text(text):
    """
    Clean text to be RFC compliant for hostnames / DNS
    """
    banned_chars = re.compile('[^a-z0-9.-]')
    text_lower = text.lower()
    text_clean = banned_chars.sub('', text_lower)

    return text_clean


def append_name(name, names_list):
    """
    Ensure strings stick to DNS label limit of 63 characters
    """
    if len(name) <= 63:
        names_list.append(name)


def build_names(base_list, mutations, keyword_logic='conc'):
    """
    Combine base and mutations for processing by individual modules.
    
    Args:
        base_list: List of base keywords
        mutations: List of mutation strings  
        keyword_logic: 'seq' for sequential (current behavior) or 'conc' for concurrent (mutations between keywords)
    """
    names = []

    if keyword_logic == 'seq':
        # Sequential logic: Process each keyword individually (original behavior)
        for base in base_list:
            # Clean base
            base = clean_text(base)

            # First, include with no mutations
            append_name(base, names)

            for mutation in mutations:
                # Clean mutation
                mutation = clean_text(mutation)

                # Then, do appends
                append_name(f"{base}{mutation}", names)
                append_name(f"{base}.{mutation}", names)
                append_name(f"{base}-{mutation}", names)
                append_name(f"{base}_{mutation}", names)

                # Then, do prepends
                append_name(f"{mutation}{base}", names)
                append_name(f"{mutation}.{base}", names)
                append_name(f"{mutation}-{base}", names)
                append_name(f"{mutation}_{base}", names)

    else:  # 'conc' - Concurrent logic
        # Clean all bases first
        clean_bases = [clean_text(base) for base in base_list]
        clean_mutations = [clean_text(mutation) for mutation in mutations]
        
        # Step 1: Add original keywords as-is
        for base in clean_bases:
            append_name(base, names)
        
        # Step 2: Generate keyword combinations with mutations between them
        if len(clean_bases) > 1:
            import itertools
            
            # Generate all 2+ keyword combinations
            for r in range(2, len(clean_bases) + 1):
                for keyword_combo in itertools.permutations(clean_bases, r):
                    # For each keyword combination, try mutations between them
                    for mutation in clean_mutations:
                        # Join with mutation using different separators
                        separators = ['', '.', '-', '_']
                        for sep in separators:
                            # Insert mutation between keywords
                            joined_with_mutation = f"{sep}{mutation}{sep}".join(keyword_combo)
                            append_name(joined_with_mutation, names)
                    
                    # Also try combinations without mutations (just keywords joined)
                    for sep in ['.', '-', '_']:
                        simple_combo = sep.join(keyword_combo)
                        append_name(simple_combo, names)
        
        # Step 3: Apply traditional front/back mutations to individual keywords
        for base in clean_bases:
            for mutation in clean_mutations:
                # Then, do appends
                append_name(f"{base}{mutation}", names)
                append_name(f"{base}.{mutation}", names)
                append_name(f"{base}-{mutation}", names)
                append_name(f"{base}_{mutation}", names)

                # Then, do prepends
                append_name(f"{mutation}{base}", names)
                append_name(f"{mutation}.{base}", names)
                append_name(f"{mutation}-{base}", names)
                append_name(f"{mutation}_{base}", names)

    # Remove duplicates while preserving order
    seen = set()
    unique_names = []
    for name in names:
        if name not in seen:
            seen.add(name)
            unique_names.append(name)

    print(f"[+] Mutated results: {len(unique_names)} items (logic: {keyword_logic})")

    return unique_names

def read_nameservers(file_path):
    try:
        with open(file_path, 'r') as file:
            nameservers = [line.strip() for line in file if line.strip()]
        if not nameservers:
            raise ValueError("Nameserver file is empty")
        return nameservers
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        exit(1)
    except ValueError as e:
        print(e)
        exit(1)

def main():
    """
    Main program function.
    """
    args = parse_arguments()
    print(BANNER)

    # Generate a basic status on targets and parameters
    print_status(args)

    # Give our Windows friends a chance at pretty colors
    check_windows()

    # First, build a sorted base list of target names
    if args.quickscan:
        mutations = []
    else:
        mutations = read_mutations(args.mutations)
    names = build_names(args.keyword, mutations, args.keyword_logic)

    # All the work is done in the individual modules
    try:
        if not args.disable_aws:
            aws_checks.run_all(names, args)
        if not args.disable_azure:
            azure_checks.run_all(names, args)
        if not args.disable_gcp:
            gcp_checks.run_all(names, args)
    except KeyboardInterrupt:
        print("Thanks for playing!")
        sys.exit()

    # Best of luck to you!
    print("\n[+] All done, happy hacking!\n")
    sys.exit()


if __name__ == '__main__':
    main()
