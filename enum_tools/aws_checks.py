"""
AWS-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

import boto3
import botocore
import signal
import sys
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from enum_tools import utils

# Global flag for interrupt handling
_interrupt_flag = False

BANNER = '''
++++++++++++++++++++++++++
      amazon checks
++++++++++++++++++++++++++
'''

# Known S3 domain names
S3_URL = 's3.amazonaws.com'
S3_ACCELERATE_URL = 's3-accelerate.amazonaws.com'
APPS_URL = 'awsapps.com'
SQS_URL = 'sqs.amazonaws.com'
EKS_URL = 'eks.amazonaws.com'
WORKDOCS_URL = 'workdocs.amazonaws.com'
EMR_URL = 'emr.amazonaws.com'
ELASTIC_BEANSTALK_URL = 'elasticbeanstalk.com'
CLOUDTRAIL_URL = 'cloudtrail.amazonaws.com'
COGNITO_URL = 'amazoncognito.com'
CLOUD9_URL = 'aws.amazon.com'
IOT_CORE_URL = 'iot.amazonaws.com'
SAGEMAKER_URL = 'sagemaker.amazonaws.com'
QUICKSIGHT_URL = 'quicksight.amazonaws.com'

# Known AWS region names. This global will be used unless the user passes
# in a specific region name. (NOT YET IMPLEMENTED)
AWS_REGIONS = [
    # North America
    'us-east-1.amazonaws.com',        # US East (N. Virginia)
    'us-east-2.amazonaws.com',        # US East (Ohio)
    'us-west-1.amazonaws.com',        # US West (N. California)
    'us-west-2.amazonaws.com',        # US West (Oregon)
    'ca-central-1.amazonaws.com',     # Canada (Central)
    'ca-west-1.amazonaws.com',        # Canada West (Calgary)
    'us-gov-east-1.amazonaws.com',    # GovCloud (US-East)
    'us-gov-west-1.amazonaws.com',    # GovCloud (US-West)
    'mx-central-1.amazonaws.com',     # Mexico (Central)
    
    # South America
    'sa-east-1.amazonaws.com',        # South America (São Paulo)
    
    # Europe
    'eu-west-1.amazonaws.com',        # Europe (Ireland)
    'eu-west-2.amazonaws.com',        # Europe (London)
    'eu-west-3.amazonaws.com',        # Europe (Paris)
    'eu-central-1.amazonaws.com',     # Europe (Frankfurt)
    'eu-central-2.amazonaws.com',     # Europe (Zurich)
    'eu-north-1.amazonaws.com',       # Europe (Stockholm)
    'eu-south-1.amazonaws.com',       # Europe (Milan)
    'eu-south-2.amazonaws.com',       # Europe (Spain)
    
    # Asia Pacific
    'ap-southeast-1.amazonaws.com',   # Asia Pacific (Singapore)
    'ap-southeast-2.amazonaws.com',   # Asia Pacific (Sydney)
    'ap-southeast-3.amazonaws.com',   # Asia Pacific (Jakarta)
    'ap-southeast-4.amazonaws.com',   # Asia Pacific (Melbourne)
    'ap-southeast-5.amazonaws.com',   # Asia Pacific (Malaysia)
    'ap-southeast-7.amazonaws.com',   # Asia Pacific (Thailand)
    'ap-northeast-1.amazonaws.com',   # Asia Pacific (Tokyo)
    'ap-northeast-2.amazonaws.com',   # Asia Pacific (Seoul)
    'ap-northeast-3.amazonaws.com',   # Asia Pacific (Osaka)
    'ap-south-1.amazonaws.com',       # Asia Pacific (Mumbai)
    'ap-south-2.amazonaws.com',       # Asia Pacific (Hyderabad)
    'ap-east-1.amazonaws.com',        # Asia Pacific (Hong Kong)
    
    # Middle East
    'me-south-1.amazonaws.com',       # Middle East (Bahrain)
    'me-central-1.amazonaws.com',     # Middle East (UAE)
    'il-central-1.amazonaws.com',     # Israel (Tel Aviv)
    
    # Africa
    'af-south-1.amazonaws.com',       # Africa (Cape Town)
    
    # China (special domains)
    'cn-north-1.amazonaws.com.cn',    # China (Beijing)
    'cn-northwest-1.amazonaws.com.cn', # China (Ningxia)
    
    # Legacy/Generic (keeping for backward compatibility)
    'amazonaws.com'
]


def get_all_aws_regions():
    """
    Extract region names from AWS_REGIONS constant
    Returns list of region names like ['us-east-1', 'eu-west-1', etc.]
    """
    regions = []
    for region_fqdn in AWS_REGIONS:
        # Skip the generic amazonaws.com entry
        if region_fqdn == 'amazonaws.com':
            continue
        
        # Extract region name from FQDN
        # Handle both .amazonaws.com and .amazonaws.com.cn domains
        if '.amazonaws.com.cn' in region_fqdn:
            region = region_fqdn.replace('.amazonaws.com.cn', '')
        elif '.amazonaws.com' in region_fqdn:
            region = region_fqdn.replace('.amazonaws.com', '')
        else:
            continue
            
        regions.append(region)
    
    return regions


def check_aws_credentials(access_key=None, secret_key=None):
    """
    Check if AWS credentials are available and valid
    Returns tuple: (has_creds, boto3_client_or_none)
    """
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
        from botocore.config import Config
        
        config = Config(
            read_timeout=5,
            connect_timeout=5,
            retries={'max_attempts': 1}
        )
        
        # Try to create client with provided credentials or default chain
        if access_key and secret_key:
            s3_client = boto3.client(
                's3',
                config=config,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
        else:
            s3_client = boto3.client('s3', config=config)
        
        # Test credentials by calling list_buckets
        s3_client.list_buckets()
        return True, s3_client
        
    except (NoCredentialsError, PartialCredentialsError):
        return False, None
    except ClientError as e:
        # If we get a ClientError, credentials are configured but might not have permissions
        # This is still "valid" credentials, just limited permissions
        return True, s3_client
    except Exception:
        return False, None


# Global set to collect unique redirect endpoints during S3 scanning
_s3_redirect_endpoints = set()

def print_s3_http_response(reply):
    """
    Parses the HTTP reply for S3 bucket enumeration (fallback method)
    """
    global _s3_redirect_endpoints
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Bucket doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Protected S3 Bucket'
        data['target'] = reply.url.replace('https://', '').replace('/index.html', '')
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        # Direct access to bucket
        data['msg'] = 'OPEN S3 BUCKET'
        data['target'] = reply.url.replace('https://', '').replace('/index.html', '')
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 301:
        # HTTP 301 = Redirect to correct regional endpoint
        # Parse XML response to get the correct endpoint and collect for later testing
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(reply.text)
            # Look for <Endpoint> tag in the XML
            endpoint_elem = root.find('Endpoint')
            if endpoint_elem is not None:
                correct_endpoint = endpoint_elem.text
                # Add to set of unique endpoints for later testing
                _s3_redirect_endpoints.add(correct_endpoint)
                # Log the redirect during scan
                data['msg'] = 'S3 Bucket Found (301 Redirect)'
                data['target'] = reply.url.replace('https://', '').replace('/index.html', '') + ' -> ' + correct_endpoint
                data['access'] = 'redirect'
                utils.fmt_output(data)
            else:
                # No endpoint found in XML, still report bucket existence
                data['msg'] = 'S3 Bucket Found (301 Redirect)'
                data['target'] = reply.url.replace('https://', '').replace('/index.html', '')
                data['access'] = 'redirect'
                utils.fmt_output(data)
        except Exception:
            # XML parsing failed, still report bucket existence
            data['msg'] = 'S3 Bucket Found (301 Redirect)'
            data['target'] = reply.url.replace('https://', '').replace('/index.html', '')
            data['access'] = 'redirect'
        utils.fmt_output(data)
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of S3 check...")
        return 'breakout'
    else:
        # Any other response might indicate bucket existence
        if reply.status_code not in [404]:
            data['msg'] = f'S3 Bucket Found (HTTP {reply.status_code})'
            data['target'] = reply.url.replace('https://', '').replace('/index.html', '')
            data['access'] = 'investigate'
            utils.fmt_output(data)
    return None


def test_s3_redirect_endpoints(verbose=False):
    """
    Test collected redirect endpoints to determine if they're open or protected
    """
    global _s3_redirect_endpoints
    
    if not _s3_redirect_endpoints:
        return
    
    if verbose:
        print(f"[*] Testing {len(_s3_redirect_endpoints)} unique redirect endpoints...")
    
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}
    
    for endpoint in _s3_redirect_endpoints:
        try:
            import requests
            follow_up_url = f'https://{endpoint}/'
            response = requests.get(follow_up_url, timeout=10)
            
            if response.status_code == 200:
                data['msg'] = 'OPEN S3 BUCKET'
                data['target'] = endpoint
                data['access'] = 'public'
                utils.fmt_output(data)
                if verbose:
                    print(f"[*] {endpoint}: OPEN (200 response)")
            elif response.status_code == 403:
                data['msg'] = 'Protected S3 Bucket'
                data['target'] = endpoint
                data['access'] = 'protected'
                utils.fmt_output(data)
                if verbose:
                    print(f"[*] {endpoint}: PROTECTED (403 response)")
            else:
                data['msg'] = f'S3 Bucket Found (HTTP {response.status_code})'
                data['target'] = endpoint
                data['access'] = 'investigate'
                utils.fmt_output(data)
                if verbose:
                    print(f"[*] {endpoint}: UNKNOWN ({response.status_code} response)")
                    
        except Exception as e:
            if verbose:
                print(f"[*] {endpoint}: ERROR (Exception: {e})")
    
    # Clear the set for future scans
    _s3_redirect_endpoints.clear()


def is_valid_s3_bucket_name(bucket_name):
    """
    Check if bucket name follows AWS S3 naming rules to avoid connection errors
    Returns True if valid for virtual hosted-style URLs
    """
    if not bucket_name:
        return False
    
    # Length check (3-63 characters)
    if len(bucket_name) < 3 or len(bucket_name) > 63:
        return False
    
    # Character check: only lowercase letters, numbers, and hyphens
    # Exclude underscores and dots to avoid DNS/SSL issues with virtual hosting
    import re
    if not re.match(r'^[a-z0-9-]+$', bucket_name):
        return False
    
    # Must start and end with letter or number
    if not (bucket_name[0].isalnum() and bucket_name[-1].isalnum()):
        return False
    
    # Cannot be formatted as IP address
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', bucket_name):
        return False
    
    return True


def check_s3_rate_limiting():
    """
    Check if user is being rate limited by AWS by testing a known public bucket.
    Returns True if rate limited, False if OK to proceed.
    """
    import requests
    
    test_url = "https://floqast.s3-us-west-2.amazonaws.com/"
    
    try:
        response = requests.get(test_url, timeout=10)
        
        # This bucket should return 200 with XML content
        if response.status_code == 200:
            return False  # Not rate limited
        elif response.status_code == 404:
            return True   # Likely rate limited
        else:
            # Other status codes might indicate rate limiting too
            return response.status_code in [429, 503, 403]
            
    except requests.exceptions.RequestException:
        # Connection issues might indicate rate limiting
        return True


def check_s3_buckets_http(names, threads, regions_to_check=None, verbose=False):
    """
    HTTP-based S3 bucket enumeration (fallback when no credentials)
    Tests multiple regional endpoint formats
    """
    global _s3_redirect_endpoints
    _s3_redirect_endpoints.clear()  # Start fresh for each scan
    
    print("[+] Checking for S3 buckets (HTTP method)")
    
    if verbose:
        print(f"[*] Using HTTP requests to check {len(names)} bucket name mutations")
        print(f"[*] Testing multiple S3 endpoint formats across regions")
        print(f"[*] No AWS credentials found - using HTTP fallback method")
        print(f"[*] Results: 200 = Open bucket, 403 = Protected bucket, 404 = Not found")
    
    # Check for AWS rate limiting before proceeding
    if verbose:
        print("[*] Checking for AWS rate limiting...")
    
    if check_s3_rate_limiting():
        print("")
        print("="*60)
        print("🚫 AWS RATE LIMITING DETECTED")
        print("="*60)
        print("")
        print("[!] Your IP address appears to be rate limited by AWS S3.")
        print("[!] The test request to a known public bucket returned an unexpected response.")
        print("")
        print("💡 SOLUTIONS:")
        print("   1. Wait 10-15 minutes and try again")
        print("   2. Use a VPN to change your IP address")
        print("   3. Use AWS credentials with --aws-access-key and --aws-secret-key")
        print("   4. Run the tool from a different network/location")
        print("")
        print("🔍 WHY THIS HAPPENS:")
        print("   - AWS automatically rate limits excessive HTTP requests")
        print("   - Previous enumeration tools or scans may have triggered limits")
        print("   - Your IP may be flagged for automated requests")
        print("")
        print("⚠️  Skipping S3 HTTP enumeration to avoid false negatives.")
        print("="*60)
        print("")
        return
    
    if verbose:
        print("[*] Rate limiting check passed - proceeding with S3 enumeration")

    # Use provided regions or default to key regions for HTTP checks
    if regions_to_check:
        regions = regions_to_check
    else:
        # Use a subset of major regions for HTTP to avoid excessive requests
        regions = ['us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 
                  'ap-southeast-1', 'ap-northeast-1']
    
    if verbose:
        print(f"[*] Testing across {len(regions)} regions: {', '.join(regions)}")
    
    start_time = utils.start_timer()

    # Filter out invalid bucket names to avoid connection errors
    valid_names = []
    invalid_names = []

    for name in names:
        if is_valid_s3_bucket_name(name):
            valid_names.append(name)
        else:
            invalid_names.append(name)
    
    if verbose and invalid_names:
        print(f"[*] Skipped {len(invalid_names)} invalid bucket names (contain dots/underscores/invalid chars)")
        if len(invalid_names) <= 10:
            print(f"[*] Invalid names: {', '.join(invalid_names)}")
        else:
            print(f"[*] Examples: {', '.join(invalid_names[:5])}...")
    
    if verbose:
        print(f"[*] Testing {len(valid_names)} valid bucket names (filtered from {len(names)} total)")
    
    candidates = []
    
    # Build all S3 URL variations for valid bucket names only
    for name in valid_names:
        # Standard S3 URLs (region-specific)
        for region in regions:
            candidates.append(f'{name}.s3.{region}.amazonaws.com/index.html')
            candidates.append(f'{name}.s3-{region}.amazonaws.com/index.html')
        
        # Legacy and special endpoints
        candidates.append(f'{name}.s3.amazonaws.com/index.html')  # Legacy
        candidates.append(f'{name}.s3-accelerate.amazonaws.com/index.html')  # Transfer acceleration

    if verbose:
        print(f"[*] Total URL combinations to test: {len(candidates)} (optimized - no connection errors expected)")

    # Use HTTP batch processing
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_s3_http_response,
                        threads=threads, verbose=verbose)
    
    # After main scan, test any redirect endpoints we collected
    test_s3_redirect_endpoints(verbose)
    
    utils.stop_timer(start_time)


def check_single_s3_bucket(bucket_name, s3_client, anonymous_client, verbose=False):
    """
    Check if a single S3 bucket exists using boto3
    Returns tuple: (bucket_name, status, access_level, region)
    """
    # Check for interrupt early
    if _interrupt_flag:
        return None
        
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    # Try with configured credentials first, then anonymous
    clients_to_try = [s3_client] if s3_client else []
    if anonymous_client:
        clients_to_try.append(anonymous_client)
    
    for client in clients_to_try:
        try:
            # Try to get bucket location to confirm existence (works globally)
            response = client.head_bucket(Bucket=bucket_name)
            
            # Bucket exists! Now get its actual region for region-specific operations
            bucket_region = 'us-east-1'  # Default fallback
            try:
                location_response = client.get_bucket_location(Bucket=bucket_name)
                bucket_region = location_response.get('LocationConstraint') or 'us-east-1'
            except Exception:
                if verbose:
                    print(f"[*] {bucket_name}: Could not determine region, using us-east-1")
            
            # Create region-specific client for content operations if needed
            region_client = client
            try:
                if client == s3_client:  # Authenticated client
                    from botocore.config import Config
                    config = Config(
                        read_timeout=10,
                        connect_timeout=10,
                        retries={'max_attempts': 1}
                    )
                    region_client = boto3.client('s3', config=config, region_name=bucket_region)
                else:  # Anonymous client
                    from botocore.config import Config
                    anonymous_config = Config(
                        signature_version=botocore.UNSIGNED,
                        read_timeout=10,
                        connect_timeout=10,
                        retries={'max_attempts': 1}
                    )
                    region_client = boto3.client('s3', config=anonymous_config, region_name=bucket_region)
            except Exception:
                # If region-specific client creation fails, use original global client
                region_client = client
            
            # Bucket exists, try to list objects to determine access level
            try:
                region_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                data['msg'] = 'OPEN S3 BUCKET'
                data['target'] = f'{bucket_name}.s3.{bucket_region}.amazonaws.com'
                data['access'] = 'public'
                utils.fmt_output(data)
                
                if verbose:
                    print(f"[*] {bucket_name}: OPEN (publicly accessible, region: {bucket_region})")
                    
                # Try to list some contents using region-specific client
                if verbose:
                    try:
                        response = region_client.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
                        if 'Contents' in response:
                            print(f"    Sample contents:")
                            for obj in response.get('Contents', [])[:5]:
                                print(f"      - {obj['Key']} ({obj['Size']} bytes)")
                            if len(response.get('Contents', [])) == 10:
                                print("      ... (more files)")
                    except Exception as e:
                        print(f"    Could not list contents: {e}")
                    
                return bucket_name, 'public', 'authenticated' if client == s3_client else 'anonymous'
                
            except ClientError as e:
                error_code = e.response['Error']['Code']

                if error_code == 'AccessDenied':
                    data['msg'] = 'Protected S3 Bucket'
                    data['target'] = f'{bucket_name}.s3.{bucket_region}.amazonaws.com'
                    data['access'] = 'protected'
                    utils.fmt_output(data)
                    if verbose:
                        print(f"[*] {bucket_name}: PROTECTED (exists but private, region: {bucket_region})")
                    return bucket_name, 'protected', 'authenticated' if client == s3_client else 'anonymous'
                else:
                    continue
                    
        except ClientError as e:
            error_code = e.response['Error']['Code']
            http_status_code = e.response['ResponseMetadata']['HTTPStatusCode']
            
            if error_code == 'NoSuchBucket' or http_status_code == 404:
                continue
            elif error_code in ['AccessDenied', 'Forbidden'] or http_status_code == 403:
                # Bucket exists but we can't access it (403 = bucket exists but private)
                # Try to get region if possible, but don't fail if we can't
                bucket_region = 'unknown'
                try:
                    location_response = client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location_response.get('LocationConstraint') or 'us-east-1'
                except Exception:
                    bucket_region = 'unknown'
                
                data['msg'] = 'Protected S3 Bucket'
                data['target'] = f'{bucket_name}.s3.amazonaws.com' if bucket_region == 'unknown' else f'{bucket_name}.s3.{bucket_region}.amazonaws.com'
                data['access'] = 'protected'
                utils.fmt_output(data)
                if verbose:
                    region_info = f', region: {bucket_region}' if bucket_region != 'unknown' else ''
                    print(f"[*] {bucket_name}: PROTECTED (exists but private{region_info})")
                return bucket_name, 'protected', 'authenticated' if client == s3_client else 'anonymous'
            elif error_code in ['SlowDown', 'RequestTimeTooSkewed']:
                if verbose:
                    print(f"[!] {bucket_name}: RATE LIMITED, skipping...")
                continue
            else:
                if verbose:
                    print(f"[*] {bucket_name}: ERROR ({error_code})")
                continue
        except Exception as ex:
            if verbose:
                print(f"[*] {bucket_name}: ERROR (Exception: {ex})")
            continue
    
    # If we get here, bucket was not found
    if verbose:
        print(f"[*] {bucket_name}: NOT FOUND")
    return None


def check_s3_buckets_boto3(names, threads, s3_client, verbose=False):
    """
    Checks for Amazon S3 buckets using boto3 AWS API calls (when credentials available)
    """
    print("[+] Checking for S3 buckets (boto3 method)")
    
    # Set up signal handler for better Ctrl+C handling
    def signal_handler(signum, frame):
        global _interrupt_flag
        _interrupt_flag = True
        print("\n[!] Interrupted by user (Ctrl+C)")
        print("[!] Stopping S3 bucket enumeration...")
        sys.exit(1)  # Force exit
    
    original_handler = signal.signal(signal.SIGINT, signal_handler)
    
    try:
        if verbose:
            print(f"[*] Using boto3 AWS API to check {len(names)} bucket name mutations")
            print(f"[*] Using authenticated AWS credentials for reliable bucket detection")
            print(f"[*] S3 bucket names are globally unique, but buckets are tied to specific regions")
            print(f"[*] Results: Open bucket, Protected bucket, Access denied, or Not found")

        # Start a counter to report on elapsed time
        start_time = utils.start_timer()
    
        # Create anonymous client as fallback for public bucket detection
        anonymous_client = None
        try:
            from botocore.config import Config
            anonymous_config = Config(
                signature_version=botocore.UNSIGNED,
                read_timeout=10,
                connect_timeout=10,
                retries={'max_attempts': 1}
            )
            anonymous_client = boto3.client(
                's3',
                config=anonymous_config,
                region_name='us-east-1'
            )
            if verbose:
                print("[*] Anonymous S3 client created as fallback for public bucket detection")
        except Exception as e:
            if verbose:
                print(f"[*] Could not create anonymous client: {e}")

        # Process bucket names with threading
        results = []
        executor = None
        
        try:
            executor = ThreadPoolExecutor(max_workers=threads)
            future_to_bucket = {
                executor.submit(check_single_s3_bucket, name, s3_client, anonymous_client, verbose): name 
                for name in names
            }
            
            # Use timeout on as_completed to make it more responsive to interrupts
            for future in as_completed(future_to_bucket, timeout=30):
                # Check for interrupt flag frequently
                if _interrupt_flag:
                    print("[!] Interrupt detected, stopping immediately...")
                    break
                    
                bucket_name = future_to_bucket[future]
                try:
                    result = future.result(timeout=1)  # Short timeout to be more responsive
                    if result:
                        results.append(result)
                except TimeoutError:
                    if verbose:
                        print(f"[*] {bucket_name}: TIMEOUT (request took too long)")
                except Exception as e:
                    if verbose:
                        print(f"[*] Error checking bucket {bucket_name}: {e}")
                        
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user (Ctrl+C)")
            print("[!] Stopping S3 bucket enumeration...")
            
            # Cancel all pending futures
            if executor:
                print("[!] Canceling pending requests...")
                for future in future_to_bucket:
                    future.cancel()
                
                # Shutdown executor immediately without waiting
                executor.shutdown(wait=False)
            return
        finally:
            # Ensure executor is properly closed
            if executor:
                executor.shutdown(wait=False)

        if verbose and results:
            print(f"[*] Found {len(results)} existing S3 buckets")
        elif verbose:
            print("[*] No S3 buckets found")

        # Stop the time
        utils.stop_timer(start_time)
        
    finally:
        # Restore original signal handler
        signal.signal(signal.SIGINT, original_handler)


def check_s3_buckets(names, threads, verbose=False, aws_access_key=None, aws_secret_key=None, regions_to_check=None):
    """
    Hybrid S3 bucket enumeration - boto3 if credentials available, HTTP fallback otherwise
    """
    # Check for AWS credentials first
    has_creds, s3_client = check_aws_credentials(aws_access_key, aws_secret_key)
    
    if has_creds:
        # Use boto3 method with credentials
        check_s3_buckets_boto3(names, threads, s3_client, verbose)
    else:
        # Fall back to HTTP method without credentials
        check_s3_buckets_http(names, threads, regions_to_check, verbose)


def check_awsapps(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for existence of AWS Apps
    (ie. WorkDocs, WorkMail, Connect, etc.)
    """
    data = {'platform': 'aws', 'msg': 'AWS App Found:', 'target': '', 'access': ''}

    print("[+] Checking for AWS Apps")
    
    if verbose:
        print(f"[*] AWS Apps use format: appname.{APPS_URL}")
        print(f"[*] Real example: mycompany-workdocs.{APPS_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS A record lookups")
        print(f"[*] DNS resolution = App exists (then check HTTPS access)")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()
    
    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    for name in names:
        candidates.append(f'{name}.{APPS_URL}')

    # AWS Apps use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)

    for name in valid_names:
        data['target'] = f'https://{name}'
        data['access'] = 'protected'
        utils.fmt_output(data)

    # Stop the timer
    utils.stop_timer(start_time)


def print_sqs_response(reply):
    """
    Parses the HTTP reply for SQS enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Queue doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'SQS Queue Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN SQS Queue'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 400:
        # Bad request might indicate queue exists but malformed request
        data['msg'] = 'SQS Queue Found (Bad Request - Check Permissions)'
        data['target'] = reply.url
        data['access'] = 'investigate'
        utils.fmt_output(data)
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of SQS check...")
        return 'breakout'
    else:
        # Any other response might indicate queue existence
        if reply.status_code not in [404]:
            data['msg'] = f'SQS Queue Found (HTTP {reply.status_code})'
            data['target'] = reply.url
            data['access'] = 'investigate'
            utils.fmt_output(data)
    return None


def check_sqs(names, threads, verbose=False, aws_account_id=None, selected_regions=None):
    """
    Checks for SQS queues using proper AWS Account ID and region format
    Requires AWS Account ID - will skip if not provided
    """
    if not aws_account_id:
        print("[!] SQS enumeration requires AWS Account ID (use --aws-account-id)")
        print("[!] Skipping SQS enumeration...")
        return
    
    print("[+] Checking for SQS queues")
    
    # Use selected regions or default to major regions for SQS
    if selected_regions:
        regions_to_check = selected_regions
    else:
        # Use major AWS regions for SQS enumeration
        regions_to_check = [
            'us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-central-1',
            'ap-southeast-1', 'ap-northeast-1', 'sa-east-1', 'ca-central-1'
        ]
    
    if verbose:
        print(f"[*] SQS uses format: https://sqs.region.amazonaws.com/{aws_account_id}/queue-name")
        print(f"[*] Real example: https://sqs.us-east-1.amazonaws.com/{aws_account_id}/mycompany-jobs")
        print(f"[*] Testing {len(names)} queue names across {len(regions_to_check)} regions")
        print(f"[*] Regions: {', '.join(regions_to_check)}")
        print(f"[*] Account ID: {aws_account_id}")
        print(f"[*] 200 = Open queue, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    # Build SQS URLs with proper format: sqs.region.amazonaws.com/account_id/queue_name
    for region in regions_to_check:
        for name in names:
            candidates.append(f'sqs.{region}.amazonaws.com/{aws_account_id}/{name}')
    
    if verbose:
        print(f"[*] Total URL combinations to test: {len(candidates)}")
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_sqs_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def check_eks(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for EKS clusters using DNS enumeration
    EKS clusters are typically accessed through custom domains and ALBs, not predictable HTTP endpoints
    """
    print("[+] Checking for EKS clusters")
    
    if verbose:
        print(f"[*] EKS clusters are accessed through custom domains and ALBs, not predictable URLs")
        print(f"[*] Looking for DNS records that might indicate EKS deployments:")
        print(f"[*] - Common patterns: cluster-name.company.com, eks-cluster.company.com")
        print(f"[*] - ALB endpoints: cluster-name-alb-123456789.region.elb.amazonaws.com")
        print(f"[*] - API server endpoints: cluster-name.cluster-id.region.eks.amazonaws.com")
        print(f"[*] Testing {len(names)} mutations via DNS A record lookups")
        print(f"[*] DNS resolution = EKS-related resource found (then investigate)")
    
    data = {'platform': 'aws', 'msg': 'EKS-related DNS Found:', 'target': '', 'access': ''}
    
    start_time = utils.start_timer()
    candidates = []
    
    # Build EKS-related domain patterns
    # Note: These are speculative patterns since EKS doesn't have predictable public domains
    # Real EKS enumeration would target known company domains
    for name in names:
        # Potential EKS API server patterns (these typically require authentication)
        candidates.append(f'{name}.eks.amazonaws.com')
        candidates.append(f'{name}-cluster.eks.amazonaws.com')
        candidates.append(f'{name}-prod.eks.amazonaws.com')
        candidates.append(f'{name}-dev.eks.amazonaws.com')
        candidates.append(f'{name}-staging.eks.amazonaws.com')
        
        # Potential ALB patterns that might expose EKS services
        # These would typically be in the format: name-alb-randomid.region.elb.amazonaws.com
        # But without knowing the random ID and region, we can't predict them
        
    if verbose:
        print(f"[*] Note: Real EKS enumeration typically targets known company domains")
        print(f"[*] This check looks for potential EKS-related AWS subdomains")
        print(f"[*] For comprehensive EKS discovery, also check company-specific domains")
    
    # Use DNS validation to check for existence
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    for name in valid_names:
        # Check if the resolved domain points to AWS infrastructure
        data['target'] = f'{name} (Investigate for EKS/ALB endpoints)'
        data['access'] = 'investigate'
        utils.fmt_output(data)
        
        if verbose:
            print(f"[*] Found DNS record: {name}")
            print(f"[*] This may indicate EKS infrastructure - investigate further")
    
    if verbose and not valid_names:
        print(f"[*] No EKS-related DNS records found in AWS domains")
        print(f"[*] Consider running DNS enumeration against known company domains")
    
    utils.stop_timer(start_time)


def print_workdocs_response(reply):
    """
    Parses the HTTP reply for WorkDocs enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 403:
        data['msg'] = 'WorkDocs Site Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN WorkDocs Site'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of check...")
        return 'breakout'
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")
    return None


def check_workdocs(names, threads, verbose=False):
    """
    Checks for WorkDocs sites
    """
    print("[+] Checking for WorkDocs sites")
    
    if verbose:
        print(f"[*] WorkDocs uses format: site.{WORKDOCS_URL}")
        print(f"[*] Real example: mycompany-docs.{WORKDOCS_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open site, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{WORKDOCS_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_workdocs_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def check_emr(names, threads, nameserver, nameserverfile=False, verbose=False, selected_regions=None):
    """
    Checks for EMR clusters using DNS validation across AWS regions
    """
    print("[+] Checking for EMR clusters")
    
    # Use selected regions or all AWS regions by default
    if selected_regions:
        regions_to_check = selected_regions
    else:
        # Default to ALL AWS regions for comprehensive EMR scanning
        regions_to_check = get_all_aws_regions()
    
    if verbose:
        print(f"[*] EMR clusters use format: clustername.emr.<region>.amazonaws.com")
        print(f"[*] Real example: mycompany-bigdata.emr.us-east-1.amazonaws.com")
        print(f"[*] Testing {len(names)} mutations across {len(regions_to_check)} regions")
        print(f"[*] Regions: {', '.join(regions_to_check)}")
        print(f"[*] DNS resolution = EMR cluster exists (typically VPC-internal)")
        print(f"[*] Note: EMR clusters are usually private and not publicly accessible")
    
    data = {'platform': 'aws', 'msg': 'EMR Cluster Found:', 'target': '', 'access': ''}
    
    start_time = utils.start_timer()
    candidates = []
    
    # EMR clusters use region-specific domains
    # Interleave regions so we test across regions early instead of exhausting one region first
    for name in names:
        for region in regions_to_check:
            candidates.append(f'{name}.emr.{region}.amazonaws.com')
    
    if verbose:
        print(f"[*] Total combinations to test: {len(candidates)}")
    
    # Use DNS validation instead of HTTP requests
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    for name in valid_names:
        data['target'] = f'{name} (Usually VPC-internal, check access)'
        data['access'] = 'investigate'
        utils.fmt_output(data)
    
    utils.stop_timer(start_time)


def print_elastic_beanstalk_response(reply):
    """
    Parses the HTTP reply for Elastic Beanstalk enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Application doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Elastic Beanstalk App Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN Elastic Beanstalk Application'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in [401, 429, 503]:
        data['msg'] = 'Elastic Beanstalk App Found (Service Issue)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of check...")
        return 'breakout'
    else:
        data['msg'] = f'Elastic Beanstalk Domain Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_elastic_beanstalk(names, threads, verbose=False):
    """
    Checks for Elastic Beanstalk applications
    """
    print("[+] Checking for Elastic Beanstalk applications")
    
    if verbose:
        print(f"[*] Elastic Beanstalk uses format: app.{ELASTIC_BEANSTALK_URL}")
        print(f"[*] Real example: mycompany-webapp.{ELASTIC_BEANSTALK_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open app, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{ELASTIC_BEANSTALK_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_elastic_beanstalk_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_cognito_response(reply):
    """
    Parses the HTTP reply for Cognito enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # User pool domain doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Cognito User Pool Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN Cognito User Pool Interface'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in [401, 429]:
        data['msg'] = 'Cognito User Pool Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of check...")
        return 'breakout'
    else:
        data['msg'] = f'Cognito Domain Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_cognito(names, threads, verbose=False, selected_regions=None):
    """
    Checks for Cognito user pools across AWS regions using proper domain format
    """
    print("[+] Checking for Cognito user pools")
    
    # Use selected regions or default to major regions for Cognito
    if selected_regions:
        regions_to_check = selected_regions
    else:
        # Use major AWS regions for Cognito enumeration
        regions_to_check = [
            'us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-central-1',
            'ap-southeast-1', 'ap-northeast-1', 'sa-east-1', 'ca-central-1'
        ]
    
    if verbose:
        print(f"[*] Cognito uses format: user_pool_domain.auth.<region>.{COGNITO_URL}")
        print(f"[*] Real example: mycompany-users.auth.us-east-1.{COGNITO_URL}")
        print(f"[*] Testing {len(names)} mutations across {len(regions_to_check)} regions")
        print(f"[*] Regions: {', '.join(regions_to_check)}")
        print(f"[*] 200 = Open pool, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    # Build Cognito URLs with proper region format
    for name in names:
        for region in regions_to_check:
            candidates.append(f'{name}.auth.{region}.{COGNITO_URL}')
    
    if verbose:
        print(f"[*] Total URL combinations to test: {len(candidates)}")
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_cognito_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_cloud9_response(reply):
    """
    Parses the HTTP reply for Cloud9 enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Environment doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Cloud9 Environment Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN Cloud9 Environment'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in [401, 429]:
        data['msg'] = 'Cloud9 Environment Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of check...")
        return 'breakout'
    else:
        data['msg'] = f'Cloud9 Domain Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_cloud9(names, threads, verbose=False):
    """
    Checks for Cloud9 environments
    """
    print("[+] Checking for Cloud9 environments")
    
    if verbose:
        print(f"[*] Cloud9 uses format: env.{CLOUD9_URL}")
        print(f"[*] Real example: mycompany-ide.{CLOUD9_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open environment, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{CLOUD9_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_cloud9_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def check_mx_records(domain, verbose=False):
    """
    Check if a domain has MX records pointing to AWS WorkMail infrastructure
    Returns True if AWS WorkMail MX records are found, False otherwise
    """
    try:
        import dns.resolver
        
        # Query MX records for the domain
        answers = dns.resolver.resolve(domain, 'MX')
        
        # Look for AWS WorkMail indicators in MX records
        aws_workmail_indicators = [
            'inbound-smtp',
            'amazonaws.com',
            'awsapps.com'
        ]
        
        mx_records = []
        has_aws_workmail = False
        
        for rdata in answers:
            mx_record = str(rdata.exchange).lower()
            mx_records.append(mx_record)
            
            # Check if any MX record indicates AWS WorkMail
            for indicator in aws_workmail_indicators:
                if indicator in mx_record:
                    has_aws_workmail = True
                    break
        
        if verbose and mx_records:
            print(f"[*] MX records for {domain}: {', '.join(mx_records)}")
        
        return has_aws_workmail, mx_records
        
    except ImportError:
        if verbose:
            print("[!] dnspython not installed. Install with: pip install dnspython")
        return False, []
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        if verbose:
            print(f"[*] No MX records found for {domain} or domain does not exist")
        return False, []
    except Exception as e:
        if verbose:
            print(f"[*] Error checking MX records for {domain}: {e}")
        return False, []


def check_workmail(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for WorkMail organizations using MX record enumeration of awsapps.com domains
    """
    print("[+] Checking for WorkMail organizations")
    
    if verbose:
        print(f"[*] WorkMail uses format: org.{APPS_URL}")
        print(f"[*] Real example: mycompany.{APPS_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS MX record lookups")
        print(f"[*] Looking for MX records pointing to AWS mail infrastructure")
        print(f"[*] Indicators: inbound-smtp, amazonaws.com, awsapps.com")
    
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}
    start_time = utils.start_timer()
    
    # Check MX records for each candidate domain
    found_count = 0
    for name in names:
        domain = f'{name}.{APPS_URL}'
        
        has_workmail, mx_records = check_mx_records(domain, verbose)
        
        if has_workmail:
            found_count += 1
            data['msg'] = 'WorkMail Organization Found'
            data['target'] = f'{domain} (MX: {", ".join(mx_records[:2])}{"..." if len(mx_records) > 2 else ""})'
            data['access'] = 'protected'
            utils.fmt_output(data)
            
            if verbose:
                print(f"[*] {domain}: WORKMAIL DETECTED")
                for mx in mx_records:
                    print(f"    MX Record: {mx}")
        elif verbose:
            print(f"[*] {domain}: No WorkMail indicators found")
    
    if verbose:
        print(f"[*] Found {found_count} WorkMail organizations out of {len(names)} tested")
    
    utils.stop_timer(start_time)


def print_api_service_response(reply, service_name):
    """
    Generic response handler for AWS API services
    Any HTTP response indicates the service domain exists
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Specific resource might not exist, but service domain might
    elif reply.status_code == 403:
        data['msg'] = f'{service_name} Service Found (Access Denied - Normal)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = f'ACCESSIBLE {service_name} Service'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in [401, 429]:
        data['msg'] = f'{service_name} Service Found (Auth/Rate Limited)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of check...")
        return 'breakout'
    else:
        # Any other response indicates service exists
        data['msg'] = f'{service_name} Service Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'investigate'
        utils.fmt_output(data)
    return None


def print_cloudtrail_response(reply):
    """
    Parses the HTTP reply for CloudTrail S3 log enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # CloudTrail logs don't exist for this path
    elif reply.status_code == 403:
        data['msg'] = 'CloudTrail Logs Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN CloudTrail Logs'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 301:
        # S3 redirect to correct regional endpoint
        data['msg'] = 'CloudTrail Logs Found (301 Redirect)'
        data['target'] = reply.url
        data['access'] = 'redirect'
        utils.fmt_output(data)
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of CloudTrail check...")
        return 'breakout'
    else:
        # Any other response might indicate log existence
        if reply.status_code not in [404]:
            data['msg'] = f'CloudTrail Logs Found (HTTP {reply.status_code})'
            data['target'] = reply.url
            data['access'] = 'investigate'
            utils.fmt_output(data)
    return None


def generate_cloudtrail_dates(days_back=14):
    """
    Generate date strings for the past N days in CloudTrail format (YYYY/MM/DD)
    """
    from datetime import datetime, timedelta
    
    dates = []
    for i in range(days_back):
        date = datetime.now() - timedelta(days=i)
        dates.append(date.strftime('%Y/%m/%d'))
    
    return dates


def check_cloudtrail(names, threads, verbose=False, aws_account_id=None, selected_regions=None):
    """
    Checks for CloudTrail logs in S3 buckets using proper AWS Account ID and region format
    CloudTrail logs are stored in S3 with format: AWSLogs/{account-id}/CloudTrail/{region}/{year}/{month}/{day}/
    Requires AWS Account ID - will skip if not provided
    """
    if not aws_account_id:
        print("[!] CloudTrail enumeration requires AWS Account ID (use --aws-account-id)")
        print("[!] Skipping CloudTrail enumeration...")
        return
    
    print("[+] Checking for CloudTrail logs in S3")
    
    # Use selected regions or default to major regions for CloudTrail
    if selected_regions:
        regions_to_check = selected_regions
    else:
        # Use major AWS regions for CloudTrail enumeration
        regions_to_check = [
            'us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-central-1',
            'ap-southeast-1', 'ap-northeast-1', 'sa-east-1', 'ca-central-1'
        ]
    
    # Generate date ranges for the past 14 days
    dates_to_check = generate_cloudtrail_dates(14)
    
    if verbose:
        print(f"[*] CloudTrail logs stored in S3 format: AWSLogs/{aws_account_id}/CloudTrail/region/YYYY/MM/DD/")
        print(f"[*] Real example: https://s3.amazonaws.com/AWSLogs/{aws_account_id}/CloudTrail/us-east-1/2023/12/15/")
        print(f"[*] Testing {len(names)} bucket names across {len(regions_to_check)} regions and {len(dates_to_check)} dates")
        print(f"[*] Regions: {', '.join(regions_to_check)}")
        print(f"[*] Account ID: {aws_account_id}")
        print(f"[*] Date range: {dates_to_check[0]} to {dates_to_check[-1]} (past 14 days)")
        print(f"[*] 200 = Open logs, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    # Build CloudTrail S3 URLs with proper format
    for name in names:
        # Test potential S3 bucket names that might contain CloudTrail logs
        for region in regions_to_check:
            for date in dates_to_check:
                # Try common CloudTrail bucket naming patterns
                # Format: https://s3.amazonaws.com/bucket-name/AWSLogs/account-id/CloudTrail/region/date/
                candidates.append(f's3.amazonaws.com/{name}-cloudtrail/AWSLogs/{aws_account_id}/CloudTrail/{region}/{date}/')
                candidates.append(f's3.amazonaws.com/{name}-cloudtrail-logs/AWSLogs/{aws_account_id}/CloudTrail/{region}/{date}/')
                candidates.append(f's3.amazonaws.com/{name}-audit/AWSLogs/{aws_account_id}/CloudTrail/{region}/{date}/')
                candidates.append(f's3.amazonaws.com/{name}-logs/AWSLogs/{aws_account_id}/CloudTrail/{region}/{date}/')
                candidates.append(f's3.amazonaws.com/{name}/AWSLogs/{aws_account_id}/CloudTrail/{region}/{date}/')
                # Also test common default bucket name
                candidates.append(f's3.amazonaws.com/{name}-{aws_account_id}-cloudtrail/AWSLogs/{aws_account_id}/CloudTrail/{region}/{date}/')
    
    if verbose:
        print(f"[*] Total URL combinations to test: {len(candidates)}")
        print(f"[*] Testing common CloudTrail bucket patterns: -cloudtrail, -cloudtrail-logs, -audit, -logs")
        print(f"[*] Also testing pattern: name-accountid-cloudtrail")
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_cloudtrail_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_iot_core_response(reply):
    """
    Parses the HTTP reply for IoT Core enumeration
    """
    return print_api_service_response(reply, 'IoT Core')


def check_iot_core(names, threads, verbose=False):
    """
    Checks for IoT Core resources
    """
    print("[+] Checking for IoT Core resources")
    
    if verbose:
        print(f"[*] IoT Core uses format: device.{IOT_CORE_URL}")
        print(f"[*] Real example: mycompany-sensors.{IOT_CORE_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open resource, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{IOT_CORE_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_iot_core_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_sagemaker_response(reply):
    """
    Parses the HTTP reply for SageMaker enumeration
    """
    return print_api_service_response(reply, 'SageMaker Endpoint')


def check_sagemaker(names, threads, verbose=False):
    """
    Checks for SageMaker endpoints
    """
    print("[+] Checking for SageMaker endpoints")
    
    if verbose:
        print(f"[*] SageMaker uses format: endpoint-name.{SAGEMAKER_URL}")
        print(f"[*] Real example: mycompany-model.{SAGEMAKER_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open endpoint, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{SAGEMAKER_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_sagemaker_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_quicksight_response(reply):
    """
    Parses the HTTP reply for QuickSight enumeration
    """
    return print_api_service_response(reply, 'QuickSight Dashboard')


def check_quicksight(names, threads, verbose=False):
    """
    Checks for QuickSight dashboards
    """
    print("[+] Checking for QuickSight dashboards")
    
    if verbose:
        print(f"[*] QuickSight uses format: dashboards.{QUICKSIGHT_URL}")
        print(f"[*] Real example: mycompany-dashboard.{QUICKSIGHT_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open dashboard, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}-dashboard.{QUICKSIGHT_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_quicksight_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


# Service mapping for user selections
SERVICE_FUNCTIONS = {
    's3': 'check_s3_buckets',
    'awsapps': 'check_awsapps',


    'sqs': 'check_sqs',
    'eks': 'check_eks',
    'workdocs': 'check_workdocs',
    'emr': 'check_emr',
    'elastic-beanstalk': 'check_elastic_beanstalk',
    'cognito': 'check_cognito',
    'cloud9': 'check_cloud9',
    'workmail': 'check_workmail',
    'cloudtrail': 'check_cloudtrail',
    'iot-core': 'check_iot_core',
    'sagemaker': 'check_sagemaker',
    'quicksight': 'check_quicksight'
}


def run_all(names, args):
    """
    Function is called by main program
    """
    print(BANNER)

    # Determine which services to run
    services_to_run = SERVICE_FUNCTIONS.keys()
    if hasattr(args, 'aws_services') and args.aws_services:
        services_to_run = args.aws_services
        print(f"[*] Running selected AWS services: {', '.join(services_to_run)}")
    else:
        print(f"[*] Running all {len(services_to_run)} AWS services")

    # Determine which regions to use
    regions_to_use = None
    if hasattr(args, 'aws_regions') and args.aws_regions:
        regions_to_use = args.aws_regions
        print(f"[*] Using selected AWS regions: {', '.join(regions_to_use)}")

    # Check for verbose mode
    verbose = hasattr(args, 'verbose') and args.verbose
    if verbose:
        print(f"[*] Verbose mode enabled - showing detailed enumeration process")

    # Execute selected services
    for service in services_to_run:
        if service in SERVICE_FUNCTIONS:
            func_name = SERVICE_FUNCTIONS[service]
            func = globals()[func_name]
            
            try:
                # Special handling for different function signatures
                if service == 'awsapps':
                    func(names, args.threads, args.nameserver, args.nameserverfile, verbose)
                elif service == 's3':  # S3 uses hybrid method
                    # Pass AWS credentials and regions to S3 function
                    aws_access_key = getattr(args, 'aws_access_key', None)
                    aws_secret_key = getattr(args, 'aws_secret_key', None)
                    func(names, args.threads, verbose, aws_access_key, aws_secret_key, regions_to_use)
                elif service in ['sqs', 'cloudtrail']:  # SQS and CloudTrail need account ID and regions
                    aws_account_id = getattr(args, 'aws_account_id', None)
                    func(names, args.threads, verbose, aws_account_id, regions_to_use)
                elif service in ['emr']:  # Services that need region support via DNS
                    func(names, args.threads, args.nameserver, args.nameserverfile, verbose, regions_to_use)
                elif service in ['cognito']:  # Services that need region support via HTTPS
                    func(names, args.threads, verbose, regions_to_use)
                elif service in ['eks', 'workmail']:  # Services that use DNS validation
                    func(names, args.threads, args.nameserver, args.nameserverfile, verbose)
                else:
                    # All services should support verbose - call with verbose parameter
                    func(names, args.threads, verbose)
            except Exception as e:
                print(f"    [!] ERROR in {service}: {e}")
                if verbose:
                    import traceback
                    traceback.print_exc()

    # Legacy function calls for backward compatibility when no service filtering
    if not hasattr(args, 'aws_services') or not args.aws_services:
        # All services run with original logic
        pass  # Already handled above
