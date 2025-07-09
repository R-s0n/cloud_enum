"""
AWS-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

from enum_tools import utils

BANNER = '''
++++++++++++++++++++++++++
      amazon checks
++++++++++++++++++++++++++
'''

# Known S3 domain names
S3_URL = 's3.amazonaws.com'
APPS_URL = 'awsapps.com'

# AWS Service Domain Patterns
ELB_URL = 'elb.amazonaws.com'
RDS_URL = 'rds.amazonaws.com'
DYNAMODB_URL = 'dynamodb.amazonaws.com'
CLOUDWATCH_URL = 'cloudwatch.amazonaws.com'
LAMBDA_URL = 'lambda.amazonaws.com'

SQS_URL = 'sqs.amazonaws.com'
SNS_URL = 'sns.amazonaws.com'
IAM_URL = 'iam.amazonaws.com'
SECRETS_MANAGER_URL = 'secretsmanager.amazonaws.com'
CLOUDFORMATION_URL = 'cloudformation.amazonaws.com'
APPSYNC_URL = 'appsync-api.amazonaws.com'
EKS_URL = 'eks.amazonaws.com'
EFS_URL = 'efs.amazonaws.com'
WORKSPACES_URL = 'workspaces.amazonaws.com'
ELASTIC_TRANSCODER_URL = 'elastictranscoder.amazonaws.com'
WORKDOCS_URL = 'workdocs.amazonaws.com'
EMR_URL = 'emr.amazonaws.com'

# New AWS Service Domain Patterns
ELASTIC_BEANSTALK_URL = 'elasticbeanstalk.com'
CLOUDTRAIL_URL = 'cloudtrail.amazonaws.com'
DATA_PIPELINE_URL = 'datapipeline.amazonaws.com'
REDSHIFT_URL = 'redshift.amazonaws.com'
REDSHIFT_SPECTRUM_URL = 'redshift.amazonaws.com'
KMS_URL = 'kms.amazonaws.com'
COGNITO_URL = 'amazoncognito.com'
CLOUD9_URL = 'aws.amazon.com'
IOT_CORE_URL = 'iot.amazonaws.com'
ELASTIC_INFERENCE_URL = 'elasticinference.amazonaws.com'
SSM_URL = 'ssm.amazonaws.com'
XRAY_URL = 'xray.amazonaws.com'
LIGHTSAIL_URL = 'lightsail.aws'
WORKMAIL_URL = 'workmail.amazonaws.com'
BATCH_URL = 'batch.amazonaws.com'
SNOWBALL_URL = 'snowball.amazonaws.com'
INSPECTOR_URL = 'inspector.amazonaws.com'
KINESIS_URL = 'kinesis.amazonaws.com'
STEP_FUNCTIONS_URL = 'states.amazonaws.com'
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


def print_s3_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif 'Bad Request' in reply.reason:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN S3 BUCKET'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
        utils.list_bucket_contents(reply.url)
    elif reply.status_code == 403:
        data['msg'] = 'Protected S3 Bucket'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of check...")
        return 'breakout'
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")

    return None


def check_s3_buckets(names, threads, verbose=False):
    """
    Checks for open and restricted Amazon S3 buckets
    """
    print("[+] Checking for S3 buckets")
    
    if verbose:
        print(f"[*] S3 buckets use format: bucketname.{S3_URL}")
        print(f"[*] Real example: company-backups.{S3_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTP GET requests")
        print(f"[*] 200 = Open bucket, 403 = Protected bucket, 404 = Not found")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        candidates.append(f'{name}.{S3_URL}')

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_s3_response,
                        threads=threads, verbose=verbose)

    # Stop the time
    utils.stop_timer(start_time)


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





def print_elb_response(reply):
    """
    Parses the HTTP reply for ELB enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 503:
        data['msg'] = 'ELB Found (Service Unavailable)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN ELB'
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


def check_elb(names, threads, verbose=False):
    """
    Checks for Elastic Load Balancer endpoints
    """
    print("[+] Checking for ELB endpoints")
    
    if verbose:
        print(f"[*] ELB uses format: elbname.{ELB_URL}")
        print(f"[*] Real example: my-app-prod.{ELB_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open ELB, 503 = Service unavailable, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{ELB_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_elb_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)





def check_rds(names, threads, nameserver, nameserverfile=False, verbose=False, selected_regions=None):
    """
    Checks for RDS instances using DNS validation across AWS regions
    """
    print("[+] Checking for RDS instances")
    
    # Use selected regions or all AWS regions by default
    if selected_regions:
        regions_to_check = selected_regions
    else:
        # Default to ALL AWS regions for comprehensive RDS scanning
        regions_to_check = get_all_aws_regions()
    
    if verbose:
        print(f"[*] RDS instances use format: dbname.<region>.{RDS_URL}")
        print(f"[*] Real example: mycompany-prod.us-west-2.{RDS_URL}")
        print(f"[*] Testing {len(names)} mutations across {len(regions_to_check)} regions")
        print(f"[*] Regions: {', '.join(regions_to_check)}")
        print(f"[*] DNS resolution = RDS exists (then check ports 3306/5432)")
    
    data = {'platform': 'aws', 'msg': 'RDS Instance Found:', 'target': '', 'access': ''}
    
    start_time = utils.start_timer()
    candidates = []
    
    # RDS instances use region-specific domains
    # Interleave regions so we test across regions early instead of exhausting one region first
    for name in names:
        for region in regions_to_check:
            candidates.append(f'{name}.{region}.{RDS_URL}')
    
    if verbose:
        print(f"[*] Total combinations to test: {len(candidates)}")
    
    # Use DNS validation instead of HTTP requests
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    for name in valid_names:
        data['target'] = f'{name} (Check DB ports: 3306/MySQL, 5432/PostgreSQL)'
        data['access'] = 'investigate'
        utils.fmt_output(data)
    
    utils.stop_timer(start_time)


def print_dynamodb_response(reply):
    """
    Parses the HTTP reply for DynamoDB enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 403:
        data['msg'] = 'DynamoDB Table Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN DynamoDB Table'
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


def check_dynamodb(names, threads, verbose=False):
    """
    Checks for DynamoDB tables
    """
    print("[+] Checking for DynamoDB tables")
    
    if verbose:
        print(f"[*] DynamoDB uses format: tablename.{DYNAMODB_URL}")
        print(f"[*] Real example: mycompany-users.{DYNAMODB_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open table, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{DYNAMODB_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_dynamodb_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)





def check_cloudwatch(names, threads, nameserver, nameserverfile=False, verbose=False, selected_regions=None):
    """
    Checks for CloudWatch resources using DNS validation across AWS regions
    """
    print("[+] Checking for CloudWatch resources")
    
    # Use selected regions or all AWS regions by default
    if selected_regions:
        regions_to_check = selected_regions
    else:
        # Default to ALL AWS regions for comprehensive CloudWatch scanning
        regions_to_check = get_all_aws_regions()
    
    if verbose:
        print(f"[*] CloudWatch uses format: resource.cloudwatch.<region>.amazonaws.com")
        print(f"[*] Real example: mycompany-logs.cloudwatch.us-west-2.amazonaws.com")
        print(f"[*] Testing {len(names)} mutations across {len(regions_to_check)} regions")
        print(f"[*] Regions: {', '.join(regions_to_check[:5])}{'...' if len(regions_to_check) > 5 else ''}")
        print(f"[*] DNS resolution = CloudWatch resource exists")
    
    data = {'platform': 'aws', 'msg': 'CloudWatch Resource Found:', 'target': '', 'access': ''}
    
    start_time = utils.start_timer()
    candidates = []
    
    # CloudWatch resources use region-specific domains
    # Interleave regions so we test across regions early instead of exhausting one region first
    for name in names:
        for region in regions_to_check:
            candidates.append(f'{name}.cloudwatch.{region}.amazonaws.com')
    
    if verbose:
        print(f"[*] Total combinations to test: {len(candidates)}")
    
    # Use DNS validation instead of HTTP requests
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    for name in valid_names:
        data['target'] = f'{name} (CloudWatch logs/metrics/alarms)'
        data['access'] = 'investigate'
        utils.fmt_output(data)
    
    utils.stop_timer(start_time)


def print_lambda_response(reply):
    """
    Parses the HTTP reply for Lambda enumeration
    NOTE: Lambda functions aren't directly HTTP accessible unless using Function URLs
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Function might not have HTTP endpoint
    elif reply.status_code == 403:
        data['msg'] = 'Lambda Function Found (Function URL Protected)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN Lambda Function URL'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    else:
        # Any other response indicates Lambda domain exists
        data['msg'] = f'Lambda Domain Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'investigate'
        utils.fmt_output(data)
    return None


def check_lambda(names, threads, verbose=False):
    """
    Checks for Lambda functions
    """
    print("[+] Checking for Lambda functions")
    
    if verbose:
        print(f"[*] Lambda uses format: function.{LAMBDA_URL}")
        print(f"[*] Real example: mycompany-processor.{LAMBDA_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open function URL, 403 = Auth required, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{LAMBDA_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_lambda_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)





def print_sqs_response(reply):
    """
    Parses the HTTP reply for SQS enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
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
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of check...")
        return 'breakout'
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")
    return None


def check_sqs(names, threads, verbose=False):
    """
    Checks for SQS queues
    """
    print("[+] Checking for SQS queues")
    
    if verbose:
        print(f"[*] SQS uses format: queue.{SQS_URL}")
        print(f"[*] Real example: mycompany-jobs.{SQS_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open queue, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{SQS_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_sqs_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_sns_response(reply):
    """
    Parses the HTTP reply for SNS enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 403:
        data['msg'] = 'SNS Topic Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN SNS Topic'
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


def check_sns(names, threads, verbose=False):
    """
    Checks for SNS topics
    """
    print("[+] Checking for SNS topics")
    
    if verbose:
        print(f"[*] SNS uses format: topic.{SNS_URL}")
        print(f"[*] Real example: mycompany-notifications.{SNS_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open topic, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{SNS_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_sns_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_iam_response(reply):
    """
    Parses the HTTP reply for IAM enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 403:
        data['msg'] = 'IAM Resource Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN IAM Resource'
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


def check_iam(names, threads, verbose=False):
    """
    Checks for IAM resources
    """
    print("[+] Checking for IAM resources")
    
    if verbose:
        print(f"[*] IAM uses format: resource.{IAM_URL}")
        print(f"[*] Real example: mycompany-role.{IAM_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open resource, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{IAM_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_iam_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_secrets_manager_response(reply):
    """
    Parses the HTTP reply for Secrets Manager enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 403:
        data['msg'] = 'Secrets Manager Secret Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN Secrets Manager Secret'
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


def check_secrets_manager(names, threads, verbose=False):
    """
    Checks for Secrets Manager secrets
    """
    print("[+] Checking for Secrets Manager secrets")
    
    if verbose:
        print(f"[*] Secrets Manager uses format: secret.{SECRETS_MANAGER_URL}")
        print(f"[*] Real example: mycompany-db-password.{SECRETS_MANAGER_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open secret, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{SECRETS_MANAGER_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_secrets_manager_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_cloudformation_response(reply):
    """
    Parses the HTTP reply for CloudFormation enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 403:
        data['msg'] = 'CloudFormation Stack Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN CloudFormation Stack'
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


def check_cloudformation(names, threads, verbose=False):
    """
    Checks for CloudFormation stacks
    """
    print("[+] Checking for CloudFormation stacks")
    
    if verbose:
        print(f"[*] CloudFormation uses format: stack.{CLOUDFORMATION_URL}")
        print(f"[*] Real example: mycompany-infrastructure.{CLOUDFORMATION_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open stack, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{CLOUDFORMATION_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_cloudformation_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_appsync_response(reply):
    """
    Parses the HTTP reply for AppSync enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 403:
        data['msg'] = 'AppSync API Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN AppSync API'
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


def check_appsync(names, threads, verbose=False):
    """
    Checks for AppSync APIs
    """
    print("[+] Checking for AppSync APIs")
    
    if verbose:
        print(f"[*] AppSync uses format: api.{APPSYNC_URL}")
        print(f"[*] Real example: mycompany-graphql.{APPSYNC_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open API, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{APPSYNC_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_appsync_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_eks_response(reply):
    """
    Parses the HTTP reply for EKS enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 403:
        data['msg'] = 'EKS Cluster Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN EKS Cluster'
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


def check_eks(names, threads, verbose=False):
    """
    Checks for EKS clusters
    """
    print("[+] Checking for EKS clusters")
    
    if verbose:
        print(f"[*] EKS uses format: cluster.{EKS_URL}")
        print(f"[*] Real example: mycompany-prod-cluster.{EKS_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open cluster, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{EKS_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_eks_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)





def check_efs(names, threads, nameserver, nameserverfile=False, verbose=False):
    """
    Checks for EFS file systems using DNS validation
    """
    print("[+] Checking for EFS file systems")
    
    if verbose:
        print(f"[*] EFS uses format: fsname.{EFS_URL}")
        print(f"[*] Real example: mycompany-shared.{EFS_URL}")
        print(f"[*] Testing {len(names)} mutations via DNS A record lookups")
        print(f"[*] DNS resolution = EFS exists (then check NFS port 2049)")
    
    data = {'platform': 'aws', 'msg': 'EFS File System Found:', 'target': '', 'access': ''}
    
    start_time = utils.start_timer()
    candidates = []
    
    # EFS uses DNS sub-domains. Check DNS resolution only.
    for name in names:
        candidates.append(f'{name}.{EFS_URL}')
    
    # Use DNS validation instead of HTTP requests
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    for name in valid_names:
        data['target'] = f'{name} (Check NFS port 2049)'
        data['access'] = 'investigate'
        utils.fmt_output(data)
    
    utils.stop_timer(start_time)


def print_workspaces_response(reply):
    """
    Parses the HTTP reply for WorkSpaces enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 403:
        data['msg'] = 'WorkSpaces Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN WorkSpaces'
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


def check_workspaces(names, threads, verbose=False):
    """
    Checks for WorkSpaces
    """
    print("[+] Checking for WorkSpaces")
    
    if verbose:
        print(f"[*] WorkSpaces uses format: workspace.{WORKSPACES_URL}")
        print(f"[*] Real example: mycompany-desktop.{WORKSPACES_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open workspace, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{WORKSPACES_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_workspaces_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_elastic_transcoder_response(reply):
    """
    Parses the HTTP reply for Elastic Transcoder enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 403:
        data['msg'] = 'Elastic Transcoder Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN Elastic Transcoder'
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


def check_elastic_transcoder(names, threads, verbose=False):
    """
    Checks for Elastic Transcoder pipelines
    """
    print("[+] Checking for Elastic Transcoder pipelines")
    
    if verbose:
        print(f"[*] Elastic Transcoder uses format: pipeline.{ELASTIC_TRANSCODER_URL}")
        print(f"[*] Real example: mycompany-video.{ELASTIC_TRANSCODER_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open pipeline, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{ELASTIC_TRANSCODER_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_elastic_transcoder_response,
                        threads=threads, verbose=verbose)
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


def print_emr_response(reply):
    """
    Parses the HTTP reply for EMR enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 403:
        data['msg'] = 'EMR Cluster Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN EMR Cluster'
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


def check_emr(names, threads, verbose=False):
    """
    Checks for EMR clusters
    """
    print("[+] Checking for EMR clusters")
    
    if verbose:
        print(f"[*] EMR uses format: cluster.{EMR_URL}")
        print(f"[*] Real example: mycompany-bigdata.{EMR_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open cluster, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{EMR_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_emr_response,
                        threads=threads, verbose=verbose)
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


def check_cognito(names, threads, verbose=False):
    """
    Checks for Cognito user pools
    """
    print("[+] Checking for Cognito user pools")
    
    if verbose:
        print(f"[*] Cognito uses format: pool.{COGNITO_URL}")
        print(f"[*] Real example: mycompany-users.{COGNITO_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open pool, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{COGNITO_URL}')
    
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


def print_lightsail_response(reply):
    """
    Parses the HTTP reply for Lightsail enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Instance doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'Lightsail Instance Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN Lightsail Instance'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in [401, 429, 503]:
        data['msg'] = 'Lightsail Instance Found (Service Issue)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of check...")
        return 'breakout'
    else:
        data['msg'] = f'Lightsail Domain Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_lightsail(names, threads, verbose=False):
    """
    Checks for Lightsail instances
    """
    print("[+] Checking for Lightsail instances")
    
    if verbose:
        print(f"[*] Lightsail uses format: instance.{LIGHTSAIL_URL}")
        print(f"[*] Real example: mycompany-server.{LIGHTSAIL_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open instance, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{LIGHTSAIL_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_lightsail_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_workmail_response(reply):
    """
    Parses the HTTP reply for WorkMail enumeration
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass  # Organization doesn't exist
    elif reply.status_code == 403:
        data['msg'] = 'WorkMail Organization Found (Access Denied)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 200:
        data['msg'] = 'OPEN WorkMail Organization'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in [401, 429]:
        data['msg'] = 'WorkMail Organization Found (Auth Required)'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif 'Slow Down' in reply.reason:
        print("[!] You've been rate limited, skipping rest of check...")
        return 'breakout'
    else:
        data['msg'] = f'WorkMail Domain Found (HTTP {reply.status_code})'
        data['target'] = reply.url
        data['access'] = 'unknown'
        utils.fmt_output(data)
    return None


def check_workmail(names, threads, verbose=False):
    """
    Checks for WorkMail organizations
    """
    print("[+] Checking for WorkMail organizations")
    
    if verbose:
        print(f"[*] WorkMail uses format: org.{WORKMAIL_URL}")
        print(f"[*] Real example: mycompany-mail.{WORKMAIL_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open organization, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{WORKMAIL_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_workmail_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)





def check_redshift(names, threads, nameserver, nameserverfile=False, verbose=False, selected_regions=None):
    """
    Checks for Redshift clusters using DNS validation across AWS regions
    """
    print("[+] Checking for Redshift clusters")
    
    # Use selected regions or all AWS regions by default
    if selected_regions:
        regions_to_check = selected_regions
    else:
        # Default to ALL AWS regions for comprehensive Redshift scanning
        regions_to_check = get_all_aws_regions()
    
    if verbose:
        print(f"[*] Redshift uses format: clustername.<region>.{REDSHIFT_URL}")
        print(f"[*] Real example: mycompany-dwh.us-west-2.{REDSHIFT_URL}")
        print(f"[*] Testing {len(names)} mutations across {len(regions_to_check)} regions")
        print(f"[*] Regions: {', '.join(regions_to_check)}")
        print(f"[*] DNS resolution = Redshift exists (then check port 5439)")
    
    data = {'platform': 'aws', 'msg': 'Redshift Cluster Found:', 'target': '', 'access': ''}
    
    start_time = utils.start_timer()
    candidates = []
    
    # Redshift clusters use region-specific domains
    # Interleave regions so we test across regions early instead of exhausting one region first
    for name in names:
        for region in regions_to_check:
            candidates.append(f'{name}.{region}.{REDSHIFT_URL}')
    
    if verbose:
        print(f"[*] Total combinations to test: {len(candidates)}")
    
    # Use DNS validation instead of HTTP requests
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads, verbose=verbose)
    
    for name in valid_names:
        data['target'] = f'{name} (Check port 5439/PostgreSQL)'
        data['access'] = 'investigate'
        utils.fmt_output(data)
    
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
    Parses the HTTP reply for CloudTrail enumeration
    """
    return print_api_service_response(reply, 'CloudTrail')


def check_cloudtrail(names, threads, verbose=False):
    """
    Checks for CloudTrail trails
    """
    print("[+] Checking for CloudTrail trails")
    
    if verbose:
        print(f"[*] CloudTrail uses format: trail.{CLOUDTRAIL_URL}")
        print(f"[*] Real example: mycompany-audit.{CLOUDTRAIL_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open trail, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{CLOUDTRAIL_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_cloudtrail_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_data_pipeline_response(reply):
    """
    Parses the HTTP reply for Data Pipeline enumeration
    """
    return print_api_service_response(reply, 'Data Pipeline')


def check_data_pipeline(names, threads, verbose=False):
    """
    Checks for Data Pipeline pipelines
    """
    print("[+] Checking for Data Pipeline pipelines")
    
    if verbose:
        print(f"[*] Data Pipeline uses format: pipeline.{DATA_PIPELINE_URL}")
        print(f"[*] Real example: mycompany-etl.{DATA_PIPELINE_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open pipeline, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{DATA_PIPELINE_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_data_pipeline_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_kms_response(reply):
    """
    Parses the HTTP reply for KMS enumeration
    """
    return print_api_service_response(reply, 'KMS')


def check_kms(names, threads, verbose=False):
    """
    Checks for KMS keys
    """
    print("[+] Checking for KMS keys")
    
    if verbose:
        print(f"[*] KMS uses format: key.{KMS_URL}")
        print(f"[*] Real example: mycompany-encryption.{KMS_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open key, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{KMS_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_kms_response,
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


def print_elastic_inference_response(reply):
    """
    Parses the HTTP reply for Elastic Inference enumeration
    """
    return print_api_service_response(reply, 'Elastic Inference')


def check_elastic_inference(names, threads, verbose=False):
    """
    Checks for Elastic Inference instances
    """
    print("[+] Checking for Elastic Inference instances")
    
    if verbose:
        print(f"[*] Elastic Inference uses format: instance.{ELASTIC_INFERENCE_URL}")
        print(f"[*] Real example: mycompany-ai.{ELASTIC_INFERENCE_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open instance, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{ELASTIC_INFERENCE_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_elastic_inference_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_ssm_response(reply):
    """
    Parses the HTTP reply for Systems Manager enumeration
    """
    return print_api_service_response(reply, 'Systems Manager (SSM)')


def check_ssm(names, threads, verbose=False):
    """
    Checks for Systems Manager resources
    """
    print("[+] Checking for Systems Manager resources")
    
    if verbose:
        print(f"[*] SSM uses format: parameter.{SSM_URL}")
        print(f"[*] Real example: mycompany-config.{SSM_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open resource, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{SSM_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_ssm_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_xray_response(reply):
    """
    Parses the HTTP reply for X-Ray enumeration
    """
    return print_api_service_response(reply, 'X-Ray')


def check_xray(names, threads, verbose=False):
    """
    Checks for X-Ray resources
    """
    print("[+] Checking for X-Ray resources")
    
    if verbose:
        print(f"[*] X-Ray uses format: trace.{XRAY_URL}")
        print(f"[*] Real example: mycompany-traces.{XRAY_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open resource, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{XRAY_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_xray_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_batch_response(reply):
    """
    Parses the HTTP reply for Batch enumeration
    """
    return print_api_service_response(reply, 'Batch')


def check_batch(names, threads, verbose=False):
    """
    Checks for Batch jobs and compute environments
    """
    print("[+] Checking for Batch jobs and compute environments")
    
    if verbose:
        print(f"[*] Batch uses format: job.{BATCH_URL}")
        print(f"[*] Real example: mycompany-processing.{BATCH_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open job, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{BATCH_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_batch_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_snowball_response(reply):
    """
    Parses the HTTP reply for Snowball enumeration
    """
    return print_api_service_response(reply, 'Snowball')


def check_snowball(names, threads, verbose=False):
    """
    Checks for Snowball jobs
    """
    print("[+] Checking for Snowball jobs")
    
    if verbose:
        print(f"[*] Snowball uses format: job.{SNOWBALL_URL}")
        print(f"[*] Real example: mycompany-migration.{SNOWBALL_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open job, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{SNOWBALL_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_snowball_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_inspector_response(reply):
    """
    Parses the HTTP reply for Inspector enumeration
    """
    return print_api_service_response(reply, 'Inspector')


def check_inspector(names, threads, verbose=False):
    """
    Checks for Inspector assessments
    """
    print("[+] Checking for Inspector assessments")
    
    if verbose:
        print(f"[*] Inspector uses format: assessment.{INSPECTOR_URL}")
        print(f"[*] Real example: mycompany-security.{INSPECTOR_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open assessment, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{INSPECTOR_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_inspector_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_kinesis_response(reply):
    """
    Parses the HTTP reply for Kinesis enumeration
    """
    return print_api_service_response(reply, 'Kinesis Stream')


def check_kinesis(names, threads, verbose=False):
    """
    Checks for Kinesis streams
    """
    print("[+] Checking for Kinesis streams")
    
    if verbose:
        print(f"[*] Kinesis uses format: streamname.{KINESIS_URL}")
        print(f"[*] Real example: mycompany-logs.{KINESIS_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open stream, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{KINESIS_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_kinesis_response,
                        threads=threads, verbose=verbose)
    utils.stop_timer(start_time)


def print_step_functions_response(reply):
    """
    Parses the HTTP reply for Step Functions enumeration
    """
    return print_api_service_response(reply, 'Step Functions')


def check_step_functions(names, threads, verbose=False):
    """
    Checks for Step Functions state machines
    """
    print("[+] Checking for Step Functions state machines")
    
    if verbose:
        print(f"[*] Step Functions uses format: state-machine-name.{STEP_FUNCTIONS_URL}")
        print(f"[*] Real example: mycompany-process.{STEP_FUNCTIONS_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open state machine, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}.{STEP_FUNCTIONS_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_step_functions_response,
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


def print_redshift_spectrum_response(reply):
    """
    Parses the HTTP reply for Redshift Spectrum enumeration
    """
    return print_api_service_response(reply, 'Redshift Spectrum')


def check_redshift_spectrum(names, threads, verbose=False):
    """
    Checks for Redshift Spectrum resources
    """
    print("[+] Checking for Redshift Spectrum resources")
    
    if verbose:
        print(f"[*] Redshift Spectrum uses format: spectrum.{REDSHIFT_SPECTRUM_URL}")
        print(f"[*] Real example: mycompany-spectrum.{REDSHIFT_SPECTRUM_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open resource, 403 = Access denied, 404 = Not found")
    
    start_time = utils.start_timer()
    
    candidates = []
    for name in names:
        candidates.append(f'{name}-spectrum.{REDSHIFT_SPECTRUM_URL}')
    
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_redshift_spectrum_response,
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
    'elb': 'check_elb',
    'rds': 'check_rds',
    'dynamodb': 'check_dynamodb',
    'cloudwatch': 'check_cloudwatch',
    'lambda': 'check_lambda',
    'sqs': 'check_sqs',
    'sns': 'check_sns',
    'iam': 'check_iam',
    'secrets-manager': 'check_secrets_manager',
    'cloudformation': 'check_cloudformation',
    'appsync': 'check_appsync',
    'eks': 'check_eks',
    'efs': 'check_efs',
    'workspaces': 'check_workspaces',
    'elastic-transcoder': 'check_elastic_transcoder',
    'workdocs': 'check_workdocs',
    'emr': 'check_emr',
    'elastic-beanstalk': 'check_elastic_beanstalk',
    'cognito': 'check_cognito',
    'cloud9': 'check_cloud9',
    'lightsail': 'check_lightsail',
    'workmail': 'check_workmail',
    'redshift': 'check_redshift',
    'cloudtrail': 'check_cloudtrail',
    'data-pipeline': 'check_data_pipeline',
    'kms': 'check_kms',
    'iot-core': 'check_iot_core',
    'elastic-inference': 'check_elastic_inference',
    'ssm': 'check_ssm',
    'xray': 'check_xray',
    'batch': 'check_batch',
    'snowball': 'check_snowball',
    'inspector': 'check_inspector',
    'kinesis': 'check_kinesis',
    'step-functions': 'check_step_functions',
    'sagemaker': 'check_sagemaker',
    'redshift-spectrum': 'check_redshift_spectrum',
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
                elif service in ['rds', 'redshift', 'cloudwatch']:  # Services that need region support
                    func(names, args.threads, args.nameserver, args.nameserverfile, verbose, regions_to_use)
                elif service in ['efs']:  # Other database services use DNS validation
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
