# cloud_enum

## Maintained Fork - Ars0n Framework v2

This fork is actively maintained by **rs0n** as part of [The Ars0n Framework v2](https://github.com/R-s0n/ars0n-framework-v2), a comprehensive bug bounty hunting framework. This version includes significant enhancements and expanded cloud service coverage.

<div align="center">
  <a href="https://www.youtube.com/watch?v=kAO0stO-hBg">
    <img src="thumbnail.png" width="600px" alt="Youtube Thumbnail" style="border-radius: 12px;">
  </a>
</div>

### Major Updates & Enhancements

**🚀 Massive Service Expansion:**
- **AWS**: Expanded from 2 to 39+ services (1850% increase)
- **Azure**: Expanded from 17 to 24+ services (41% increase) 
- **GCP**: Expanded from 5 to 15+ services (200% increase)

**🌍 Global Region Coverage:**
- **AWS**: Updated from 20 to 37+ regions with complete global coverage
- **Azure**: Expanded from 31 to 62+ regions including new European, Asian, and South American regions
- **GCP**: Updated from 19 to 45+ regions reflecting Google Cloud's infrastructure expansion

**⚡ Advanced Controls:**
- **Service Selection**: Target specific services with `--aws-services`, `--azure-services`, `--gcp-services`
- **Region Filtering**: Limit scans to specific regions with `--aws-regions`, `--azure-regions`, `--gcp-regions`
- **Discovery Commands**: Use `--show-services` and `--show-regions` to explore available options (no longer require `-k` flag)
- **Verbose Mode**: Comprehensive `-v` flag showing detailed enumeration process, FQDN formats, and testing methodology

**🎯 Enhanced Mutation & Discovery:**
- **Expanded Wordlist**: Upgraded `fuzz.txt` from 306 to 800+ cloud-focused terms (160% increase)
- **Enhanced Mutations**: Added underscore support increasing variations from 6 to 8 per keyword (33% more coverage)
- **Region-Aware Testing**: Proper region-specific enumeration for Cloud SQL, Spanner, RDS, Redshift

**🔧 Improved Response Handling:**
- Service-appropriate HTTP response interpretation across all cloud providers
- Improved rate limiting detection and handling
- Better authentication requirement detection with new access levels
- More accurate public vs. protected resource classification
- Fixed critical error handling for edge-case HTTP responses

### Connect with rs0n

- **GitHub**: [https://github.com/R-s0n](https://github.com/R-s0n)
- **YouTube**: [https://www.youtube.com/@rs0n_live](https://www.youtube.com/@rs0n_live)
- **Twitch**: [https://www.twitch.tv/rs0n_live](https://www.twitch.tv/rs0n_live)
- **LinkedIn**: [https://www.linkedin.com/in/harrison-richardson-rs0n-7a55bb158/](https://www.linkedin.com/in/harrison-richardson-rs0n-7a55bb158/)

*This enhanced version maintains full backward compatibility while providing powerful new capabilities for modern cloud reconnaissance.*

### 🔥 S3 Bucket Enumeration Enhancements

This fork includes significant improvements to S3 bucket detection and enumeration:

**🎯 Hybrid Enumeration Approach:**
- **Authenticated Mode**: When AWS credentials are available (via `aws configure`, environment variables, or `--aws-access-key`/`--aws-secret-key`), uses boto3 APIs for reliable bucket detection and content listing
- **HTTP Fallback Mode**: When no credentials are available, falls back to HTTP-based enumeration with intelligent redirect handling

**🚫 Eliminates False Positives:**
- **Proper 301 Redirect Handling**: No longer treats HTTP 301 redirects as "open buckets"
- **XML Response Parsing**: Extracts correct regional endpoints from S3 error responses
- **Follow-up Verification**: Tests redirect endpoints separately to determine true accessibility (200 = Open, 403 = Protected)

**📊 Enhanced Logging & Results:**
- **Redirect Tracking**: Logs 301 responses with `"access": "redirect"` and shows redirect paths (`source -> destination`)
- **Duplicate Elimination**: Collects unique redirect endpoints and tests them once, eliminating multiple duplicate results
- **Comprehensive Access Classification**: `public` (open), `protected` (exists but private), `redirect` (301 response), `investigate` (other status codes)

**⚡ Intelligent Optimizations:**
- **Rate Limiting Detection**: Proactively checks for AWS rate limiting before enumeration to avoid false negatives
- **Bucket Name Validation**: Filters invalid bucket names (dots, underscores, etc.) to prevent connection errors
- **Regional Endpoint Testing**: Tests multiple S3 endpoint formats across regions for comprehensive coverage

**📝 Verbose Mode Insights:**
```bash
# See detailed S3 enumeration process
./cloud_enum.py -k company --aws-services s3 -v

# Output includes:
# - Credential detection status (boto3 vs HTTP method)
# - Rate limiting checks
# - Bucket name validation results  
# - Regional endpoint testing
# - 301 redirect resolution process
# - Final accessibility determination
```

## Overview

Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud.

Currently enumerates the following:

**Amazon Web Services** (39+ services):
- **S3 Buckets with Advanced Detection**: Hybrid enumeration using both authenticated boto3 APIs and HTTP fallback. Proper 301 redirect handling eliminates false positives and provides accurate bucket accessibility classification.
- AWS Apps (WorkMail, WorkDocs, Connect, etc.)
- RDS, DynamoDB, CloudWatch
- Lambda, SQS, SNS, IAM
- Secrets Manager, CloudFormation, AppSync, EKS, EFS
- WorkSpaces, Elastic Transcoder, WorkDocs, EMR
- Elastic Beanstalk, Cognito, Cloud9, Lightsail
- WorkMail, Redshift, CloudTrail, Data Pipeline
- KMS, IoT Core, Systems Manager, X-Ray
- Batch, Snowball, Inspector, Kinesis, Step Functions
- SageMaker, Redshift Spectrum, QuickSight, and more

**Microsoft Azure** (24+ services):
- Storage Accounts (Blob, File, Queue, Table)
- Open Blob Storage Containers
- Key Vault, App Management
- Hosted Databases, Virtual Machines, Web Apps
- Cognitive Services, Active Directory, Service Bus
- API Management, AKS, Monitor, Logic Apps, Redis Cache
- Container Registry, Virtual Networks, CDN, Event Grid
- Data Lake Storage, Cognitive Search, IoT Hub

**Google Cloud Platform** (15+ services):
- Open / Protected GCP Buckets
- Firebase (Realtime Database, Applications)
- Google App Engine sites, Cloud Functions
- Pub/Sub, BigQuery, Spanner, Cloud SQL
- Vision API, Identity Platform, Firestore
- Datastore, Text-to-Speech, AI Platform

See it in action in [Codingo](https://github.com/codingo)'s video demo [here](https://www.youtube.com/embed/pTUDJhWJ1m0).

<img src="https://initstring.keybase.pub/host/images/cloud_enum.png" align="center"/>


## Usage

### Setup
Several non-standard libaries are required to support threaded HTTP requests and dns lookups. You'll need to install the requirements as follows:

```sh
pip3 install -r ./requirements.txt
```

### Running
The only required argument is at least one keyword. You can use the built-in fuzzing strings, but you will get better results if you supply your own with `-m` and/or `-b`.

You can provide multiple keywords by specifying the `-k` argument multiple times.

Keywords are mutated automatically using strings from `enum_tools/fuzz.txt` or a file you provide with the `-m` flag. Services that require a second-level of brute forcing (Azure Containers and GCP Functions) will also use `fuzz.txt` by default or a file you provide with the `-b` flag.

Let's say you were researching "somecompany" whose website is "somecompany.io" that makes a product called "blockchaindoohickey". You could run the tool like this:

```sh
./cloud_enum.py -k somecompany -k somecompany.io -k blockchaindoohickey
```

HTTP scraping and DNS lookups use 5 threads each by default. You can try increasing this, but eventually the cloud providers will rate limit you. Here is an example to increase to 10.

```sh
./cloud_enum.py -k keyword -t 10
```

For detailed output showing enumeration methodology and FQDN formats, use the verbose flag:

```sh
./cloud_enum.py -k keyword -v
```

### Advanced Usage

**AWS Credentials Support**: For enhanced S3 enumeration with authenticated access:

```sh
# Use AWS credentials from environment or ~/.aws/credentials (via 'aws configure')
./cloud_enum.py -k keyword --aws-services s3

# Or provide credentials directly
./cloud_enum.py -k keyword --aws-services s3 --aws-access-key AKIA... --aws-secret-key secret...

# With credentials, you get:
# - Reliable bucket detection using AWS APIs
# - Actual bucket content listings (when accessible)
# - Accurate region detection for each bucket
# - No rate limiting issues compared to HTTP methods
```

**Service Selection**: You can target specific cloud services instead of running all checks:

```sh
# AWS specific services
./cloud_enum.py -k keyword --aws-services s3,lambda,rds

# Azure specific services  
./cloud_enum.py -k keyword --azure-services storage-accounts,websites,databases,container-registry,iot-hub

# GCP specific services
./cloud_enum.py -k keyword --gcp-services gcp-buckets,app-engine,cloud-functions

# Mixed cloud targeting
./cloud_enum.py -k keyword --aws-services s3,cloudfront --azure-services storage-accounts,container-registry --gcp-services gcp-buckets
```

**Region Filtering**: You can limit scans to specific regions for faster, targeted enumeration:

```sh
# AWS regions
./cloud_enum.py -k keyword --aws-regions us-east-1,us-west-2,eu-west-1

# Azure regions
./cloud_enum.py -k keyword --azure-regions eastus,westus2,northeurope

# GCP regions (especially useful for Cloud Functions)
./cloud_enum.py -k keyword --gcp-regions us-central1,europe-west1,asia-east1

# Combined region and service filtering
./cloud_enum.py -k keyword --aws-services rds --aws-regions us-east-1,us-west-2
./cloud_enum.py -k keyword --gcp-services cloud-functions --gcp-regions us-central1,us-east1
```

**Discovery Commands**: Use these to see what services and regions are available:

```sh
# Show all available services (now includes 24+ Azure services)
./cloud_enum.py --show-services

# Show all available regions
./cloud_enum.py --show-regions
```

**Important Notes**: 
- Some resources (RDS, Redshift, Azure Containers, GCP Functions, Cloud SQL, Spanner) are discovered per-region. 
- RDS and Redshift use region-specific FQDNs: `instance.region.rds.amazonaws.com`
- GCP region-specific services use: `resource.region.googleapis.com` (Cloud SQL, Spanner)
- Cloud Functions use: `region-projectname.cloudfunctions.net`
- BigQuery and Pub/Sub are region-aware but don't include region in URL format
- The tool will validate your region/service selections and warn about invalid entries.
- Region filtering is most beneficial for RDS, Redshift, GCP Cloud Functions/SQL/Spanner, and Azure Virtual Machines.
- Use `--quickscan` to disable mutations and second-level scanning for faster results.

**Complete Usage Details**
```
usage: cloud_enum.py [-h] -k KEYWORD [-m MUTATIONS] [-b BRUTE] [-t THREADS] [-ns NAMESERVER] 
                     [-nsf NAMESERVERFILE] [-l LOGFILE] [-f FORMAT] [--disable-aws] [--disable-azure] 
                     [--disable-gcp] [-qs] [-v] [--aws-access-key AWS_ACCESS_KEY] [--aws-secret-key AWS_SECRET_KEY]
                     [--aws-regions AWS_REGIONS] [--azure-regions AZURE_REGIONS] [--gcp-regions GCP_REGIONS] 
                     [--aws-services AWS_SERVICES] [--azure-services AZURE_SERVICES] [--gcp-services GCP_SERVICES] 
                     [--show-regions] [--show-services]

Multi-cloud enumeration utility. All hail OSINT!

optional arguments:
  -h, --help            show this help message and exit
  -k KEYWORD, --keyword KEYWORD
                        Keyword. Can use argument multiple times.
  -kf KEYFILE, --keyfile KEYFILE
                        Input file with a single keyword per line.
  -m MUTATIONS, --mutations MUTATIONS
                        Mutations. Default: enum_tools/fuzz.txt
  -b BRUTE, --brute BRUTE
                        List to brute-force Azure container names. Default: enum_tools/fuzz.txt
  -t THREADS, --threads THREADS
                        Threads for HTTP brute-force. Default = 5
  -ns NAMESERVER, --nameserver NAMESERVER
                        DNS server to use in brute-force.
  -nsf NAMESERVERFILE, --nameserverfile NAMESERVERFILE
                        Path to the file containing nameserver IPs
  -l LOGFILE, --logfile LOGFILE
                        Will APPEND found items to specified file.
  -f FORMAT, --format FORMAT
                        Format for log file (text,json,csv - defaults to text)
  --disable-aws         Disable Amazon checks.
  --disable-azure       Disable Azure checks.
  --disable-gcp         Disable Google checks.
  -qs, --quickscan      Disable all mutations and second-level scans
  -v, --verbose         Show detailed enumeration process including FQDN formats and HTTP response meanings
  --aws-access-key AWS_ACCESS_KEY
                        AWS access key ID for authenticated S3 enumeration
  --aws-secret-key AWS_SECRET_KEY
                        AWS secret access key for authenticated S3 enumeration
  --aws-regions AWS_REGIONS
                        Comma-separated list of AWS regions to check
  --azure-regions AZURE_REGIONS
                        Comma-separated list of Azure regions to check
  --gcp-regions GCP_REGIONS
                        Comma-separated list of GCP regions to check
  --aws-services AWS_SERVICES
                        Comma-separated list of AWS services to check
  --azure-services AZURE_SERVICES
                        Comma-separated list of Azure services to check
  --gcp-services GCP_SERVICES
                        Comma-separated list of GCP services to check
  --show-regions        Display available regions for all cloud providers
  --show-services       Display available services for all cloud providers
```

## Thanks
So far, I have borrowed from:
- Some of the permutations from [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute/blob/master/permutations.txt)
