"""
Google-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

from enum_tools import utils
from enum_tools import gcp_regions

BANNER = '''
++++++++++++++++++++++++++
      google checks
++++++++++++++++++++++++++
'''

# Known GCP domain names
GCP_URL = 'storage.googleapis.com'
FBRTDB_URL = 'firebaseio.com'
APPSPOT_URL = 'appspot.com'
FUNC_URL = 'cloudfunctions.net'
FBAPP_URL = 'firebaseapp.com'
PUBSUB_URL = 'pubsub.googleapis.com'
BIGQUERY_URL = 'bigquery.googleapis.com'
SPANNER_URL = 'spanner.googleapis.com'
SQL_URL = 'sql.googleapis.com'
VISION_URL = 'vision.googleapis.com'
IDENTITY_URL = 'identityplatform.googleapis.com'
FIRESTORE_URL = 'firestore.googleapis.com'
DATASTORE_URL = 'datastore.googleapis.com'
TTS_URL = 'texttospeech.googleapis.com'
AI_URL = 'ai.googleapis.com'

# Hacky, I know. Used to store project/region combos that report at least
# one cloud function, to brute force later on
HAS_FUNCS = []


def print_bucket_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE BUCKET'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
        utils.list_bucket_contents(reply.url + '/')
    elif reply.status_code == 403:
        data['msg'] = 'Protected Google Bucket'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google Bucket'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_gcp_buckets(names, threads, verbose=False):
    """
    Checks for open and restricted Google Cloud buckets
    """
    print("[+] Checking for Google buckets")
    
    if verbose:
        print(f"[*] GCP buckets use format: bucketname.{GCP_URL}")
        print(f"[*] Real example: company-backups.{GCP_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTP GET requests")
        print(f"[*] 200 = Open bucket, 403 = Protected bucket, 404 = Not found")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        candidates.append(f'{GCP_URL}/{name}')

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_bucket_response,
                        threads=threads, verbose=verbose)

    # Stop the time
    utils.stop_timer(start_time)


def print_pubsub_response(reply):
    """
    Parses the HTTP reply of a Pub/Sub brute-force attempt
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE PUB/SUB'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 403:
        data['msg'] = 'Protected Google Pub/Sub'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google Pub/Sub'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_pubsub(names, threads, verbose=False):
    """
    Checks for Google Cloud Pub/Sub topics
    Note: Topics don't require region in URL, but subscriptions may be region-dependent
    """
    print("[+] Checking for Google Pub/Sub topics")
    
    if verbose:
        print(f"[*] Pub/Sub uses format: topicname.{PUBSUB_URL}")
        print(f"[*] Real example: company-notifications.{PUBSUB_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] Note: Topics don't require region in URL format")
        print(f"[*] 200 = Open topic, 403 = Protected topic, 404 = Not found")

    start_time = utils.start_timer()
    candidates = []

    for name in names:
        candidates.append(f'{name}.{PUBSUB_URL}')

    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_pubsub_response,
                        threads=threads, verbose=verbose)

    utils.stop_timer(start_time)


def print_bigquery_response(reply):
    """
    Parses the HTTP reply of a BigQuery brute-force attempt
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE BIGQUERY'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 403:
        data['msg'] = 'Protected Google BigQuery'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google BigQuery'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_bigquery(names, threads, verbose=False):
    """
    Checks for Google BigQuery datasets
    Note: Datasets are region-specific but region is not in URL format
    """
    print("[+] Checking for Google BigQuery datasets")
    
    if verbose:
        print(f"[*] BigQuery uses format: dataset.{BIGQUERY_URL}")
        print(f"[*] Real example: company-analytics.{BIGQUERY_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] Note: Datasets are region-specific but region is specified at creation, not in URL")
        print(f"[*] 200 = Open dataset, 403 = Protected dataset, 404 = Not found")

    start_time = utils.start_timer()
    candidates = []

    for name in names:
        candidates.append(f'{name}.{BIGQUERY_URL}')

    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_bigquery_response,
                        threads=threads, verbose=verbose)

    utils.stop_timer(start_time)


def print_spanner_response(reply):
    """
    Parses the HTTP reply of a Spanner brute-force attempt
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE SPANNER'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 403:
        data['msg'] = 'Protected Google Spanner'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google Spanner'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_spanner(names, threads, verbose=False, selected_regions=None):
    """
    Checks for Google Cloud Spanner instances across regions
    """
    print("[+] Checking for Google Spanner instances")
    
    # Use selected regions or all regions
    regions = selected_regions if selected_regions else gcp_regions.REGIONS
    
    if verbose:
        print(f"[*] Spanner uses format: instance.<region>.{SPANNER_URL}")
        print(f"[*] Real example: company-database.us-central1.{SPANNER_URL}")
        print(f"[*] Testing {len(names)} mutations across {len(regions)} regions")
        print(f"[*] Regions: {', '.join(regions[:5])}{'...' if len(regions) > 5 else ''}")
        print(f"[*] Note: Based on GCP examples showing region in Spanner instance URLs")
        print(f"[*] 200 = Open instance, 403 = Protected instance, 404 = Not found")

    start_time = utils.start_timer()
    candidates = []

    # Spanner instances are region-specific
    for name in names:
        for region in regions:
            candidates.append(f'{name}.{region}.{SPANNER_URL}')

    if verbose:
        print(f"[*] Total combinations to test: {len(candidates)}")

    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_spanner_response,
                        threads=threads, verbose=verbose)

    utils.stop_timer(start_time)


def print_sql_response(reply):
    """
    Parses the HTTP reply of a Cloud SQL brute-force attempt
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE CLOUD SQL'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 403:
        data['msg'] = 'Protected Google Cloud SQL'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google Cloud SQL'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_sql(names, threads, verbose=False, selected_regions=None):
    """
    Checks for Google Cloud SQL instances across regions
    """
    print("[+] Checking for Google Cloud SQL instances")
    
    # Use selected regions or all regions
    regions = selected_regions if selected_regions else gcp_regions.REGIONS
    
    if verbose:
        print(f"[*] Cloud SQL uses format: instance.<region>.{SQL_URL}")
        print(f"[*] Real example: company-prod-db.us-central1.{SQL_URL}")
        print(f"[*] Testing {len(names)} mutations across {len(regions)} regions")
        print(f"[*] Regions: {', '.join(regions[:5])}{'...' if len(regions) > 5 else ''}")
        print(f"[*] Note: Based on GCP examples showing region in SQL instance URLs")
        print(f"[*] 200 = Open instance, 403 = Protected instance, 404 = Not found")

    start_time = utils.start_timer()
    candidates = []

    # Cloud SQL instances are region-specific
    for name in names:
        for region in regions:
            candidates.append(f'{name}.{region}.{SQL_URL}')

    if verbose:
        print(f"[*] Total combinations to test: {len(candidates)}")

    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_sql_response,
                        threads=threads, verbose=verbose)

    utils.stop_timer(start_time)


def print_vision_response(reply):
    """
    Parses the HTTP reply of a Vision API brute-force attempt
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE VISION API'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 403:
        data['msg'] = 'Protected Google Vision API'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google Vision API'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_vision(names, threads, verbose=False):
    """
    Checks for Google Cloud Vision API endpoints
    """
    print("[+] Checking for Google Vision API endpoints")
    
    if verbose:
        print(f"[*] Vision API uses format: endpoint.{VISION_URL}")
        print(f"[*] Real example: company-vision.{VISION_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open endpoint, 403 = Protected endpoint, 404 = Not found")

    start_time = utils.start_timer()
    candidates = []

    for name in names:
        candidates.append(f'{name}.{VISION_URL}')

    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_vision_response,
                        threads=threads, verbose=verbose)

    utils.stop_timer(start_time)


def print_identity_response(reply):
    """
    Parses the HTTP reply of an Identity Platform brute-force attempt
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE IDENTITY PLATFORM'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 403:
        data['msg'] = 'Protected Google Identity Platform'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google Identity Platform'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_identity(names, threads, verbose=False):
    """
    Checks for Google Cloud Identity Platform services
    """
    print("[+] Checking for Google Identity Platform services")
    
    if verbose:
        print(f"[*] Identity Platform uses format: service.{IDENTITY_URL}")
        print(f"[*] Real example: company-auth.{IDENTITY_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open service, 403 = Protected service, 404 = Not found")

    start_time = utils.start_timer()
    candidates = []

    for name in names:
        candidates.append(f'{name}.{IDENTITY_URL}')

    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_identity_response,
                        threads=threads, verbose=verbose)

    utils.stop_timer(start_time)


def print_firestore_response(reply):
    """
    Parses the HTTP reply of a Firestore brute-force attempt
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE FIRESTORE'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 403:
        data['msg'] = 'Protected Google Firestore'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google Firestore'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_firestore(names, threads, verbose=False):
    """
    Checks for Google Firestore databases
    """
    print("[+] Checking for Google Firestore databases")
    
    if verbose:
        print(f"[*] Firestore uses format: database.{FIRESTORE_URL}")
        print(f"[*] Real example: company-docs.{FIRESTORE_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open database, 403 = Protected database, 404 = Not found")

    start_time = utils.start_timer()
    candidates = []

    for name in names:
        candidates.append(f'{name}.{FIRESTORE_URL}')

    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_firestore_response,
                        threads=threads, verbose=verbose)

    utils.stop_timer(start_time)


def print_datastore_response(reply):
    """
    Parses the HTTP reply of a Datastore brute-force attempt
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE DATASTORE'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 403:
        data['msg'] = 'Protected Google Datastore'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google Datastore'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_datastore(names, threads, verbose=False):
    """
    Checks for Google Cloud Datastore instances
    """
    print("[+] Checking for Google Datastore instances")
    
    if verbose:
        print(f"[*] Datastore uses format: instance.{DATASTORE_URL}")
        print(f"[*] Real example: company-entities.{DATASTORE_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open instance, 403 = Protected instance, 404 = Not found")

    start_time = utils.start_timer()
    candidates = []

    for name in names:
        candidates.append(f'{name}.{DATASTORE_URL}')

    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_datastore_response,
                        threads=threads, verbose=verbose)

    utils.stop_timer(start_time)


def print_tts_response(reply):
    """
    Parses the HTTP reply of a Text-to-Speech brute-force attempt
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE TEXT-TO-SPEECH'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 403:
        data['msg'] = 'Protected Google Text-to-Speech'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google Text-to-Speech'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_tts(names, threads, verbose=False):
    """
    Checks for Google Text-to-Speech services
    """
    print("[+] Checking for Google Text-to-Speech services")
    
    if verbose:
        print(f"[*] Text-to-Speech uses format: service.{TTS_URL}")
        print(f"[*] Real example: company-tts.{TTS_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open service, 403 = Protected service, 404 = Not found")

    start_time = utils.start_timer()
    candidates = []

    for name in names:
        candidates.append(f'{name}.{TTS_URL}')

    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_tts_response,
                        threads=threads, verbose=verbose)

    utils.stop_timer(start_time)


def print_ai_response(reply):
    """
    Parses the HTTP reply of an AI Platform brute-force attempt
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE AI PLATFORM'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 403:
        data['msg'] = 'Protected Google AI Platform'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google AI Platform'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_ai(names, threads, verbose=False):
    """
    Checks for Google AI Platform services
    """
    print("[+] Checking for Google AI Platform services")
    
    if verbose:
        print(f"[*] AI Platform uses format: service.{AI_URL}")
        print(f"[*] Real example: company-ml.{AI_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open service, 403 = Protected service, 404 = Not found")

    start_time = utils.start_timer()
    candidates = []

    for name in names:
        candidates.append(f'{name}.{AI_URL}')

    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_ai_response,
                        threads=threads, verbose=verbose)

    utils.stop_timer(start_time)


def print_fbrtdb_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE FIREBASE RTDB'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 401:
        data['msg'] = 'Protected Google Firebase RTDB'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 402:
        data['msg'] = 'Payment required on Google Firebase RTDB'
        data['target'] = reply.url
        data['access'] = 'disabled'
        utils.fmt_output(data)
    elif reply.status_code == 423:
        data['msg'] = 'The Firebase database has been deactivated.'
        data['target'] = reply.url
        data['access'] = 'disabled'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google Firebase RTDB'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_fbrtdb(names, threads, verbose=False):
    """
    Checks for Google Firebase RTDB
    """
    print("[+] Checking for Google Firebase Realtime Databases")
    
    if verbose:
        print(f"[*] Firebase RTDB uses format: dbname.{FBRTDB_URL}/.json")
        print(f"[*] Real example: company-app.{FBRTDB_URL}/.json")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open database, 401 = Auth required, 404 = Not found")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        # Firebase RTDB names cannot include a period. We'll exlcude
        # those from the global candidates list
        if '.' not in name:
            candidates.append(f'{name}.{FBRTDB_URL}/.json')

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_fbrtdb_response,
                        threads=threads,
                        redir=False, verbose=verbose)

    # Stop the time
    utils.stop_timer(start_time)
      
      
def print_fbapp_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE FIREBASE APP'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google Firebase App'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")

def check_fbapp(names, threads, verbose=False):
    """
    Checks for Google Firebase Applications
    """
    print("[+] Checking for Google Firebase Applications")
    
    if verbose:
        print(f"[*] Firebase Apps use format: appname.{FBAPP_URL}")
        print(f"[*] Real example: company-webapp.{FBAPP_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTPS GET requests")
        print(f"[*] 200 = Open app, 404 = Not found")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        # Firebase App names cannot include a period. We'll exlcude
        # those from the global candidates list
        if '.' not in name:
            candidates.append(f'{name}.{FBAPP_URL}')

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_fbapp_response,
                        threads=threads,
                        redir=False, verbose=verbose)

    # Stop the time
    utils.stop_timer(start_time)

def print_appspot_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif str(reply.status_code)[0] == 5:
        data['msg'] = 'Google App Engine app with a 50x error'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in (200, 302, 404):
        if 'accounts.google.com' in reply.url:
            data['msg'] = 'Protected Google App Engine app'
            data['target'] = reply.history[0].url
            data['access'] = 'protected'
            utils.fmt_output(data)
        else:
            data['msg'] = 'Open Google App Engine app'
            data['target'] = reply.url
            data['access'] = 'public'
            utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Google App Engine'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_appspot(names, threads, verbose=False):
    """
    Checks for Google App Engine sites running on appspot.com
    """
    print("[+] Checking for Google App Engine apps")
    
    if verbose:
        print(f"[*] App Engine uses format: projectname.{APPSPOT_URL}")
        print(f"[*] Real example: company-api.{APPSPOT_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTP GET requests")
        print(f"[*] 200 = Open app, 302 = App exists, 404 = Not found")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        # App Engine project names cannot include a period. We'll exlcude
        # those from the global candidates list
        if '.' not in name:
            candidates.append(f'{name}.{APPSPOT_URL}')

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_appspot_response,
                        threads=threads, verbose=verbose)

    # Stop the time
    utils.stop_timer(start_time)


def print_functions_response1(reply):
    """
    Parses the HTTP reply the initial Cloud Functions check

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 302:
        data['msg'] = 'Contains at least 1 Cloud Function'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
        HAS_FUNCS.append(reply.url)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Cloud Functions'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def print_functions_response2(reply):
    """
    Parses the HTTP reply from the secondary, brute-force Cloud Functions check

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if 'accounts.google.com/ServiceLogin' in reply.url:
        pass
    elif reply.status_code in (403, 401):
        data['msg'] = 'Auth required Cloud Function'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 405:
        data['msg'] = 'UNAUTHENTICATED Cloud Function (POST-Only)'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in (200, 404):
        data['msg'] = 'UNAUTHENTICATED Cloud Function (GET-OK)'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 429:
        data['msg'] = 'Rate-limited Cloud Function'
        data['target'] = reply.url
        data['access'] = 'rate-limited'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


# Service mapping for user selections
SERVICE_FUNCTIONS = {
    'gcp-buckets': 'check_gcp_buckets',
    'firebase-rtdb': 'check_fbrtdb',
    'firebase-apps': 'check_fbapp',
    'app-engine': 'check_appspot',
    'cloud-functions': 'check_functions',
    'pubsub': 'check_pubsub',
    'bigquery': 'check_bigquery',
    'spanner': 'check_spanner',
    'cloud-sql': 'check_sql',
    'vision-api': 'check_vision',
    'identity-platform': 'check_identity',
    'firestore': 'check_firestore',
    'datastore': 'check_datastore',
    'text-to-speech': 'check_tts',
    'ai-platform': 'check_ai'
}


def check_functions(names, brute_list, quickscan, threads):
    """
    Checks for Google Cloud Functions running on cloudfunctions.net

    This is a two-part process. First, we want to find region/project combos
    that have existing Cloud Functions. The URL for a function looks like this:
    https://[ZONE]-[PROJECT-ID].cloudfunctions.net/[FUNCTION-NAME]

    We look for a 302 in [ZONE]-[PROJECT-ID].cloudfunctions.net. That means
    there are some functions defined in that region. Then, we brute force a list
    of possible function names there.

    See gcp_regions.py to define which regions to check. The tool currently
    defaults to only 1 region, so you should really modify it for best results.
    """
    print("[+] Checking for project/zones with Google Cloud Functions.")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []
      
    # Pull the regions from a config file
    regions = gcp_regions.REGIONS

    print(f"[*] Testing across {len(regions)} regions defined in the config file")

    # Take each mutated keyword craft a url with the correct format
    for region in regions:
        candidates += [region + '-' + name + '.' + FUNC_URL for name in names]

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_functions_response1,
                        threads=threads,
                        redir=False)

    # Retun from function if we have not found any valid combos
    if not HAS_FUNCS:
        utils.stop_timer(start_time)
        return

    # Also bail out if doing a quick scan
    if quickscan:
        return

    # If we did find something, we'll use the brute list. This will allow people
    # to provide a separate fuzzing list if they choose.
    print(f"[*] Brute-forcing function names in {len(HAS_FUNCS)} project/region combos")

    # Load brute list in memory, based on allowed chars/etc
    brute_strings = utils.get_brute(brute_list)

    # The global was built in a previous function. We only want to brute force
    # project/region combos that we know have existing functions defined
    for func in HAS_FUNCS:
        print(f"[*] Brute-forcing {len(brute_strings)} function names in {func}")
        # Initialize the list of initial URLs to check. Strip out the HTTP
        # protocol first, as that is handled in the utility
        func = func.replace("http://", "")

        # Noticed weird behaviour with functions when a slash is not appended.
        # Works for some, but not others. However, appending a slash seems to
        # get consistent results. Might need further validation.
        candidates = [func + brute + '/' for brute in brute_strings]

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(candidates, use_ssl=False,
                            callback=print_functions_response2,
                            threads=threads, verbose=verbose)

    # Stop the time
    utils.stop_timer(start_time)


def check_functions_filtered(names, brute_list, quickscan, threads, selected_regions=None, verbose=False):
    """
    Checks for Google Cloud Functions with optional region filtering
    """
    print("[+] Checking for project/zones with Google Cloud Functions.")
    
    if verbose:
        print(f"[*] Cloud Functions use format: <region>-<project>.{FUNC_URL}")
        print(f"[*] Real example: us-central1-mycompany.{FUNC_URL}")
        print(f"[*] Testing {len(names)} mutations via HTTP GET requests")
        print(f"[*] 302 = Functions exist, 404 = Not found")

    start_time = utils.start_timer()
    candidates = []
      
    # Use selected regions or all regions
    regions = selected_regions if selected_regions else gcp_regions.REGIONS

    print(f"[*] Testing across {len(regions)} regions")

    # Take each mutated keyword craft a url with the correct format
    for region in regions:
        candidates += [region + '-' + name + '.' + FUNC_URL for name in names]

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_functions_response1,
                        threads=threads,
                        redir=False, verbose=verbose)

    # Return from function if we have not found any valid combos
    if not HAS_FUNCS:
        utils.stop_timer(start_time)
        return

    # Also bail out if doing a quick scan
    if quickscan:
        return

    # If we did find something, we'll use the brute list
    print(f"[*] Brute-forcing function names in {len(HAS_FUNCS)} project/region combos")

    # Load brute list in memory, based on allowed chars/etc
    brute_strings = utils.get_brute(brute_list)

    # The global was built in a previous function
    for func in HAS_FUNCS:
        print(f"[*] Brute-forcing {len(brute_strings)} function names in {func}")
        func = func.replace("http://", "")
        candidates = [func + brute + '/' for brute in brute_strings]

        utils.get_url_batch(candidates, use_ssl=False,
                            callback=print_functions_response2,
                            threads=threads, verbose=verbose)

    utils.stop_timer(start_time)


def run_all(names, args):
    """
    Function is called by main program
    """
    print(BANNER)

    # Determine which services to run
    services_to_run = SERVICE_FUNCTIONS.keys()
    if hasattr(args, 'gcp_services') and args.gcp_services:
        services_to_run = args.gcp_services
        print(f"[*] Running selected GCP services: {', '.join(services_to_run)}")
    else:
        print(f"[*] Running all {len(services_to_run)} GCP services")

    # Determine which regions to use
    selected_regions = None
    if hasattr(args, 'gcp_regions') and args.gcp_regions:
        selected_regions = args.gcp_regions
        print(f"[*] Using selected GCP regions: {', '.join(selected_regions)}")

    # Check for verbose mode
    verbose = hasattr(args, 'verbose') and args.verbose
    if verbose:
        print(f"[*] Verbose mode enabled - showing detailed enumeration process")

    # Execute selected services
    for service in services_to_run:
        if service in SERVICE_FUNCTIONS:
            # Special handling for different function signatures and region usage
            if service == 'gcp-buckets':
                check_gcp_buckets(names, args.threads, verbose)
            elif service == 'firebase-rtdb':
                check_fbrtdb(names, args.threads, verbose)
            elif service == 'firebase-apps':
                check_fbapp(names, args.threads, verbose)
            elif service == 'app-engine':
                check_appspot(names, args.threads, verbose)
            elif service == 'cloud-functions':
                # Use region filtering for Cloud Functions
                check_functions_filtered(names, args.brute, args.quickscan, 
                                       args.threads, selected_regions, verbose)
            elif service == 'pubsub':
                check_pubsub(names, args.threads, verbose)
            elif service == 'bigquery':
                check_bigquery(names, args.threads, verbose)
            elif service == 'spanner':
                check_spanner(names, args.threads, verbose, selected_regions)
            elif service == 'cloud-sql':
                check_sql(names, args.threads, verbose, selected_regions)
            elif service == 'vision-api':
                check_vision(names, args.threads, verbose)
            elif service == 'identity-platform':
                check_identity(names, args.threads, verbose)
            elif service == 'firestore':
                check_firestore(names, args.threads, verbose)
            elif service == 'datastore':
                check_datastore(names, args.threads, verbose)
            elif service == 'text-to-speech':
                check_tts(names, args.threads, verbose)
            elif service == 'ai-platform':
                check_ai(names, args.threads, verbose)
