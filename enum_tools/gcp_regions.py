"""
File used to track the DNS regions for GCP resources.
"""

# Some enumeration tasks will need to go through the complete list of
# possible DNS names for each region. You may want to modify this file to
# use the regions meaningful to you.
#
# Whatever is listed in the last instance of 'REGIONS' below is what the tool
# will use.

# Here is the comprehensive list of all GCP regions as of 2024/2025
# This represents Google Cloud's global infrastructure expansion
REGIONS = [
    # North America
    'us-central1',              # Iowa
    'us-east1',                 # South Carolina  
    'us-east4',                 # Northern Virginia
    'us-east5',                 # Columbus, Ohio
    'us-west1',                 # Oregon
    'us-west2',                 # Los Angeles
    'us-west3',                 # Salt Lake City
    'us-west4',                 # Las Vegas
    'us-south1',                # Dallas
    'northamerica-northeast1',  # Montreal
    'northamerica-northeast2',  # Toronto
    'northamerica-south1',      # Mexico
    
    # South America
    'southamerica-east1',       # São Paulo
    'southamerica-west1',       # Santiago
    
    # Europe
    'europe-central2',          # Warsaw
    'europe-north1',            # Finland
    'europe-north2',            # Stockholm
    'europe-southwest1',        # Madrid
    'europe-west1',             # Belgium
    'europe-west2',             # London
    'europe-west3',             # Frankfurt
    'europe-west4',             # Netherlands
    'europe-west6',             # Zurich
    'europe-west8',             # Milan
    'europe-west9',             # Paris
    'europe-west10',            # Berlin
    'europe-west12',            # Turin
    
    # Asia Pacific
    'asia-east1',               # Taiwan
    'asia-east2',               # Hong Kong
    'asia-northeast1',          # Tokyo
    'asia-northeast2',          # Osaka
    'asia-northeast3',          # Seoul
    'asia-south1',              # Mumbai
    'asia-south2',              # Delhi
    'asia-southeast1',          # Singapore
    'asia-southeast2',          # Jakarta
    'australia-southeast1',     # Sydney
    'australia-southeast2',     # Melbourne
    
    # Middle East
    'me-central1',              # Doha
    'me-central2',              # Dammam
    'me-west1',                 # Tel Aviv
    
    # Africa
    'africa-south1',            # Johannesburg
]
