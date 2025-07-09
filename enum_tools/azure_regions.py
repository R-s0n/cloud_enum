"""
File used to track the DNS regions for Azure resources.
"""

# Some enumeration tasks will need to go through the complete list of
# possible DNS names for each region. You may want to modify this file to
# use the regions meaningful to you.
#
# Whatever is listed in the last instance of 'REGIONS' below is what the tool
# will use.


# Here is the list I get when running `az account list-locations` in Azure
# Powershell:
REGIONS = [
    # North America
    'eastus', 'eastus2', 'eastus3', 'centralus', 'northcentralus', 'southcentralus', 
    'westus', 'westus2', 'westus3', 'westcentralus',
    'canadacentral', 'canadaeast',
    'mexicocentral',
    
    # South America
    'brazilsouth', 'brazilsoutheast',
    'chilecentral',
    
    # Europe
    'northeurope', 'westeurope',
    'francecentral', 'francesouth',
    'germanywestcentral', 'germanynorth',
    'norwayeast', 'norwaywest',
    'switzerlandnorth', 'switzerlandwest',
    'uksouth', 'ukwest',
    'swedencentral', 'swedensouth',
    'polandcentral',
    'spaincentral',
    'italynorth',
    'austriaeast',
    'belgiumcentral',
    'denmarkeast',
    'finlandcentral',
    'greececentral',
    
    # Asia Pacific
    'eastasia', 'southeastasia',
    'australiaeast', 'australiasoutheast', 'australiacentral', 'australiacentral2',
    'japaneast', 'japanwest',
    'koreacentral', 'koreasouth',
    'centralindia', 'southindia', 'westindia',
    'indonesiacentral',
    'malaysiawest',
    'newzealandnorth',
    
    # Middle East
    'uaenorth', 'uaecentral',
    'qatarcentral',
    'israelcentral',
    
    # Africa
    'southafricanorth', 'southafricawest',
    
    # China (Special Administrative Regions)
    'chinaeast', 'chinaeast2', 'chinanorth', 'chinanorth2', 'chinanorth3',
    
    # Additional regions for government/sovereign clouds
    'usgovvirginia', 'usgovarizona', 'usgovtexas', 'usdodcentral', 'usdodeast',
    'germanycentral', 'germanynortheast'
]


