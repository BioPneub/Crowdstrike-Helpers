#!/usr/bin/env python3

################################################################################################
####### API REQUIREMENTS ###########
# Identity Protection Entities: Read
# Identity Protection GraphQL: Write
####### API REQUIREMENTS ###########
#
####### Run Examples ########
# Within Falcon cloud US-1, Export list of all users which have duplicated passwords with other users in the domain
#python3 duplicatePWExport_IDP.py -c 1
#
# Within Falcon cloud US-1, Export list of all users which have duplicated passwords with other users in the domain, along with showing all the other users 
#python3 duplicatePWExport_IDP.py -c 1 -d
#
#
# For different Falcon cloud environments, use the appropriate option value for '-c #'
# '1' : US-1
# '2' : US-2
# '3' : EU-1
# '4' : GOV-1
####### Run Examples ########

####### CrowdStrike Scripts & Code License Agreement ########
# (c) Copyright CrowdStrike 2022-24
# By accessing or using this script, sample code, application programming interface, tools, and/or associated
# documentation (if any) (collectively, "Tools"), You (i) represent and warrant that You are entering into this
# Agreement on behalf of a company, organization or another legal entity ("Entity") that is currently a
# customer or partner of CrowdStrike, Inc. ("CrowdStrike"), and (ii) have the authority to bind such Entity
# and such Entity agrees to be bound by this Agreement.
#
# CrowdStrike grants Entity a non-exclusive, non-transferable, non-sublicensable, royalty free and limited
# license to access and use the Tools solely for Entity's internal business purposes and in accordance with
# its obligations under any agreement(s) it may have with CrowdStrike. Entity acknowledges and agrees that
# CrowdStrike and its licensors retain all right, title and interest in and to the Tools, and all intellectual
# property rights embodied therein, and that Entity has no right, title or interest therein except for the
# express licenses granted hereunder and that Entity will treat such Tools as CrowdStrike's confidential
# information.
#
# THE TOOLS ARE PROVIDED "AS-IS" WITHOUT WARRANTY OF ANY KIND, WHETHER EXPRESS, IMPLIED OR
# STATUTORY OR OTHERWISE. CROWDSTRIKE SPECIFICALLY DISCLAIMS ALL SUPPORT OBLIGATIONS AND
# ALL WARRANTIES, INCLUDING WITHOUT LIMITATION, ALL IMPLIED WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. IN NO EVENT SHALL CROWDSTRIKE
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE TOOLS,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
################################################################################################

import requests
import json
from datetime import datetime
from getpass import getpass
import csv
from optparse import OptionParser

def getToken(falconURL, apiClient, apiSecret, last_token=None, last_token_time=None):
  """ 
    Dedicated function to get/renew the auth/bearer token
    Returns a tuple to include the time the token was requested
  """

  # Let's configure the authorization request with the necessary data
  authurl = falconURL+'/oauth2/token'
  auth_headers = {
      "accept": "application/json",
      "Content-Type": "application/x-www-form-urlencoded"
  }
  authdata={
      "client_id":apiClient,
      "client_secret":apiSecret
  }

  if last_token_time and last_token:
    delta = datetime.utcnow() - last_token_time

    # Check if our token is older than 25 min
    if (delta.total_seconds() / 60) <= 25:
      return last_token, last_token_time
    else:
      print("[+] Refreshing Auth Token")

  # Get & decode bearer token
  r = requests.post(authurl,headers=auth_headers,params=authdata)
  token_time = datetime.utcnow()
  auth_string = r.content.decode('utf8')
  json_auth = json.loads(auth_string)
  bearer = json_auth['access_token']

  # Setup the header for future requests
  idp_header = {
      "Authorization": "Bearer " + bearer,
      "Content-Type": "application/json",
      "Accept": "application/json"
      }

  return idp_header, token_time

def queryData(falconURL, auth_header, runQuery):
    """ Function to run various queries and return all the node data """

    # Setup the IDP URL
    idp_url = falconURL+ "/identity-protection/combined/graphql/v1"
    
    print("[+] Running query now ...")
    pageTracker = True
    r = requests.post(idp_url, headers=auth_header, json={'query':runQuery})
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print("[!] Received an error: {}".format(r.text))
        raise SystemExit(e)

    results = json.loads(r.content.decode('utf-8'))
    data = results['data']
    entities = data['entities']
    nodes = entities['nodes']
    pageInfo = entities['pageInfo']

    # Check and see if there are multiple pages of results (more than the 1000 result limit)
    if pageInfo['hasNextPage']:
        endCursor = pageInfo['endCursor']
        
        # While loop to keep querying as long as there are more pages
        while pageTracker:
            endCursor = pageInfo['endCursor']

            # Configure new query using the value of 'endCursor' from the last query
            variables={}
            variables["after"] = endCursor
            r = requests.post(idp_url, headers=auth_header,json={'query':runQuery, 'variables':variables})
            results = json.loads(r.content.decode('utf-8'))
            data = results['data']
            entities = data['entities']
            nodes = nodes + entities['nodes']
            pageInfo = entities['pageInfo']
            if pageInfo['hasNextPage']:
                pageTracker = True
            else:
                pageTracker = False
    else:
        pageTracker = False
    
    return nodes
         
def exportCSV(nodeData, dupPWNames=False):
    """"Function to export all data to CSV based on the query type
    """

    # List to hold all CSV rows
    csv_complete_row = []

    # Prep CSV with header and write
    if dupPWNames:
        csv_header = ['Entity Type', 'samAccountName', 'Object SID (User/Endpoint) / Object GUID (Group)', 'Domain', 'Enabled', 'Most Recent Activity', 'Organizational Unit (OU)', 'Description', 'IsPrivileged', 'DuplicatePW Group', 'Total Similar Users', 'Users with Duplicated Password' ]
        print("[!] WARNING:")
        print("[!] \tYou've selected to display all users which have duplicate pws in the last column...")
        print("[!] \tExcel cells have a character limit of ~32767. Data in these cells may be truncated to fit the cell.")
        print("[!] \tUtilize column 'J' to filter on users with the same Duplicate Password GroupID to validate totals.")
        print("[+] Continuing...")
    else:
        csv_header = ['Entity Type', 'samAccountName', 'Object SID (User/Endpoint) / Object GUID (Group)', 'Domain', 'Enabled', 'Most Recent Activity', 'Organizational Unit (OU)', 'Description', 'IsPrivileged', 'DuplicatePW Group', 'Total Similar Users' ]
    csv_complete_row.append(csv_header)

    # Need to track all users by groupID for entering into the last column
    dupPWUsersDict = {}

    # Let's initially loop thru this data to build the dict we need
    for e in nodeData:
        for rf in e['riskFactors']:
            if rf['type'] == "DUPLICATE_PASSWORD": 
                try:
                    dupPWUsersDict[rf['groupId']].append(e['accounts'][0]['samAccountName'])
                except:
                    dupPWUsersDict[rf['groupId']] = []
                    dupPWUsersDict[rf['groupId']].append(e['accounts'][0]['samAccountName'])
            

    # Need a dict to track accounts with duplicate passwords using the groupId field
    srcUserIsPrivileged = False
    dupPWGroupId = ""
    for e in nodeData:
        for r in e['roles']:
            if len(r) > 0:
                if r['fullPath'].split("/")[0] == 'AdminAccountRole': # Only care about admin roles
                    srcUserIsPrivileged = True
        
        for rf in e['riskFactors']:
            if rf['type'] == "DUPLICATE_PASSWORD": 
                dupPWGroupId = rf['groupId']

        # Iterate through the groupID user list to create a string
        similarPWUsers = ', '.join(x for x in dupPWUsersDict[dupPWGroupId])

        # Excel cells have a character limit of 32,767, we will truncate if there is more data than this in the last column
        excelCharLimit = 32767
        if len(similarPWUsers) > excelCharLimit:
            similarPWUsers = similarPWUsers[:32600] # using lower value to be safe

        # Count how many users total
        totalSimilarUsers = len(dupPWUsersDict[dupPWGroupId])
        if dupPWNames:
            csv_complete_row.append([ e['type'], e['accounts'][0]['samAccountName'], e['accounts'][0]['objectSid'], e['accounts'][0]['domain'], e['accounts'][0]['enabled'], e['accounts'][0]['mostRecentActivity'], e['accounts'][0]['ou'], e['accounts'][0]['description'], srcUserIsPrivileged, dupPWGroupId, totalSimilarUsers, similarPWUsers ])
        else:
            csv_complete_row.append([ e['type'], e['accounts'][0]['samAccountName'], e['accounts'][0]['objectSid'], e['accounts'][0]['domain'], e['accounts'][0]['enabled'], e['accounts'][0]['mostRecentActivity'], e['accounts'][0]['ou'], e['accounts'][0]['description'], srcUserIsPrivileged, dupPWGroupId, totalSimilarUsers])

        srcUserIsPrivileged = False # Set back for next entity in loop

    print("[+] Writing CSV File to start...")
    # Set up CSV writing
    csv_file = "IdP_DuplicatePasswordUsers-Export_" + str(datetime.utcnow().strftime('%Y_%m_%d-%H-%M-%S')) + '.csv'
    f = open(csv_file, 'w', encoding='UTF8', newline='')
    csv_writer = csv.writer(f)

    # Only need this for CSV data
    for row in csv_complete_row:
        csv_writer.writerow(row)
        
    # Close the CSV File
    f.close()

    return True

def main():
    parser = OptionParser(usage="Usage: %prog [options]", version="%prog 1.0")
    parser.add_option("-c", "--cloud", dest = "cloud_opt", help="Select which Falcon cloud to use - '1': (US-1) '2': (US-2) '3': (EU-1) '4': (US-GOV-1)")
    parser.add_option("-C", "--client_id", dest="client_id", help="Optional: Define the API Client ID as a parameter")
    parser.add_option("-S", "--secret", dest="secret", help="Optional: Define the API Secret as a parameter")
    parser.add_option("-d", "--dup_pw_show_namee", dest="dupPWNames", action="store_true", default=False, help="If using -q 7 for duplicate passwords, this option will show the list of names in the last column. Default: False")
    (options, args) = parser.parse_args()


    ############################################################
    # Script Input Checks
    ############################################################
    # base api config
    # Need to handle for different clouds
    cloud_dict = {
        '1': 'https://api.crowdstrike.com',
        '2': 'https://api.us-2.crowdstrike.com',
        '3': 'https://api.eu-1.crowdstrike.com',
        '4': 'https://api.laggar.gcw.crowdstrike.com'
    }
    if options.cloud_opt:
        # Error check input
        if str(options.cloud_opt) not in ['1', '2', '3', '4']:
            print("Please enter only '1', '2', '3', or '4' when using the '-c' or '--cloud' parameters.")
            exit(0)
        baseurl = cloud_dict[str(options.cloud_opt)]
    else:
        cloud_select = input("Which Falcon cloud to use? \n1: (US-1) \n2: (US-2) \n3: (EU-1) \n4: (US-GOV-1) \nEnter Choice (1-4): ")
        # Error check input
        if str(cloud_select) not in ['1', '2', '3', '4']:
            print("Please enter only '1', '2', '3', or '4'. ")
            exit(0)
        baseurl = cloud_dict[str(cloud_select)]
    

    ############################################################
    # Get API Key
    ############################################################
    
    # Get API Key
    if not options.client_id:
        client=getpass('Client Key: ')
    else:
        client=options.client_id
    if not options.secret:
        secret=getpass('Secret Key: ')
    else:
        secret=options.secret

    # get & decode bearer token
    initial_token, initial_token_time = getToken(baseurl, client, secret)
    

    ############################################################
    # Query Section
    ############################################################
    ## Duplicate Password
    duplicatePwQuery = """
    query ($after: Cursor)
    {
        entities(
            types: [USER]
            riskFactorTypes: [DUPLICATE_PASSWORD]
            archived: false
            after: $after
            first: 1000) 
        {
            nodes {
                type
                secondaryDisplayName
              	primaryDisplayName
                accounts {
                    ... on ActiveDirectoryAccountDescriptor{
                        objectSid
                        samAccountName
                        domain
                        enabled
                        ou
                        description
                        mostRecentActivity
                      
                    }
                }
                riskFactors {
                    type
                    ... on DuplicatePasswordRiskEntityFactor {
                      groupId
                    }
                }
                roles {
                ... on AdminAccountRole {
                  fullPath
                }
              }
            }
            pageInfo {
                hasNextPage
                endCursor
            }
        }
    }
    """

    ############################################################
    # Do the work
    ############################################################

    print("[+] Querying for users with Duplicate Password risk")
    duplicatePasswordEntNodes = queryData(baseurl, initial_token, duplicatePwQuery)

    print("[+] Exporting Data...")
    exportCSV(duplicatePasswordEntNodes, options.dupPWNames)

    # Exit the script
    exit(0)

if __name__ == '__main__':
  main()