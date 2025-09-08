#!/usr/bin/env python
import sys  
import json
import argparse
import requests
import msal
import os 
import time
from os.path import expanduser
from ConfigParser import SafeConfigParser
from os import environ
import logging
import urlparse


configParser = SafeConfigParser()
DEFAULT_CREDENTIALS_FILE = os.path.join(expanduser("~"),'.mitsogo/credentials')
logger = logging.getLogger(__name__)
FORMAT = "%(asctime)s {} {} - %(levelname)s - %(message)s".format(os.uname()[1],os.environ.get('technician','SYSTEM'))
logging.basicConfig(format=FORMAT, level=os.environ.get('LOGLEVEL','INFO'))

client_id = None
value = None

try:
    from production import client_id, value
except Exception as e:
    logger.info(e)

def getconfig(profile,variable,environment,default=""):
    try:
        configParser.read(os.environ.get('SHARED_CREDENTIALS_FILE', DEFAULT_CREDENTIALS_FILE))
        value = configParser.get(profile, variable)
    except:
        value = os.environ.get(environment,default)
    return value

def create_token(client_id,value):
    if not client_id and not value:
        client_id = "6518ddf6-26e8-457a-a028-8e6c05083673"
        value = "DgN8Q~LwuGDyqunu3ffu1MbFjfy.33cefL.iPbJT"
    tenent = "adff86ed-b8a1-416f-9cc9-4fc89c26990b"
    authority = "https://login.microsoftonline.com/" + tenent
    scope = ["https://graph.microsoft.com/.default"]
    app = msal.ConfidentialClientApplication(client_id, authority=authority,client_credential=value)
    result = app.acquire_token_for_client(scopes=scope)
    if  result['access_token']:
        header = {'Authorization': 'Bearer ' + result['access_token'],"Content-Type": "application/json"}
        return header
    else:
        logger.error("Token generation failed")
        sys.exit(1)
   

def upload(endpoint,file_path,drive):
    file_data = open(file_path, 'rb')
    response=requests.put(endpoint+drive+"/"+file_path+":/content",headers=header, data=file_data).json()    
    logger.debug(response)
    return response
   
def session_upload(endpoint,file_path,drive):
    upload_session=requests.post(endpoint+drive+"/"+file_path+":/createUploadSession", headers=header).json()
    with open(file_path, 'rb') as f:
        total_file_size = os.path.getsize(file_path)
        chunk_size = 327680
        chunk_number = total_file_size//chunk_size
        chunk_leftover = total_file_size - chunk_size * chunk_number
        i = 0
        while i <= chunk_number:
            chunk_data = f.read(chunk_size)
            start_index = i*chunk_size
            end_index = start_index + chunk_size
            if i == chunk_number:
                end_index = start_index + chunk_leftover
            headers = {'Content-Length':'{}'.format(chunk_size),'Content-Range':'bytes {}-{}/{}'.format(start_index, end_index-1, total_file_size)}
            time.sleep(2)
            response = requests.put(upload_session['uploadUrl'], data=chunk_data, headers=headers).json()
            i += 1
        logger.debug(response)
        return response

def create_sharing_link(drive,item,emails,groups,file_type):
    try:
        email = None
        email_list = []
        if groups:
            modified_names = ["displayName eq '"+ name+"'" for name in groups.split(',')]
            url = "https://graph.microsoft.com/v1.0/groups?$filter={}&$select=id".format(" or ".join(modified_names))
            groups_response = [k['id'] for k in (requests.get(url,headers=header).json()['value'])]            
            for i in groups_response:
                 mem_response = requests.get("https://graph.microsoft.com/v1.0/groups/"+i+"/members?$select=mail",headers=header).json()
                 for j in mem_response['value']:
                        if j['mail'] and j['mail'] not in email_list:
                              email_list.append(str(j['mail']))
        if emails:
            email_list = emails.split(',') + email_list

        if email_list:
            email = [{"email": i } for i in email_list] 
        url = "{}/drives/{}/items/{}?$select=sharepointids".format(base_url,drive,item)
        response = requests.get(url,headers=header).json()
        item_url = "https://graph.microsoft.com/beta/sites/{}/lists/{}/items/{}/createLink".format(site_id,library_id,response['sharepointIds']['listItemId'])
        data = {
             "type": file_type,
             "scope": "users",
             "recipients": email,
             "retainInheritedPermissions":True
             }
        link_response = requests.post(item_url,headers=header,json=data).json()
        if link_response['link']['webUrl']:
             return link_response['link']['webUrl']
        else:
             logger.error(link_response['error']['message'])
             return False
   
    except Exception as e:
        return False

def download_file(sharepoint_url, headers , base_url,file_name):
    parsed_url = urlparse.urlparse(sharepoint_url)
    hostname = parsed_url.hostname
    path_parts = parsed_url.path.strip('/').split('/')
    try:
        site_index = path_parts.index('sites') + 1
        site_name = path_parts[site_index]
    except (ValueError, IndexError):
        logger.error("unable to extract site name from URL")
        sys.exit(1)
    site_api = "{}/sites/{}:/sites/{}".format(base_url,hostname, site_name)
    site_resp = requests.get(site_api, headers=headers)
    if site_resp.status_code != 200:
        logger.error("failed to get siteid: {} - {}".format(site_resp.status_code, site_resp.text))
        sys.exit(1)
    site_id = site_resp.json().get('id')

    drive_api = "{}/sites/{}/drives".format(base_url,site_id)
    drive_resp = requests.get(drive_api, headers=headers)
    if drive_resp.status_code != 200:
        logger.error("failed to get driveid: {} - {}".format(drive_resp.status_code, drive_resp.text))
        sys.exit(1)

    drives = drive_resp.json().get('value', [])
    if not drives:
        logger.error("no drives found")
        sys.exit(1)
    lib_name = path_parts[site_index + 1] if len(path_parts) > site_index + 1 else None
    drive_id = None
    for d in drives:
        if d.get('name') == lib_name:
            drive_id = d.get('id')
            break
    if not drive_id:
        drive_id = drives[0].get('id')
    relative_file_path = '/'.join(path_parts[site_index + 2:])
    if not relative_file_path:
        logger.error("unable to extract file path from URL")
        sys.exit(1)
    if not file_name:
        file_name = os.path.basename(relative_file_path)

    download_api = "{}/drives/{}/root:/{}:/content".format(base_url,drive_id, relative_file_path)
    response = requests.get(download_api, headers=headers, stream=True)
    if response.status_code == 200:
        with open(file_name, 'wb') as f:
            for chunk in response.iter_content(chunk_size=4096):
                if chunk:
                    f.write(chunk)
    else:
        logger.error("Download failed: {} - {}".format(response.status_code, response.text))
        sys.exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file_path',nargs='?', default=None,type=str,help='provide file path')
    parser.add_argument('--site',"--site",default = "Devops Hub",type=str,help='enter the site name')
    parser.add_argument('--library','--library',default="Documents",type=str,help='Name of the document library')
    parser.add_argument('--p_type','--p_type',type=str,default = 'blocksDownload',help='type of permission for sharing link',choices=['blocksDownload','view','edit'])
    parser.add_argument('--drive_path','--drive_path',type=str,default = '',help='provide drive path of sharepoint default root') 
    parser.add_argument('--link','--link',type=str,default = True,help='provide drive path of sharepoint default root')
    parser.add_argument('--mail','--mail',type=str,default=None,help="provide list of email to add permission for the file seperated by comma")
    parser.add_argument('--group','--group',type=str,default=None,help="provide list of groups to add permission seperated by comma")
    parser.add_argument('--download_url', help='provide the download url')
    parser.add_argument('--download_file', help='provide the file name to download')
    args = parser.parse_args()
    header = create_token(client_id,value)
    base_url = "https://graph.microsoft.com/v1.0"
    try: 
        if args.download_url:
            download_file(args.download_url,header,base_url,args.download_file)
        else:
            site_url = "{}/sites?search={}&&select=id".format(base_url,args.site)
            site_response = requests.get(site_url,headers=header).json()['value']
            
            if not site_response:
                 logger.error("{} site doesnot exist".format(args.site))
                 sys.exit(1)
            else:
                site_id = site_response[0]['id']
                list_url = "{}/sites/{}/lists?$filter=displayName eq '{}'&&select=id".format(base_url,site_id,args.library)
                response = requests.get(list_url,headers=header).json()['value']
                if not response:
                    logger.error("{} library doesnot exist".format(args.library))
                    sys.exit(2)
                else:
                    library_id = response[0]['id']
            endpoint = "{}/sites/{}/lists/{}/drive/root:/".format(base_url,site_id,library_id)
            file_path = os.path.basename(args.file_path)
            file_size = os.stat(file_path).st_size
            if file_size < 4100000:
                 result = upload(endpoint,file_path,args.drive_path)
            else:
                 result = session_upload(endpoint,file_path,args.drive_path)
            if result['webUrl']:
                 logger.info("Upload success")
                 if args.link:
                      sharing_link = create_sharing_link(result['parentReference']['driveId'],result['id'],args.mail,args.group,args.p_type)
                      if sharing_link:
                            logger.info("successfully generated sharing link")
                            print("sharing link:{}".format(sharing_link))
                      else:       
                            logger.info("critical:link generation failed")
                            sys.exit(2)
        
    except Exception as e:
        raise e
