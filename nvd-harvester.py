from utils.utils import *
import glob
import re
import time
import os
import pandas as pd
from datetime import datetime, timezone
import json


def main():
    # ##########################################################################################
    greeting('Download NIST NVD Database')
    # ###########################################################################################

    # VARs
    start = time.time()
    step = 0
    data_folder = 'data'
    csv_data_file = f'{data_folder}/nvd-cve-kb.csv'
    repo_local = f'{data_folder}/raw-nvd-json'
    drop_references = False      # OPTIONAL: This column contain very long strings and spills over if you open the CSV in Excel
    drop_cpe = False            # OPTIONAL: This column contain very long strings and spills over if you open the CSV in Excel
    keep_diff_csv = False       # OPTIONAL: Could be useful to track CVE changes overtime
    
    # API config
    """
    Per NVD, using an API key allows increased request limit up to 50 requests in 30s (0.6s delay).
    However, NVD still recommends sleeping for several seconds so that the requests are serviced 
    without interruption.
    """
    api_endpoint = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    apiKey = os.getenv('NVD_API_KEY')   # Obtain free NVD API key from here: https://nvd.nist.gov/developers/request-an-api-key
    attempts = 20                       # number of retries before exit, the NVD API is very flaky
    retry_wait = 4                      # seconds to wait before next retry
    max_workers = 4                     # adjust this for API throttling
    
    # Check if the NIST NVD API key is set
    if apiKey is None:
        print('NIST NVD API key is required!')
        exit(1)
    else:
        headers = {'apiKey': apiKey}

    # Create the folder if it doesn't exist
    os.makedirs(data_folder, exist_ok=True)
    
    # ##########################################################################################
    step += 1
    print(f'\n[{step}] Fetch NVD data')
    # ##########################################################################################
    
    last_update_key = 'last_update'
    last_update_file = f'{repo_local}/{last_update_key}.json'
    
    # Check if the local repository exists and has successful download, then fetch accordingly
    if not os.path.exists(repo_local) or not os.path.exists(last_update_file):
        print(f'\tInitial full NVD dump. It can take a while!')
        
        # Full dump from NVD
        fetch_all_cves_threaded(api_endpoint, headers, repo_local, attempts, retry_wait, max_workers)

    else:
        # Find timestamp of last successful NVD update
        last_update_timestamp = read_file_json(last_update_file).get('last_update', None)
        end_timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        if not last_update_timestamp:
            print(f'\tLast Update timestamp is missing!')
            exit(1)
            
        print(f'\n\tDiff NVD update between {last_update_timestamp} and {end_timestamp} UTC\n')
        
        # Diff update from NVD between last update and now
        fetch_all_cves_threaded(api_endpoint, headers, repo_local, attempts, retry_wait, max_workers, last_update_timestamp, end_timestamp)
    
    # Record the new timestamp after successful update in UTC
    new_update_timestamp = datetime.fromtimestamp(start, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    with open(last_update_file, 'w', encoding='utf-8') as f:
        json.dump({f"{last_update_key}": new_update_timestamp}, f, indent=4)
    
    # ##########################################################################################
    step += 1
    print(f'\n[{step}] Process CVE files')
    # ##########################################################################################

    if not os.path.exists(f'{csv_data_file}'):
        full_data_dump = True
        print(f'\t{csv_data_file} is missing!')
        
        # Enumerate all CVE JSON files in the local repo - Full dump
        cve_file_list = glob.glob(repo_local + '/**/CVE-*.json', recursive=True)
    else:
        full_data_dump = False

        # Find timestamp of last csv_data_file CSV update - Diff dump
        t_csv_modified = get_file_modified_time(csv_data_file)
        t_csv_readable = datetime.fromtimestamp(t_csv_modified).strftime('%Y-%m-%d %H:%M:%S')
        print(f'\n\tLast {csv_data_file.split("/")[-1]} update: {t_csv_readable}')

        # Get a list of all files changed since last CSV update. Add 1 day buffer if any sync issues
        changed_file_list = get_modified_files_since(repo_local, t_csv_modified, 0)

        # Filter only CVE json files
        file_pattern = re.compile(r'CVE-\d{4}-.*\.json$') 
        cve_file_list = [f for f in changed_file_list if file_pattern.search(f)]

        # Exit if no CVE changes
        if len(cve_file_list) == 0:
            print(f'\tNo new CVE data!')
            return

    print(f'\t{len(cve_file_list)} CVE updates.')
    
    # ##########################################################################################
    step += 1
    print(f'\n[{step}] Extract JSON Data')
    # ##########################################################################################

    # Combine CVE json files into a Dataframe
    df_nvd = json_files_combine_concurrent(cve_file_list)
    
    # Parse CVE data and normalize
    df_nvd = parse_cve_nvd(df_nvd)
    
    # Normalize timestamps
    df_nvd['published'] = df_nvd['published'].apply(convert_df_timestamp)
    df_nvd['lastModified'] = df_nvd['lastModified'].apply(convert_df_timestamp)
    
    # Handle Diff changes in tha master CSV file
    if not full_data_dump:
        # Load the previous CSV file
        df_previous = pd.read_csv(csv_data_file, dtype=str)

        # Set 'id' as the index to prevent duplicates
        df_previous['id'] = df_previous['cve']
        df_previous.set_index('id', drop=True, inplace=True)

        # Keep diff changes
        if keep_diff_csv:
            write_df_csv(df_nvd, f'{data_folder}/nvd-diff-{t_csv_modified}.csv')

        # Drop CVEs from df_previous that are present in df_nvd (updated CVEs)
        df_previous = df_previous[~df_previous.index.isin(df_nvd.index)]

        # Merge df_nvd (latest updates) with the remaining df_previous records
        df_nvd = pd.concat([df_nvd, df_previous])
    
    # OPTIONAL
    if drop_references:
        df_nvd.drop(columns=['referenceUrl'], inplace=True)
    if drop_cpe:
        df_nvd.drop(columns=['cpe'], inplace=True)

    # Summary
    print(f'\tTotal CVEs: {df_nvd.shape[0]}')

    # ##########################################################################################
    step += 1
    print(f'\n[{step}] Write files')
    # ##########################################################################################

    write_df_csv(df_nvd, csv_data_file, index=False)

    runtime(start)

if __name__ == '__main__':
    main()
