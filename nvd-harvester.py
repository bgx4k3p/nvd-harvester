from utils import utils
import time
import os
import pandas as pd
from datetime import datetime, timezone


def main():
    # ##########################################################################################
    utils.greeting('Download NIST NVD Database')
    # ###########################################################################################
    
    # VARs
    start = time.time()
    step = 0
    data_folder = 'data'
    src_data_file = f'{data_folder}/nvd-cve-kb.csv' 
    repo_local = f'{data_folder}/raw-nvd-json'
    cve_json_pattern = r'CVE-\d{4}-\d{4,}\.json$'
    drop_references = False    # OPTIONAL: This column contain very long strings and spills over if you are using the CSV in Excel
    drop_cpe = False           # OPTIONAL: This column contain very long strings and spills over if you are using the CSV in Excel
    keep_diff_csv = False      # OPTIONAL: Can be useful to track CVE changes overtime
    
    # API config
    """
    Per NVD, using an API key allows increased request limit up to 50 requests in 30s (0.6s delay).
    However, NVD still recommends sleeping for several seconds so that the requests are serviced 
    without interruption.
    """
    api_endpoint = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    apiKey = os.getenv('NVD_API_KEY')   # Obtain free NVD API key from here: https://nvd.nist.gov/developers/request-an-api-key
    attempts = 20                       # Number of retries before exit, the NVD API is very flaky
    retry_wait = 4                      # Seconds to wait before next retry
    max_workers = 4                     # Adjust this for API throttling
    max_sync_attempts = 2               # Maximum number of sync attempts during iss
    
    # Check if the NIST NVD API key is set
    if apiKey is None:
        print('NIST NVD API key is required!')
        exit(1)
    else:
        headers = {'apiKey': apiKey}

    # Create the data folders if don't exist
    os.makedirs(data_folder, exist_ok=True)
    
    # ##########################################################################################
    step += 1
    print(f'\n[{step}] Check CVE counts')
    # ##########################################################################################
    
    # Check latest CVE count in NVD API
    nvd_count, _ = utils.fetch_cve_count_and_chunk_size(api_endpoint, headers)
    
    # Check local CSV count
    if os.path.exists(src_data_file):
        csv_count = pd.read_csv(src_data_file, usecols=[0]).shape[0]
    else:
        csv_count = 0
    
    # Check local JSON files count
    if os.path.exists(repo_local):
        cve_file_list = utils.enumerate_files_in_folder(repo_local, cve_json_pattern)
        cve_file_count = len(cve_file_list)
    else:
        cve_file_count = 0

    # Check last successful NVD update, if any
    last_update_file = f'{repo_local}/last_update.json'
    last_update_timestamp, last_update_count = utils.last_update_read_info(last_update_file)
    
    print(f'\t[*] NVD: {nvd_count}, JSON: {cve_file_count}, CSV: {csv_count}, Last Sync: {last_update_count}')

    # ##########################################################################################
    step += 1
    print(f'\n[{step}] Fetch NVD data')
    # ##########################################################################################

    # Capture sync start timestamp
    sync_timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    need_full_sync = False
    
    # Already in sync
    if nvd_count == cve_file_count:
        print(f'\t[*] Already in sync with NVD')
    
    # Need to sync - determine method
    else:
        need_full_sync = (
            last_update_timestamp is None or
            cve_file_count == 0 or
            (last_update_count > 0 and cve_file_count < last_update_count)
        )
        
        # Attempt differential sync first
        if not need_full_sync and last_update_timestamp:
            print(f'\t[*] Attempting Differential sync from {last_update_timestamp}')
            
            for attempt in range(max_sync_attempts):
                # Set end timestamp for diff update
                end_timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                
                # Fetch differential updates
                utils.fetch_all_cves_threaded(
                    api_endpoint, headers, repo_local, attempts, retry_wait, 
                    max_workers, last_update_timestamp, end_timestamp
                )
                
                # Verify results
                cve_file_list = utils.enumerate_files_in_folder(repo_local, cve_json_pattern)
                cve_file_count = len(cve_file_list)
                if cve_file_count == nvd_count:
                    print(f'\t[*] Differential sync successful')
                    need_full_sync = False
                    break
                
                # Diff attempt failed, fall back to full sync
                if attempt == max_sync_attempts - 1:
                    print(f'\t[!] Differential sync failed after {max_sync_attempts} attempts')
                    print(f'\t[!] Falling back to full sync')
                    need_full_sync = True
                    break
                
                print(f'\t[!] Differential sync attempt {attempt+1} failed. Retrying...')
        
        # Full sync if needed or if diff sync failed
        if need_full_sync:
            reason = 'No previous data' if last_update_timestamp is None else \
                    'Empty repository' if cve_file_count == 0 else \
                    'Local CVE files missing' if cve_file_count < last_update_count else \
                    'Differential sync failed'
            
            print(f'\t[*] Performing Full sync. Reason: {reason}')
            
            # Fetch all CVEs
            utils.fetch_all_cves_threaded(api_endpoint, headers, repo_local, attempts, retry_wait, max_workers)
            
            # Verify results
            cve_file_list = utils.enumerate_files_in_folder(repo_local, cve_json_pattern)
            cve_file_count = len(cve_file_list)
            if cve_file_count == nvd_count:
                print(f'\t[*] Full sync successful - {cve_file_count} CVEs synced')
            else:
                print(f'\t[!] ERROR: Full sync failed - expected {nvd_count} CVEs, got {cve_file_count}')
                exit(1)
    
    # Update timestamp and count after success
    utils.last_update_write_info(last_update_file, sync_timestamp, nvd_count)
    
    # ##########################################################################################
    step += 1
    print(f'\n[{step}] Find CVE JSON file changes')
    # ##########################################################################################

    if csv_count == 0 or need_full_sync:
        print(f'\t[*] Processing All {cve_file_count} JSON files for full CSV build')
        full_csv_dump = True
        
    else:
        # Try differential update first
        full_csv_dump = False

        # Find timestamp of last CSV update
        t_csv_modified = utils.get_file_modified_time_utc(src_data_file)
        print(f'\t[*] Last CSV update: {t_csv_modified}')

        # Get list of CVE files changed since last CSV update
        changed_file_list = utils.get_modified_files_since(repo_local, t_csv_modified, file_pattern=cve_json_pattern, buffer_days=0)
        
        # Check if there are any changes
        if len(changed_file_list) == 0:

            if csv_count == nvd_count and cve_file_count == nvd_count:
                print(f'\t[*] No CSV update needed.')
                return
            else:
                print(f'\t[!] CVE counts mismatch! NVD: {nvd_count}, CSV: {csv_count}, JSON: {cve_file_count}' )
                print(f'\t[!] Rebuilding CSV to ensure consistency')
                full_csv_dump = True
        else:
            # Changes detected - use them for differential update
            print(f'\t[*] Found {len(changed_file_list)} modified CVE files since last CSV update')
    
    # ##########################################################################################
    step += 1
    print(f'\n[{step}] Parse CVE JSON files')
    # ##########################################################################################

    # Handle Diff changes in the master CSV file
    if not full_csv_dump and not need_full_sync:
        # Combine Changed CVE json files into a Dataframe
        df_nvd = utils.json_files_combine_concurrent(changed_file_list)
        
        # Parse CVE data and normalize
        df_nvd = utils.parse_cve_nvd(df_nvd)
    
        # Load the previous CSV file
        df_previous = pd.read_csv(src_data_file, dtype=str)

        # Set 'id' as the index to prevent duplicates
        df_previous['id'] = df_previous['cve']
        df_previous.set_index('id', drop=True, inplace=True)

        if keep_diff_csv:
            utils.write_df_csv(df_nvd, f'{data_folder}/nvd-diff-{t_csv_modified}.csv')

        # Drop CVEs from df_previous that are present in df_nvd (updated CVEs)
        df_previous = df_previous[~df_previous.index.isin(df_nvd.index)]

        # Merge rows in df_nvd (latest updates) with the remaining df_previous records, if not empty
        if not df_previous.empty:
            df_nvd = pd.concat([df_nvd, df_previous], axis=0)
    else:
        # Combine All CVE json files into a Dataframe
        df_nvd = utils.json_files_combine_concurrent(cve_file_list)
        
        # Parse CVE data and normalize
        df_nvd = utils.parse_cve_nvd(df_nvd)
    
    # OPTIONAL
    if drop_references:
        df_nvd.drop(columns=['referenceUrl'], axis=1, inplace=True)
    if drop_cpe:
        df_nvd.drop(columns=['cpe'], axis=1, inplace=True)
    
    # Final count check
    if nvd_count == df_nvd.shape[0]:
        print(f'\t[*] All {cve_file_count} CVE files processed successfully')
    else:
        print(f'\t[!] WARNING! NVD: {nvd_count}, CSV: {df_nvd.shape[0]}')
        print(f'\t[!] Investigate data issue!')
    
    # ##########################################################################################
    step += 1
    print(f'\n[{step}] Summary')
    # ##########################################################################################

    print(f'\t[*] NVD: {nvd_count}, JSON: {cve_file_count}, CSV: {df_nvd.shape[0]}, Last Sync: {last_update_count}')
    
    # ##########################################################################################
    step += 1
    print(f'\n[{step}] Write files')
    # ##########################################################################################

    print(f'\t[*] Writing: {src_data_file}')
    utils.write_df_csv(df_nvd, src_data_file, index=False)

    utils.runtime(start)

if __name__ == '__main__':
    main()
