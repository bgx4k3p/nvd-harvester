import os
import sys
import time
from datetime import datetime, timezone

import pandas as pd

from utils import utils


def record_sync_success(file_path, timestamp, count):
    """Commit successful ingestion and CSV publication, clearing resolved repair IDs."""
    extra = {key: utils.watermark_read(file_path, key) for key in
             (utils.LOCAL_SCAN_KEY, utils.FULL_REPAIR_ATTEMPT_KEY)}
    extra[utils.RUN_COMPLETED_KEY] = time.time()
    if not utils.last_update_write_info(file_path, timestamp, count,
                                        extra=extra):
        print('\t[!] Could not record sync completion; the next run will retry.')
        sys.exit(1)


def checkpoint_local_edits(repo, pattern, state_file, pending):
    """Consume our write journal only after independently checkpointing the edit scan."""
    os.makedirs(repo, exist_ok=True)
    journal = utils.LocalWriteJournal(f'{repo}/local_writes.jsonl')
    scan_started = time.time_ns()
    cutoff = utils.watermark_read(state_file, utils.LOCAL_SCAN_KEY)
    if cutoff is None:
        last_success = utils.watermark_read(state_file, utils.RUN_COMPLETED_KEY)
        cutoff = int(last_success * 1_000_000_000) if last_success else None
    edited = utils.find_external_edits(
        utils.enumerate_files_in_folder(repo, pattern), cutoff, journal.read())
    pending.update(os.path.basename(path).removesuffix('.json') for path in edited)
    save_pending_repairs(state_file, pending, **{utils.LOCAL_SCAN_KEY: scan_started})
    journal.reset()
    return journal


def save_pending_repairs(state_file, pending, **extra):
    if not utils.watermark_merge(state_file, **{utils.PENDING_REPAIRS_KEY: sorted(pending)}, **extra):
        raise utils.DownloadError('Could not checkpoint local repair state')


def full_repair(state_file, *args, interval_seconds, initializing=False, **kwargs):
    """Bound repeat full pulls after a successful sync, allowing initialization to retry."""
    now = time.time()
    last_attempt = utils.watermark_read(state_file, utils.FULL_REPAIR_ATTEMPT_KEY)
    if not initializing and last_attempt is not None and now < last_attempt + interval_seconds:
        retry_at = utils.format_timestamp_display(datetime.fromtimestamp(
            last_attempt + interval_seconds, timezone.utc).isoformat())
        hours = interval_seconds / 3600
        raise utils.DownloadError(f'Full repair deferred until {retry_at} UTC ({hours:g}-hour cooldown); '
                                  'retry the full download at or after that time')
    if not utils.watermark_merge(state_file, **{utils.FULL_REPAIR_ATTEMPT_KEY: now}):
        raise utils.DownloadError('Could not record full repair attempt; download not started')
    return utils.fetch_all_cves_threaded(*args, **kwargs)


def report_sync_failure(error, csv_path, last_success):
    """Describe cached output and successful state without implying either exists."""
    print(f'\t[!] Sync incomplete: {error}.')
    if os.path.exists(csv_path):
        print('\t[*] Published CSV is unchanged.')
    else:
        print('\t[!] No published CSV is available.')
    if last_success is not None:
        print('\t[*] Last successful sync checkpoint is unchanged.')
    else:
        print('\t[!] No successful sync checkpoint has been recorded.')


def main():
    # ##########################################################################################
    utils.greeting('nvd-harvester - Download NIST NVD Database')
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
    # Avoid excessive NVD API requests from repeated full downloads.
    nvd_cool_off = 6           # Minimum hours between full download attempts, including failures
    # Initialization can retry immediately until the first successful sync checkpoint.
    
    # API config
    """
    Per NVD, using an API key allows increased request limit up to 50 requests in 30s (0.6s delay).
    However, NVD still recommends sleeping for several seconds so that the requests are serviced 
    without interruption.
    """
    api_endpoint = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    apiKey = os.getenv('NVD_API_KEY')   # Obtain free NVD API key from here: https://nvd.nist.gov/developers/request-an-api-key
    attempts = 20                       # Max attempts per request, including the first; NVD is flaky
    retry_wait = 4                      # Seconds to wait before next retry
    max_workers = 4                     # Adjust this for API throttling
    max_local_repairs = 500             # Beyond this, a rebuild beats one request per file

    # Create the data folders if don't exist
    os.makedirs(data_folder, exist_ok=True)

    # Rebuild the CSV from the CVE files already on disk, without contacting NVD. Useful
    # for re-parsing the corpus after changing the output options above, and for CI jobs
    # that must not depend on the API being reachable.
    skip_sync = os.getenv('NVD_SKIP_SYNC') == '1'

    # Only the download needs credentials, so this check follows the offline switch
    if not skip_sync and apiKey is None:
        print('NIST NVD API key is required!')
        sys.exit(1)
    headers = {'apiKey': apiKey}
    
    # ##########################################################################################
    step += 1
    print(f'\n[{step}] Check CVE counts')
    # ##########################################################################################
    
    # Check latest CVE count in NVD API. An offline run has no figure to compare against.
    nvd_count = None if skip_sync else utils.fetch_cve_count_and_chunk_size(api_endpoint, headers)[0]
    
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
        cve_file_list = []
        cve_file_count = 0

    # Check last successful NVD update, if any
    last_update_file = f'{repo_local}/last_update.json'
    last_update_timestamp, last_update_count = utils.last_update_read_info(last_update_file)
    
    # Local and remote are independent measurements and are labelled as such. The three
    # local figures all describe the same corpus, so they agreeing says nothing about
    # whether that corpus is complete. Only the remote total can tell you that.
    nvd_display = 'skipped' if skip_sync else nvd_count
    if nvd_count is not None:
        # "New" is relative to the local mirror at startup; revisions are reported after sync.
        nvd_display = f'{nvd_count} total, {max(nvd_count - cve_file_count, 0)} new CVEs'
    print(f'\t[*] Local  - JSON: {cve_file_count}, CSV: {csv_count}, Last sync: {last_update_count}')
    print(f'\t[*] Remote - NVD: {nvd_display}')

    # Keep the published CSV and checkpoint when NVD is unavailable. A nonzero status
    # lets scheduled callers distinguish usable cached data from a completed update.
    if not skip_sync and nvd_count is None:
        report_sync_failure('NVD did not respond; retry when the API is available',
                            src_data_file, last_update_timestamp)
        sys.exit(1)

    sync_timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    need_full_sync = False
    pending_repairs = set(utils.watermark_read(last_update_file, utils.PENDING_REPAIRS_KEY, []))
    write_journal = None

    step += 1
    print(f'\n[{step}] Fetch NVD data')

    if skip_sync:
        print(f'\t[*] NVD_SKIP_SYNC=1 - no download; rebuilding from {cve_file_count} local CVE files')
    else:
        try:
            write_journal = checkpoint_local_edits(
                repo_local, cve_json_pattern, last_update_file, pending_repairs)
            need_full_sync = (
                last_update_timestamp is None or cve_file_count == 0
                or (last_update_count > 0 and cve_file_count < last_update_count)
                or utils.window_exceeds_api_limit(last_update_timestamp)
                or len(pending_repairs) > max_local_repairs
            )
            if need_full_sync:
                if len(pending_repairs) > max_local_repairs:
                    print(f'\t[!] {len(pending_repairs)} files need repair; performing a full pull')
                else:
                    print('\t[*] Performing full sync to initialize or repair the mirror')
                full_repair(last_update_file, api_endpoint, headers, repo_local,
                            attempts, retry_wait, max_workers, required_ids=pending_repairs,
                            write_journal=write_journal, interval_seconds=nvd_cool_off * 3600,
                            initializing=last_update_timestamp is None)
                pending_repairs.clear()
                save_pending_repairs(last_update_file, pending_repairs)
            else:
                if pending_repairs:
                    print(f'\t[*] Restoring {len(pending_repairs)} pending CVE file(s) from NVD')
                    restored, failed = utils.refetch_cves_by_id(
                        api_endpoint, headers, repo_local, sorted(pending_repairs), attempts, retry_wait,
                        write_journal=write_journal)
                    pending_repairs = set(failed)
                    save_pending_repairs(last_update_file, pending_repairs)
                    if failed:
                        raise utils.DownloadError(f'{len(failed)} file repairs remain pending')
                    print(f'\t[*] Restored {len(restored)} CVE file(s)')

                # Counts cannot detect revisions, so every incremental run checks the window.
                print(f'\t[*] Attempting Differential sync from {utils.format_timestamp_display(last_update_timestamp)}')
                end_timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                held_before = cve_file_count
                retrieved = utils.fetch_all_cves_threaded(
                    api_endpoint, headers, repo_local, attempts, retry_wait,
                    max_workers, last_update_timestamp, end_timestamp, write_journal=write_journal)
                cve_file_count = len(utils.enumerate_files_in_folder(repo_local, cve_json_pattern))
                added = cve_file_count - held_before
                print(f'\t[*] Differential sync successful - {cve_file_count} CVEs '
                      f'({added} new, {max(retrieved - added, 0)} updated)')

                # The window cannot establish the identity of older missing records.
                # Retry full repair after a persistent cooldown; differential work continues.
                if cve_file_count < nvd_count:
                    print(f'\t[!] Still {nvd_count - cve_file_count} CVEs behind; performing a full repair')
                    full_repair(last_update_file, api_endpoint, headers, repo_local,
                                attempts, retry_wait, max_workers, required_ids=pending_repairs,
                                write_journal=write_journal, interval_seconds=nvd_cool_off * 3600)
                    need_full_sync = True

            cve_file_list = utils.enumerate_files_in_folder(repo_local, cve_json_pattern)
            cve_file_count = len(cve_file_list)
            if cve_file_count < nvd_count:
                raise utils.DownloadError(f'Mirror still has {nvd_count - cve_file_count} fewer CVEs than the count probe')
        except (utils.DownloadError, OSError, ValueError) as e:
            report_sync_failure(e, src_data_file, last_update_timestamp)
            sys.exit(1)

    # ##########################################################################################
    step += 1
    print(f'\n[{step}] Find CVE JSON file changes')
    # ##########################################################################################

    if csv_count == 0 or need_full_sync or skip_sync:
        print(f'\t[*] Processing All {cve_file_count} JSON files for full CSV build')
        full_csv_dump = True
        
    else:
        # Try differential update first
        full_csv_dump = False

        # Find timestamp of last CSV update
        t_csv_modified = utils.get_file_modified_time_utc(src_data_file)
        print(f'\t[*] Last CSV update: {utils.format_timestamp_display(t_csv_modified)}')

        # Get list of CVE files changed since last CSV update
        changed_file_list = utils.get_modified_files_since(repo_local, t_csv_modified, file_pattern=cve_json_pattern, buffer_days=0)
        
        # Check if there are any changes
        if len(changed_file_list) == 0:

            if csv_count == cve_file_count:
                print('\t[*] No CSV update needed.')
                record_sync_success(last_update_file, sync_timestamp, cve_file_count)
                return
            else:
                print(f'\t[!] CVE counts mismatch! NVD: {nvd_count}, CSV: {csv_count}, JSON: {cve_file_count}' )
                print('\t[!] Rebuilding CSV to ensure consistency')
                full_csv_dump = True
        else:
            # Changes detected - use them for differential update
            print(f'\t[*] Found {len(changed_file_list)} modified CVE files since last CSV update')
    
    # ##########################################################################################
    step += 1
    print(f'\n[{step}] Parse CVE JSON files')
    # ##########################################################################################

    selected_files = cve_file_list if full_csv_dump else changed_file_list
    df_nvd, unreadable = utils.json_files_combine_concurrent(selected_files)
    if unreadable:
        if skip_sync:
            print('\t[!] Offline rebuild found unreadable files; existing CSV is unchanged.')
            sys.exit(1)
        pending_repairs.update(os.path.basename(path).removesuffix('.json') for path in unreadable)
        if not utils.watermark_merge(last_update_file,
                                     **{utils.PENDING_REPAIRS_KEY: sorted(pending_repairs)}):
            sys.exit(1)
        if len(unreadable) > max_local_repairs:
            print('\t[!] Too many unreadable files for individual repair; next run will perform a full pull.')
            sys.exit(1)
        repair_ids = [os.path.basename(path).removesuffix('.json') for path in unreadable]
        _, failed = utils.refetch_cves_by_id(api_endpoint, headers, repo_local,
                                            repair_ids, attempts, retry_wait, write_journal=write_journal)
        if failed:
            print(f'\t[!] {len(failed)} repairs remain pending; existing CSV is unchanged.')
            sys.exit(1)
        df_nvd, unreadable = utils.json_files_combine_concurrent(selected_files)
        if unreadable:
            print('\t[!] Repaired files could not be read; existing CSV is unchanged and repairs remain pending.')
            sys.exit(1)

    if df_nvd.empty:
        print('\t[!] No CVE records could be parsed - leaving the existing CSV untouched')
        sys.exit(1)
    df_nvd = utils.parse_cve_nvd(df_nvd)

    if not full_csv_dump:
        df_previous = pd.read_csv(src_data_file, dtype=str)
        df_previous.index = df_previous['cve']
        df_previous.index.name = 'id'
        if keep_diff_csv:
            utils.write_df_csv(df_nvd, f'{data_folder}/nvd-diff-{t_csv_modified}.csv')
        df_previous = df_previous[~df_previous.index.isin(df_nvd.index)]
        if not df_previous.empty:
            # CSV-loaded columns can be entirely missing. Align to object explicitly
            # to avoid pandas 2.x's deprecated all-NA dtype inference during concat.
            df_nvd = pd.concat([df_nvd.astype(object), df_previous.astype(object)], axis=0)

    # OPTIONAL
    if drop_references:
        df_nvd.drop(columns=['referenceUrl'], inplace=True)
    if drop_cpe:
        df_nvd.drop(columns=['cpe'], inplace=True)
    
    # What this step can vouch for is that every CVE file on disk became a row. Breaking
    # that means something went wrong locally. A gap against NVD's reported total is a
    # separate measurement with no single cause, so it is reported rather than explained.
    row_count = df_nvd.shape[0]
    if row_count != cve_file_count:
        print(f'\t[!] WARNING! Parsed {row_count} rows from {cve_file_count} CVE files')
        print('\t[!] CSV is unchanged; resolve the record-count mismatch before publishing.')
        sys.exit(1)
    elif nvd_count is not None and not utils.mirror_is_current(row_count, nvd_count):
        print(f'\t[*] All {cve_file_count} CVE files processed; '
              f'{nvd_count - row_count} fewer than NVD reports ({nvd_count})')
    else:
        print(f'\t[*] All {cve_file_count} CVE files processed successfully')
    
    step += 1
    print(f'\n[{step}] Write files')
    print(f'\t[*] Writing: {src_data_file}')
    utils.write_df_csv(df_nvd, src_data_file, index=False)
    if not skip_sync:
        record_sync_success(last_update_file, sync_timestamp, cve_file_count)

    step += 1
    print(f'\n[{step}] Summary')
    recorded_count = last_update_count if skip_sync else cve_file_count
    print(f'\t[*] Local  - JSON: {cve_file_count}, CSV: {df_nvd.shape[0]}, Last sync: {recorded_count}')
    print(f'\t[*] Remote - NVD: {nvd_display}')
    print(f'\t[*] Finished in {utils.runtime(start)}')


if __name__ == '__main__':
    main()
