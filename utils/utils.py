import concurrent.futures
import contextlib
import json
import os
import re
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone

import pandas as pd
import requests


class DownloadError(Exception):
    pass


# The NVD API refuses a lastModified range wider than this, answering 404 with an empty
# body. Confirmed against the live API: 120 days succeeds, 121 does not.
NVD_MAX_WINDOW_DAYS = 120
REQUEST_TIMEOUT = (10, 60)


@contextlib.contextmanager
def atomic_text_file(file_path, before_replace=None):
    """Replace a text file only after its complete replacement is flushed to disk.

    The temporary file shares the destination directory so replacement is atomic.
    Exceptions leave the previous destination intact and remove the temporary file.
    An optional callback durably records the completed temporary file before replacement.
    """
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='',
                                         dir=os.path.dirname(os.path.abspath(file_path)),
                                         prefix=f'.{os.path.basename(file_path)}.',
                                         suffix='.tmp', delete=False) as f:
            temporary = f.name
            yield f
            f.flush()
            os.fsync(f.fileno())
        if before_replace is not None:
            before_replace(file_path, temporary)
        os.replace(temporary, file_path)
    finally:
        if temporary is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)


class LocalWriteJournal:
    """Track the exact file metadata produced by this process, including failed runs.

    Each entry is durable before its JSON replacement. A crash may therefore leave an
    entry for a replacement that did not occur, but cannot leave a replaced file without
    its entry. Entries only suppress edit detection when current metadata matches.
    """

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def record(self, destination, temporary):
        """Record a completed temporary file before it replaces a CVE file."""
        stat = os.stat(temporary)
        entry = [os.path.basename(destination), stat.st_mtime_ns, stat.st_size]
        with self.lock, open(self.path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
            f.flush()
            os.fsync(f.fileno())

    def read(self):
        """Read the last recorded metadata per filename; ignore an incomplete tail.

        A non-newline-terminated tail cannot have authorized a replacement: record()
        must finish writing and fsync before atomic_text_file invokes os.replace.
        Invalid complete entries fail rather than silently trusting damaged metadata.
        """
        entries = {}
        if not os.path.exists(self.path):
            return entries
        with open(self.path, encoding='utf-8') as f:
            for line in f:
                if not line.endswith('\n'):
                    break
                name, mtime_ns, size = json.loads(line)
                if (not isinstance(name, str) or type(mtime_ns) is not int
                        or type(size) is not int or size < 0):
                    raise ValueError('Invalid local write journal entry')
                entries[name] = (mtime_ns, size)
        return entries

    def reset(self):
        """Rotate consumed entries only after the edit scan has been checkpointed."""
        with atomic_text_file(self.path):
            pass


def find_external_edits(file_paths, cutoff_ns, own_writes):
    """Find changes since a scan, excluding files that still match our recorded writes."""
    if cutoff_ns is None:
        return []
    edited = []
    for path in file_paths:
        try:
            stat = os.stat(path)
        except FileNotFoundError:
            continue
        fingerprint = (stat.st_mtime_ns, stat.st_size)
        if stat.st_mtime_ns > cutoff_ns and own_writes.get(os.path.basename(path)) != fingerprint:
            edited.append(path)
    return edited


def greeting(message):
    """
    Print a banner with the message centred between two rules of hashes.

    Args:
        message (str): Text to display inside the banner.
    """
    l = 85
    p = (l - len(message)) // 2
    print()
    print(f'{l * "#"}')
    print(f'{p * " "}{message}{p * " "}')
    print(f'{l * "#"}')


def runtime(start_time):
    """
    Report the time elapsed since a starting point, formatted for display.

    Args:
        start_time (float or datetime): A time.time() value, or a UTC datetime.

    Returns:
        str: Elapsed time as '<m>m <s>s', or a message naming the unsupported type.
    """
    # Record the end time properly, depending on the input timestamp
    if isinstance(start_time, datetime):
        # Convert datetime to timestamp
        start_time = start_time.timestamp()
        end_time = datetime.now(timezone.utc).timestamp()
    elif isinstance(start_time, float):
        end_time = time.time()
    else:
        return f'Unsupported timestamp: {start_time}'

    # Calculate the elapsed time in seconds
    elapsed_time = end_time - start_time

    # Convert elapsed time to minutes and seconds
    minutes = int(elapsed_time // 60)
    seconds = int(elapsed_time % 60)

    return f'{minutes}m {seconds}s'


def read_file_json(path):
    """
    Load and decode a JSON file.

    Args:
        path (str): Path to the JSON file.

    Returns:
        The decoded JSON content.

    Note:
        Terminates the process if the file cannot be read or parsed.
    """
    try:
        with open(path, encoding='utf-8') as file:
            data = json.load(file)
    except Exception as e:
        print(f'\t{path} - Error: {e}')
        sys.exit(1)
    return data


def get_file_modified_time_utc(file_path):
    """
    Read a file's last-modified time as a UTC timestamp string.

    Args:
        file_path (str): Path to the file.

    Returns:
        str or None: Modification time as '%Y-%m-%dT%H:%M:%SZ', or None if the file
            cannot be read.
    """
    try: 
        # Convert local file modification time to UTC for consistent comparison
        file_mtime = os.path.getmtime(file_path)
        file_mtime_utc = datetime.fromtimestamp(file_mtime, tz=timezone.utc)
        return file_mtime_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    except Exception as e:
        print(f'Error: {e}')
        return None


def get_modified_files_since(base_folder, since_timestamp_str, file_pattern=None, buffer_days=0):
    """
    Returns a list of files modified since the specified timestamp.
    
    Args:
        base_folder (str): The root directory to scan for modified files.
        since_timestamp_str (str or float): ISO 8601 UTC timestamp string
            (e.g. "2025-03-02T02:32:23Z"), or a POSIX timestamp. Prefer the numeric form
            when the cutoff must be exact: the string form carries only whole seconds, so
            a file written later in that same second still counts as newer.
        file_pattern (str, optional): Regex pattern to filter files by name. Defaults to None (all files).
        buffer_days (int, optional): Number of days to subtract from the timestamp for a time buffer. Defaults to 0.
    
    Returns:
        list: Full paths of every file modified after the specified timestamp.

    Raises:
        TypeError: If since_timestamp_str is not a string.
        FileNotFoundError: If base_folder is not a directory.
        ValueError: If the timestamp or the regex pattern cannot be parsed.
        RuntimeError: If the directory tree cannot be walked.
    """
    # Validate inputs
    if not isinstance(since_timestamp_str, (str, int, float)):
        raise TypeError('since_timestamp_str must be an ISO 8601 string or a POSIX timestamp')
    
    if not os.path.isdir(base_folder):
        raise FileNotFoundError(f'Directory not found: {base_folder}')
    
    # Parse the timestamp
    if isinstance(since_timestamp_str, (int, float)):
        since_timestamp = float(since_timestamp_str) - buffer_days * 86400
    else:
        try:
            # Process timestamp once before file scanning
            since_datetime = datetime.fromisoformat(since_timestamp_str.replace('Z', '+00:00'))

            # Apply buffer if needed
            if buffer_days > 0:
                since_datetime -= timedelta(days=buffer_days)

            # Store the UTC timestamp for comparison
            since_timestamp = since_datetime.timestamp()
        except ValueError as e:
            raise ValueError(f'Failed to parse timestamp \'{since_timestamp_str}\': {e!s}') from e

    # Compile regex pattern if provided (once, outside the loop)
    pattern = None
    if file_pattern is not None:
        try:
            pattern = re.compile(file_pattern)
        except re.error as e:
            raise ValueError(f'Invalid regex pattern \'{file_pattern}\': {e!s}') from e
    
    modified_files = []
    
    # Walk the directory tree
    try:
        for root, _, files in os.walk(base_folder):
            for file in files:
                # Apply pattern filter first (cheaper operation)
                if pattern is not None and not pattern.search(file):
                    continue
                    
                file_path = os.path.join(root, file)
                
                try:
                    # Modification times and the cutoff are both POSIX timestamps,
                    # so they compare directly with no timezone conversion.
                    if os.path.getmtime(file_path) > since_timestamp:
                        modified_files.append(file_path)
                except (FileNotFoundError, PermissionError):
                    # Skip files we can't access (permission issues)
                    continue
                    
    except Exception as e:
        raise RuntimeError(f'Error walking directory {base_folder}: {e!s}') from e
        
    return modified_files


def enumerate_files_in_folder(base_folder, pattern=r'CVE-\d{4}-\d{4,}\.json$'):
    """
    Recursively collect files whose basename matches a regex pattern.

    Args:
        base_folder (str): Root folder to search.
        pattern (str, optional): Regex matched against each basename. Defaults to the
            NVD CVE JSON naming convention.

    Returns:
        list: Full paths of every matching file.
    """
    # Get all files recursively
    all_files = []
    for root, _, files in os.walk(base_folder):
        for file in files:
            all_files.append(os.path.join(root, file))
    
    # Filter by regex pattern
    regex = re.compile(pattern)
    file_paths = [file_path for file_path in all_files if regex.search(os.path.basename(file_path))]

    return file_paths


def convert_df_timestamp(timestamp, input_format='mixed'):
    """
    Convert a given timestamp format to UTC. Handles None input.

    Args:
        timestamp (str or None): The timestamp to convert.
        input_format (str, optional): Input datetime format. Defaults to 'mixed'.

    Returns:
        str or None: The timestamp as '%Y-%m-%dT%H:%M:%SZ', or None if the input was
            None or could not be parsed.
    """
    output_format = '%Y-%m-%dT%H:%M:%SZ'

    if timestamp is None:
        return None  # Return None if input is None

    try:
        # Convert the input timestamp string to a datetime object
        dt = pd.to_datetime(timestamp, format=input_format, errors='coerce') # Handle parsing errors

        if pd.isna(dt): # Check if parsing failed
            return None

        # Convert back to desired ISO 8601 format and append 'Z' for UTC time zone
        return dt.strftime(output_format)
    except Exception as e: # Catch any other exceptions
        print(f"Error converting timestamp: {e}")
        return None


def write_df_csv(df, file_path, index=False):
    """
    Write a DataFrame to a CSV file.

    Args:
        df (pd.DataFrame): The DataFrame to write.
        file_path (str): Destination path for the CSV file.
        index (bool, optional): Whether to write the index column. Defaults to False.

    Note:
        Terminates the process if the file cannot be written.
    """
    try:
        #print(f'\tWriting: {file_path}')
        with atomic_text_file(file_path) as f:
            df.to_csv(f, index=index)
    except Exception as e:
        print(f'\tError! {e}')
        sys.exit(1)


def last_update_write_info(file_path, timestamp, count, last_update_key='last_update', last_count_key='last_nvd_count', extra=None):
    """
    Writes the latest update timestamp and count in a JSON file.

    Args:
        file_path (str): The path to the JSON file to be updated.
        timestamp (str): The timestamp of the last update, formatted as a string.
        count (int): The count of items processed during the update.
        last_update_key (str, optional): The key used to store the timestamp in the JSON file. Defaults to 'last_update'.
        last_count_key (str, optional): The key used to store the count in the JSON file. Defaults to 'last_nvd_count'.
        extra (dict, optional): Additional keys to store alongside the timestamp and
            count. Omitting a key that was previously written removes it, so this also
            serves to clear a marker once it no longer applies.

    Returns:
        bool: True if the file was written, False if the write failed.

    Raises:
        TypeError: If timestamp is not a string, or count is not an integer.

    Example:
        >>> last_update_write_info('last_update.json', '2023-10-27T12:00:00Z', 12345)
        True
    """
    if not isinstance(timestamp, str):
        raise TypeError("timestamp must be a string")
    if not isinstance(count, int):
        raise TypeError("count must be an integer")
    
    try:
        with atomic_text_file(file_path) as f:
            data = {last_update_key: timestamp, last_count_key: count}
            if extra:
                data.update(extra)
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        print(f"Error updating {file_path}: {e}")
        return False


def last_update_read_info(file_path, last_update_key='last_update', last_count_key='last_nvd_count'):
    """
    Reads the last update timestamp and count from a JSON file.

    Args:
        file_path (str): The path to the JSON file to read.
        last_update_key (str, optional): The key used to store the timestamp in the JSON file. Defaults to 'last_update'.
        last_count_key (str, optional): The key used to store the count in the JSON file. Defaults to 'last_nvd_count'.

    Returns:
        tuple: (timestamp, count) read from the file, or (None, 0) if the file is
            missing or cannot be parsed.

    Example:
        >>> last_update_read_info('last_update.json')
        ('2023-10-27T12:00:00Z', 12345)
    """
    if not os.path.exists(file_path):
        print(f"\t[!] File doesn't exist: {file_path}")
        return None, 0
    
    try:
        with open(file_path, encoding='utf-8') as f:
            data = json.load(f)
            timestamp = data.get(last_update_key)
            count = data.get(last_count_key, 0)
            return timestamp, count
    except Exception as e:
        print(f'\t[] Error reading {file_path}: {e}')
        return None, 0


def format_timestamp_display(timestamp):
    """
    Render an ISO 8601 timestamp in a form that is easier to read in the console.

    Presentation only. Watermarks written to disk and timestamps sent to the API keep
    the 'Z'-suffixed form the NVD API requires, so this must never be used to build
    either of those.

    Args:
        timestamp (str or None): A timestamp such as '2026-09-09T13:11:55Z'.

    Returns:
        str: The timestamp as 'YYYY-MM-DD HH:MM:SS' in UTC, or the input rendered
            unchanged if it is not a timestamp this function recognises.
    """
    if not timestamp:
        return str(timestamp)

    try:
        parsed = datetime.fromisoformat(str(timestamp).replace('Z', '+00:00'))
    except ValueError:
        return str(timestamp)

    return parsed.strftime('%Y-%m-%d %H:%M:%S')


def window_exceeds_api_limit(start_timestamp, end_timestamp=None, max_days=NVD_MAX_WINDOW_DAYS):
    """
    Report whether a lastModified range is wider than the NVD API will accept.

    A range beyond the limit is rejected with a 404 and an empty body, which at the
    request level looks like any other 404 and simply burns every retry. Measuring the
    span first turns that dead end into a decision the caller can act on.

    Args:
        start_timestamp (str or None): Start of the range, ISO 8601 with a 'Z' suffix.
        end_timestamp (str or None): End of the range. Defaults to the current UTC time.
        max_days (int, optional): Widest range the API accepts. Defaults to 120.

    Returns:
        bool: True if the range is too wide to request. A missing or unparseable start
            is not a range at all, and returns False.
    """
    if not start_timestamp:
        return False

    try:
        start = datetime.fromisoformat(start_timestamp.replace('Z', '+00:00'))
        end = (datetime.fromisoformat(end_timestamp.replace('Z', '+00:00'))
               if end_timestamp else datetime.now(timezone.utc))
    except (AttributeError, ValueError):
        return False

    return (end - start) > timedelta(days=max_days)


RUN_COMPLETED_KEY = 'run_completed'
PENDING_REPAIRS_KEY = 'pending_repairs'
LOCAL_SCAN_KEY = 'local_scan_started_ns'
FULL_REPAIR_ATTEMPT_KEY = 'last_full_repair_attempt'


def watermark_read(file_path, key, default=None):
    """
    Read one field from the watermark file.

    Args:
        file_path (str): Path to the watermark JSON file.
        key (str): Field to read.
        default: Value to return when the file or the field is absent.

    Returns:
        The stored value, or default if it cannot be read.
    """
    if not os.path.exists(file_path):
        return default

    try:
        with open(file_path, encoding='utf-8') as f:
            return json.load(f).get(key, default)
    except (OSError, ValueError) as e:
        print(f'\t[!] Error reading {file_path}: {e}')
        return default


def watermark_merge(file_path, **fields):
    """
    Add or replace fields in the watermark file, leaving the rest intact.

    Args:
        file_path (str): Path to the watermark JSON file.
        **fields: Keys to write.

    Returns:
        bool: True if the file was written.
    """
    data = {}
    if os.path.exists(file_path):
        try:
            with open(file_path, encoding='utf-8') as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}

    data.update(fields)
    try:
        with atomic_text_file(file_path) as f:
            json.dump(data, f, indent=4)
        return True
    except OSError as e:
        print(f'\t[!] Error updating {file_path}: {e}')
        return False


def refetch_cves_by_id(base_url, headers, data_folder, cve_ids, attempts=10, retry_wait=6, write_journal=None):
    """
    Re-download specific CVEs one at a time and overwrite their local files.

    Used to restore records that were altered on disk. NVD will not return them through
    a lastModified window, because from its side nothing changed, so each has to be
    requested by id.

    Args:
        base_url (str): Base URL of the NVD CVE API.
        headers (dict): HTTP headers for the requests.
        data_folder (str): Directory in which CVE JSON files are stored.
        cve_ids (list): CVE identifiers to restore.
        attempts (int, optional): Maximum retry attempts per request. Defaults to 10.
        retry_wait (int, optional): Seconds to wait between retries. Defaults to 6.
        write_journal (LocalWriteJournal, optional): Track replacements for edit detection.

    Returns:
        tuple: (restored, failed) lists of CVE identifiers.
    """
    restored, failed = [], []

    for cve_id in cve_ids:
        for _ in range(attempts):
            try:
                response = requests.get(base_url, headers=headers, params={'cveId': cve_id},
                                        timeout=REQUEST_TIMEOUT)
                response.raise_for_status()
                payload = response.json()
                results = payload['vulnerabilities']
                if not isinstance(results, list):
                    raise TypeError('NVD vulnerabilities must be a list')
                if results:
                    if (len(results) != 1 or not isinstance(results[0], dict)
                            or not isinstance(results[0].get('cve'), dict)
                            or results[0]['cve'].get('id') != cve_id):
                        raise DownloadError(f'NVD returned an unexpected record for {cve_id}')
                    extract_cve_info_and_write_to_files(results, data_folder, write_journal=write_journal)
                    restored.append(cve_id)
                else:
                    print(f'\t[!] NVD returned no record for {cve_id}; repair remains pending')
                    failed.append(cve_id)
                break
            except (requests.exceptions.RequestException, DownloadError, KeyError, TypeError, ValueError) as e:
                print(f'\t[!] Could not restore {cve_id}: {e}')
                time.sleep(retry_wait)
        else:
            failed.append(cve_id)

    return restored, failed


def mirror_is_current(local_count, nvd_count):
    """
    Report whether the local mirror holds at least as many CVEs as NVD.

    The comparison is '>=' rather than '=='. NVD's total is sampled once, before a
    download that may run for minutes, and the catalogue keeps growing in the meantime,
    so ending a run slightly ahead of that figure is normal. Requiring an exact match
    would treat routine skew as a failure and refetch the whole catalogue on almost
    every run. Only a mirror holding fewer records has a genuine shortfall.

    Args:
        local_count (int): CVE records held locally, as JSON files or as CSV rows.
        nvd_count (int or None): totalResults from the API, or None if unavailable.

    Returns:
        bool: True if the mirror needs no repair. An unavailable total is never current.
    """
    if nvd_count is None:
        return False
    return local_count >= nvd_count


def fetch_cve_count_and_chunk_size(base_url, headers, attempts=10, retry_wait=6, params=None):
    """
    Read the CVE count and page size that the NVD API reports for a query.

    Passing lastModStartDate and lastModEndDate in params limits both figures to CVEs
    modified within that window instead of the whole catalogue.

    Args:
        base_url (str): Base URL of the NVD CVE API.
        headers (dict): HTTP headers for the request.
        attempts (int, optional): Maximum retry attempts. Defaults to 10.
        retry_wait (int, optional): Seconds to wait between retries. Defaults to 6.
        params (dict, optional): Query parameters for the request. Defaults to none.

    Returns:
        tuple: (totalResults, resultsPerPage), or (None, None) once the retries are
            exhausted. A None result means the API is unavailable and says nothing
            about the state of the local data, so callers must handle it explicitly.
    """
    
    # Set parameters
    if not params:
        params = {}
    
    # Get total CVE count and results per page from the API
    for n in range(attempts):
        try:
            response = requests.get(base_url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            json_data = response.json()
            
            totalResults = json_data['totalResults']
            resultsPerPage = json_data['resultsPerPage']
            if (type(totalResults) is not int or totalResults < 0
                    or type(resultsPerPage) is not int or resultsPerPage < 0
                    or (totalResults > 0 and resultsPerPage == 0)):
                raise ValueError('NVD returned an invalid count or page size')
            
            return totalResults, resultsPerPage
        
        except (requests.exceptions.RequestException, KeyError, TypeError, ValueError) as e:
            print(f'\t[!] Retry {n+1}, wait {retry_wait}s! Error: {e}')
            time.sleep(retry_wait)
    
    # Out of attempts. Report upward rather than killing the whole process.
    print(f'\t[!] Failed to get total CVE count after {attempts} attempts. Try again later.')
    return None, None


def fetch_and_process_chunk(base_url, headers, data_folder, attempts, retry_wait, offset, params, expected_count, write_journal=None):
    """
    Fetch one page of CVEs from the NVD API and write them to disk.

    Args:
        base_url (str): Base URL of the NVD CVE API.
        headers (dict): HTTP headers for the request.
        data_folder (str): Directory in which CVE JSON files are stored.
        attempts (int): Maximum retry attempts for the request.
        retry_wait (int): Seconds to wait between retry attempts.
        offset (int): startIndex of the page to retrieve.
        params (dict): Query parameters shared with the other workers. Copied, never
            mutated, so concurrent chunks cannot overwrite each other's offset.
        expected_count (int): Minimum records expected at this offset from the count probe.
        write_journal (LocalWriteJournal, optional): Track replacements for edit detection.

    Returns:
        set: IDs of the CVEs successfully persisted.

    Raises:
        DownloadError: If a page remains incomplete or a record cannot be persisted.
    """
    # Copy before setting the offset. The caller hands the same dict to every worker, so
    # mutating it in place lets one thread overwrite another's startIndex between the
    # assignment and the request. That silently skips whole chunks and re-fetches others,
    # leaving the mirror short by an exact multiple of the page size.
    request_params = dict(params)
    request_params['startIndex'] = offset

    for n in range(attempts):
        try:
            # API request
            response = requests.get(base_url, headers=headers, params=request_params, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            payload = response.json()
            results = payload['vulnerabilities']
            if (not isinstance(results, list)
                    or not expected_count <= len(results) <= request_params['resultsPerPage']
                    or payload['startIndex'] != offset
                    or payload['resultsPerPage'] != len(results)):
                raise ValueError(f'Incomplete or inconsistent page at offset {offset}')
        except (requests.exceptions.RequestException, KeyError, TypeError, ValueError) as e:
            print(f'\t[!] Error! Retry {n} for offset {offset}. {e}')
            time.sleep(retry_wait)
            continue

        # Persistence failures are not HTTP failures. Propagate them without repeatedly
        # downloading a valid response, and keep the caller's checkpoint unchanged.
        return extract_cve_info_and_write_to_files(results, data_folder, write_journal=write_journal)

    raise DownloadError(f'Max retries exceeded for page at offset {offset}')


def fetch_all_cves_threaded(base_url, headers, data_folder, attempts=10, retry_wait=6, max_workers=3, lastModStartDate=None, lastModEndDate=None, required_ids=None, write_journal=None):
    """
    Download every CVE the API reports for a query and write them to disk.

    Reads the record count and page size first, then submits one worker per page.
    Supplying both lastModStartDate and lastModEndDate restricts the download to CVEs
    modified within that window, which is how incremental updates are performed.

    Args:
        base_url (str): Base URL of the NVD CVE API.
        headers (dict): HTTP headers for the requests.
        data_folder (str): Directory in which to store CVE JSON files.
        attempts (int, optional): Maximum retry attempts per request. Defaults to 10.
        retry_wait (int, optional): Seconds to wait between retries. Defaults to 6.
        max_workers (int, optional): Size of the thread pool. Defaults to 3.
        lastModStartDate (str, optional): Start of the modification window, as an ISO
            8601 UTC timestamp. Defaults to None.
        lastModEndDate (str, optional): End of the modification window. Defaults to None.
        required_ids (set, optional): IDs that a full pull must restore before completing.
        write_journal (LocalWriteJournal, optional): Track replacements for edit detection.

    Returns:
        int: How many CVE records were retrieved. A caller that also counts files before
            and after can use this to separate newly published CVEs from revisions to
            records it already held, since a revision leaves the file count unchanged.

    Raises:
        DownloadError: If the record count cannot be read, if the API reports records
            without a usable page size, or if any page exhausts its retries. The caller
            decides whether the data already on disk can carry the run.
    """
    # Set parameters
    if lastModStartDate and lastModEndDate:
        params = {'lastModStartDate': lastModStartDate, 'lastModEndDate': lastModEndDate}
    else:
        params = {}
        
    # Get total CVE count and results per page from the API
    totalResults, resultsPerPage = fetch_cve_count_and_chunk_size(base_url, headers, attempts, retry_wait, params)

    # Neither case permits safe paging. A missing count means the API is unavailable; a
    # zero page size against a non-zero total would leave offset stuck at 0 and queue
    # work forever. An empty modification window reports neither, and the loop below
    # correctly does nothing.
    if totalResults is None or resultsPerPage is None:
        raise DownloadError('Unable to read the NVD record count')
    if totalResults > 0 and resultsPerPage == 0:
        raise DownloadError(f'NVD reported {totalResults} records but a page size of 0')

    # Name the population this count describes. A windowed request counts only CVEs
    # modified inside that window, which is a completely different figure from the
    # catalogue total reported at startup. Labelling both 'NVD records' invited them
    # to be read as the same measurement.
    if lastModStartDate and lastModEndDate:
        print(f'\t[*] CVEs modified in this window: {totalResults}, page size {resultsPerPage}')
    else:
        print(f'\t[*] CVEs in NVD catalogue: {totalResults}, page size {resultsPerPage}')

    # Initialize VARs
    offset = 0
    start_download = time.time()
    retrieved_ids = set()
    params['resultsPerPage'] = resultsPerPage
    
    # Fetch data
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        
        # Submitting Tasks to the Executor:
        futures = []
        while offset < totalResults:
            expected_count = min(resultsPerPage, totalResults - offset)
            futures.append(executor.submit(fetch_and_process_chunk, base_url, headers, data_folder,
                                           attempts, retry_wait, offset, params, expected_count, write_journal))
            offset += resultsPerPage

        # Retrieving the results of the tasks 
        for future in concurrent.futures.as_completed(futures):
            try:
                page_ids = future.result()
                if retrieved_ids.intersection(page_ids):
                    raise DownloadError('NVD repeated CVE IDs across pages; the query must be retried')
                retrieved_ids.update(page_ids)
                print(f'\t    Retrieved: {len(retrieved_ids)}, '
                      f'Remaining: {max(totalResults - len(retrieved_ids), 0)}')
            
            except DownloadError as e:
                executor.shutdown(wait=False, cancel_futures=True) # Shutdown executor immediately
                print(e)
                # Whether a partial sync is recoverable depends on what the caller
                # already holds on disk, so raise rather than deciding that here.
                raise

    total_retrieved = len(retrieved_ids)
    if total_retrieved < totalResults:
        raise DownloadError(f'Only persisted {total_retrieved} of {totalResults} requested CVEs')
    missing_repairs = set(required_ids or ()) - retrieved_ids
    if missing_repairs:
        raise DownloadError(f'{len(missing_repairs)} pending CVE repairs were not returned by NVD')

    if totalResults != 0:
        print(f'\n\t[*] NVD download complete in {runtime(start_download)}! Retrieved {total_retrieved} CVEs')

    return total_retrieved


def extract_cve_info_and_write_to_files(json_data, output_directory='raw-nvd', write_journal=None):
    """Validate a page and atomically write its CVEs into year subdirectories.

    Returns the set of successfully written IDs. Invalid or duplicate entries and
    persistence failures raise DownloadError so the sync cannot checkpoint past them.
    A failed page may have written some complete records; replay safely overwrites them.
    """
    if not isinstance(json_data, list):
        raise DownloadError('NVD vulnerabilities must be a list')

    records = {}
    for entry in json_data:
        record = entry.get('cve') if isinstance(entry, dict) else None
        if not isinstance(record, dict):
            raise DownloadError('NVD returned an invalid CVE record')
        cve_id = record.get('id')
        if not isinstance(cve_id, str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve_id):
            raise DownloadError('NVD returned an invalid CVE identifier')
        if cve_id in records:
            raise DownloadError(f'NVD repeated {cve_id} within a page')
        records[cve_id] = record

    for cve_id, record in records.items():
        directory = os.path.join(output_directory, cve_id.split('-')[1])
        filename = os.path.join(directory, f'{cve_id}.json')
        try:
            os.makedirs(directory, exist_ok=True)
            with atomic_text_file(filename, before_replace=write_journal.record if write_journal else None) as f:
                json.dump(record, f, indent=4, ensure_ascii=False)
        except (OSError, TypeError, ValueError) as e:
            raise DownloadError(f'Could not persist {cve_id}: {e}') from e
    return set(records)


def json_files_combine_concurrent(file_paths, max_workers=None):
    """Combines JSON files into a pandas DataFrame, including file paths.

    Reads each JSON file specified in `file_paths`, processes the data, and
    combines it into a single DataFrame. Includes the file path as a new column.

    Args:
        file_paths: A list of strings, where each string is a path to a JSON file.
        max_workers (int, optional): The maximum number of worker threads.

    Returns:
        tuple: Combined DataFrame and a list of unreadable file paths. The frame is
            empty if there is nothing readable to return. Callers must handle the
            unreadable paths before publishing an export or recording sync completion.

    Note:
        A file that cannot be read or parsed is reported and skipped. One damaged file
        among hundreds of thousands must not discard the rest of the corpus, and the
        caller receives the failed paths for repair without losing their identity.
    """

    if not file_paths:
        return pd.DataFrame(), []

    all_data = []

    def _read_and_process_json(file_path):
        """Reads and processes a single JSON file, including file path.

        Helper function used by concurrent.futures.

        Args:
            file_path: The path to the JSON file.

        Returns:
            list or None: One validated record tagged with its source path, or None
                if the file cannot be read or its required identity/fields are missing.
        """
        try:
            with open(file_path, encoding='utf-8') as f:
                data = json.load(f)
                required = {'id', 'descriptions', 'published', 'lastModified', 'vulnStatus', 'sourceIdentifier'}
                expected_id = os.path.basename(file_path).removesuffix('.json')
                if not isinstance(data, dict) or not required.issubset(data) or data['id'] != expected_id:
                    raise ValueError('CVE record is incomplete or does not match its filename')
                data['file_path'] = file_path
                return [data]
        except FileNotFoundError:
            print(f"Error: File not found: {file_path}")
            return None
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in file: {file_path}")
            return None
        except Exception as e:
            print(f"An error occurred while processing {file_path}: {e}")
            return None

    unreadable = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_read_and_process_json, path): path for path in file_paths}

        for future in concurrent.futures.as_completed(futures):
            data = future.result()
            if data is None:
                unreadable.append(futures[future])
                continue
            all_data.extend(data)

    if unreadable:
        print(f'\t[!] Skipped {len(unreadable)} unreadable file(s), first: {unreadable[0]}')

    if not all_data:
        return pd.DataFrame(), unreadable

    try:
        return pd.DataFrame(all_data), unreadable
    except ValueError as e:
        print(f'\t[!] Could not build the DataFrame: {e}')
        return pd.DataFrame(), list(file_paths)


def json_normalize_with_primary_preference(df, column='metrics', delim = '_', drop_original_column=False):
    """
    Explodes a DataFrame column with nested JSON-like data, prioritizing Primary sources.

    Handles dictionaries and lists of dictionaries within the nested data, 
    prioritizing 'Primary' sources for cvss metrics.

    Args:
        df (pd.DataFrame): The input DataFrame.
        column (str, optional): Column holding the nested data. Defaults to 'metrics'.
        delim (str, optional): Separator joining nested keys. Defaults to '_'.
        drop_original_column (bool, optional): Drop the source column afterwards.
            Defaults to False.

    Returns:
        pd.DataFrame: The DataFrame with the flattened columns appended, or unchanged
            if the column is absent or the expansion fails.
    """

    def process_nested_data(nested_data):
        """
        Flatten one cell's nested data into a single-level dict.

        Returns an empty dict for anything unusable, so one malformed cell cannot fail
        the whole column.
        """
        if nested_data is None:
            return {}

        if isinstance(nested_data, str):
            try:
                nested_data = json.loads(nested_data)
            except json.JSONDecodeError:
                print(f"\t[!] Warning: Invalid JSON string: {nested_data}")
                return {}

        if not isinstance(nested_data, (dict, list)):
            print(f"\t[!] Warning: Not a dictionary or list: {nested_data}")
            return {}


        def flatten(data, prefix=""):
            """
            Helper function that takes a nested dictionary or list and converts it into a flat dictionary
            recursively. The keys are created by joining the nested keys/indices with a delimiter.
            Special handling is implemented for CVSS metric fields to extract primary entries.

            Args:
                data: The nested data structure to flatten. Can be a dictionary, list, or primitive value.
                prefix (str, optional): The current key prefix for the flattened result. Defaults to "".

            Returns:
                None: Leaves are written into the enclosing 'result' dict, keyed by
                    their delimiter-joined path.
            """
            if isinstance(data, dict):
                for key, value in data.items():
                    if key in ('cvssMetricV2', 'cvssMetricV30', 'cvssMetricV31', 'cvssMetricV40'):
                        if isinstance(value, list):
                            primary_entry = None
                            for item in value:
                                # Handle multiple entries for the same metric and keep the Primary
                                if isinstance(item, dict) and item.get('type') == 'Primary':
                                    primary_entry = item
                                    break
                            # Flatten the primary entry if found
                            if primary_entry:
                                flatten(primary_entry, prefix + str(key) + delim)
                            # If there is a list but no primary, use the first item.
                            elif value:
                                flatten(value[0], prefix + str(key) + delim) 
                        # Flatten the dictionary if it is not a list
                        elif isinstance(value, dict):
                            flatten(value, prefix + str(key) + delim)
                        else:
                            # Store the value without the trailing delimiter
                            result[prefix[:-1]] = value
                    else:
                        # Recursive call for other keys
                        flatten(value, prefix + str(key) + delim)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    # Recursive call for list items
                    flatten(item, prefix + str(i) + delim)
            else:
                # Store the value without the trailing delimiter
                result[prefix[:-1]] = data
        
        result = {}
        flatten(nested_data)
        return result

    if column not in df.columns:
        return df

    try:
        expanded_df = df[column].apply(process_nested_data).apply(pd.Series)
        df = pd.concat([df, expanded_df], axis=1)

        if drop_original_column:
            df = df.drop(columns=[column])
        return df

    except Exception as e:
        print(f"An error occurred: {e}")
        return df


def parse_en_description(descriptions):
    """
    Parse the English ('en') description from a list of dictionaries. The function iterates through the list of
    dictionaries, and returns the value associated with the 'lang' key that matches 'en'.

    Args:
        descriptions (list): Description entries, each with a 'lang' and a 'value' key.

    Returns:
        str or None: The English description, or None if there is no English entry or
            the input is not a list.
    """
    
    # Handle cases where 'descriptions' is not a list
    if not isinstance(descriptions, list):
        return None

    for item in descriptions:
        
        # Return the value if a match is found
        if isinstance(item, dict) and item.get('lang') == 'en':          
            return item.get('value')
    
    # Return None if no match is found after iterating through the list
    return None


def parse_weaknesses(weaknesses):
    """
    Extract the distinct CWE identifiers from a CVE's weakness entries.

    Args:
        weaknesses (list): Weakness entries, each holding a 'description' list.

    Returns:
        list or None: Sorted, de-duplicated CWE identifiers, or None if none were found
            or the input is not a list.
    """
    if not isinstance(weaknesses, list):
        return None

    cwes = set()
    for item in weaknesses:
        for desc in item.get('description', []):
            if desc.get('lang') == 'en':
                cwe = desc.get('value')
                if cwe and re.match(r"^CWE-\d+", cwe):  # Check for CWE- followed by at least one digit
                    cwes.add(cwe)
    
    if not cwes:  # Check if the set of CWEs is empty
        return None

    # Convert set to sorted list for consistent order
    cwe_list = sorted(cwes)
    
    return cwe_list


def parse_cpe(configurations):
    """
    Extract the CPEs a CVE is vulnerable to, from its nested configurations tree.

    Args:
        configurations (list): The CVE's 'configurations' structure, nested to an
            arbitrary depth of nodes and cpeMatch entries.

    Returns:
        list or None: Sorted, de-duplicated CPE criteria strings for every cpeMatch
            flagged vulnerable, or None if there are none.
    """
    vulnerable_cpe = set()

    def extract_cpe(obj):
        """Descend through nodes and lists, adding the criteria of every cpeMatch
        marked vulnerable to the enclosing vulnerable_cpe set."""
        if isinstance(obj, list):
            for x in obj: extract_cpe(x)
        elif isinstance(obj, dict):
            for m in obj.get('cpeMatch', []):
                if m.get('vulnerable'): vulnerable_cpe.add(m['criteria'])
            for v in obj.values(): extract_cpe(v)

    extract_cpe(configurations)
    if not vulnerable_cpe:  # Check if the set is empty after processing
        return None

    # Convert set to sorted list for consistent order
    cpe_list = sorted(vulnerable_cpe)
    
    return cpe_list


def parse_reference_urls(references):
    """
    Extract unique reference URLs from the given entry.

    Args:
        references (list): Reference entries, each optionally carrying a 'url' key.

    Returns:
        list or None: Sorted, de-duplicated URLs, or None if there are none or the
            input is not a list.
    """
    if not isinstance(references, list):
        return None

    unique_urls = set()  # Use a set to store unique URLs efficiently

    for item in references:
        if isinstance(item, dict) and 'url' in item:
            url = item['url']
            unique_urls.add(url) # Add the url to the set
    
    if not unique_urls:  # Check if the set is empty after processing
        return None

    # Convert set to sorted list for consistent order
    unique_urls = sorted(unique_urls)
    
    return unique_urls


def parse_cve_nvd(df, drop_parsed_columns=True):
    """
    Parse a DataFrame containing raw CVE data from NVD, extract relevant information, 
    and format it into a standardized structure.
    
    This function processes raw CVE data by:
    - Extracting and normalizing CVE identifiers
    - Processing CVSS metrics with preference for primary sources
    - Extracting English descriptions from multilingual lists
    - Parsing CWE weakness identifiers
    - Extracting reference URLs
    - Processing vulnerable CPE configurations
    - Normalizing timestamps
    - Reorganizing columns in a standardized order
    
    Args:
        df : pandas.DataFrame
            DataFrame containing raw CVE data from NVD
        
        drop_parsed_columns : bool, default=True
            Whether to remove the original complex columns after extracting their data
            
    Returns:
        pandas.DataFrame
            A cleaned and normalized DataFrame with extracted CVE information
    """
    
    # CVE ID
    df['cve'] = df['id']
    
    # Set ID as the index to make sure the data aligns properly and prevent duplicates, and drop the column.
    df.set_index('id', drop=True, inplace=True)
    
    # Extract CVE Metrics with prioritizing Primary source for each
    df = json_normalize_with_primary_preference(df, column='metrics', drop_original_column=False)
    
    # Extract EN description from list
    df['description'] = df['descriptions'].apply(parse_en_description)

    # Parse Weakness IDs and handle cases when the CVEs is missing the information
    if 'weaknesses' not in df.columns:
        df['cwe'] = None
    else:
        df['cwe'] = df['weaknesses'].apply(parse_weaknesses)

    # Parse Reference URLs and handle cases when the CVEs is missing the information
    if 'references' not in df.columns:
        df['referenceUrl'] = None
    else:
        df['referenceUrl'] = df['references'].apply(parse_reference_urls)
    
    # Parse Vulnerable CPEs and handle cases when the CVEs is missing the information
    if 'configurations' not in df.columns:
        df['cpe'] = None
    else:
        df['cpe'] = df['configurations'].apply(parse_cpe)

    # Clean up column names
    df.columns = df.columns.str.replace('MetricV', '')
    df.columns = df.columns.str.replace('cvssData_', '')
    df.columns = df.columns.str.replace('_Automatable', '_automatable')
    df.columns = df.columns.str.replace('_Recovery', '_recovery')
    df.columns = df.columns.str.replace('_Safety', '_safety')
    
    # Normalize timestamps
    df['published'] = df['published'].apply(convert_df_timestamp)
    df['lastModified'] = df['lastModified'].apply(convert_df_timestamp)
    
    # Reindex the DataFrame and put these columns in front
    front_cols = ['cve', 'vulnStatus', 'published', 'lastModified', 'sourceIdentifier', 'description']
    new_order = front_cols + [col for col in df.columns if col not in front_cols]
    df = df[new_order]

    # OPTIONAL: Drop the source parsed columns
    if drop_parsed_columns:
        df.drop(columns=['metrics', 'descriptions','weaknesses', 'references', 'configurations'], inplace=True, errors='ignore')

    return df
