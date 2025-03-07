import re
import time
import requests
import os
import pandas as pd
import concurrent.futures
from datetime import datetime, timezone
import json

class DownloadError(Exception):
    pass


def greeting(message):
    """
    Display a greeting message.

    :param message: The greeting message to display.
    :type message: str
    """
    l = 85
    p = (l - len(message)) // 2
    print()
    print(f'{l * "#"}')
    print(f'{p * " "}{message}{p * " "}')
    print(f'{l * "#"}')


def runtime(start_time):
    """
    Calculate and return the runtime of the script.

    :param start_time: The start time of the script execution.
    :type start_time: time.time() float or datetime in UTC

    return: str
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
    try:
        with open(path, 'r', encoding='utf-8') as file:
            data = json.load(file)
    except Exception as e:
        print(f'\t{path} - Error: {e}')
        exit(1)
    return data


def get_file_modified_time_utc(file_path):
    """
    Returns the last modified timestamp of a given file in UTC timestamp.

    :param file_path: Path to the file.
    :return: Last modified timestamp (str) in UTC.
    """
    try: 
        # Convert local file modification time to UTC for consistent comparison
        file_mtime = os.path.getmtime(file_path)
        file_mtime_utc = datetime.fromtimestamp(file_mtime).astimezone(timezone.utc)
        return file_mtime_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    except Exception as e:
        print(f'Error: {e}')
        return None


def get_modified_files_since(base_folder, since_timestamp_str, file_pattern=None, buffer_days=0):
    """
    Returns a list of files modified since the specified timestamp.
    
    Args:
        base_folder (str): The root directory to scan for modified files.
        since_timestamp_str (str): ISO 8601 UTC timestamp string (e.g., "2025-03-02T02:32:23Z").
        file_pattern (str, optional): Regex pattern to filter files by name. Defaults to None (all files).
        buffer_days (int, optional): Number of days to subtract from the timestamp for a time buffer. Defaults to 0.
    
    Returns:
        list: List of full paths to files modified after the specified timestamp.
    """
    # Validate inputs
    if not isinstance(since_timestamp_str, str):
        raise TypeError('since_timestamp_str must be a string in ISO 8601 format (e.g., \'2025-03-02T02:32:23Z\')')
    
    if not os.path.isdir(base_folder):
        raise FileNotFoundError(f'Directory not found: {base_folder}')
    
    # Parse the timestamp
    try:
        # Process timestamp once before file scanning
        since_datetime = datetime.fromisoformat(since_timestamp_str.replace('Z', '+00:00'))
        
        # Apply buffer if needed
        if buffer_days > 0:
            since_datetime -= datetime.timedelta(days=buffer_days)
            
        # Store the UTC timestamp for comparison
        since_timestamp = since_datetime.timestamp()
    except ValueError as e:
        raise ValueError(f'Failed to parse timestamp \'{since_timestamp_str}\': {str(e)}')
    
    # Compile regex pattern if provided (once, outside the loop)
    pattern = None
    if file_pattern is not None:
        try:
            pattern = re.compile(file_pattern)
        except re.error as e:
            raise ValueError(f'Invalid regex pattern \'{file_pattern}\': {str(e)}')
    
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
                    # Get file modification time and convert to UTC for comparison
                    file_mtime = os.path.getmtime(file_path)
                    file_mtime_local = datetime.fromtimestamp(file_mtime)
                    file_mtime_utc = file_mtime_local.astimezone(timezone.utc)
                    file_mtime = file_mtime_utc.timestamp()
                    
                    if file_mtime > since_timestamp:
                        modified_files.append(file_path)
                except (FileNotFoundError, PermissionError):
                    # Skip files we can't access (permission issues)
                    continue
                    
    except Exception as e:
        raise RuntimeError(f'Error walking directory {base_folder}: {str(e)}')
        
    return modified_files


def enumerate_files_in_folder(base_folder, pattern=r'CVE-\d{4}-\d{4,}\.json$'):
    '''
    This function enumerates filenames matching the provided regex pattern recursively within base_folder.

    :param base_folder: The root folder where files will be searched.
    :type base_folder: str
    :param pattern: Regular expression pattern to match filenames.
    :type pattern: str
    
    :return: A list of full file paths to matching files.
    :rtype: list[str]
    '''
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

    Parameters:
        timestamp (str or None): The timestamp string to be converted, or None.
        input_format (str): Input datetime format string. Default is format='mixed'.

    Returns:
        str or None: The converted timestamp as a string in UTC format with 'Z',
                     or None if the input timestamp is None.
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

    This function attempts to write the given DataFrame to the specified file path in CSV format.
    If an error occurs during the write process, it prints the error message and exits the program.

    Parameters:
    df (pd.DataFrame): The DataFrame to be written to the CSV file.
    file_path (str): The path to the output CSV file.
    index (bool): Whether to write row names (index). Defaults to False.
    """
    try:
        #print(f'\tWriting: {file_path}')
        df.to_csv(file_path, index=index)
    except Exception as e:
        print(f'\tError! {e}')
        exit(1)


def last_update_write_info(file_path, timestamp, count, last_update_key='last_update', last_count_key='last_nvd_count'):
    """
    Writes the latest update timestamp and count in a JSON file.

    Args:
        file_path (str): The path to the JSON file to be updated.
        timestamp (str): The timestamp of the last update, formatted as a string.
        count (int): The count of items processed during the update.
        last_update_key (str, optional): The key used to store the timestamp in the JSON file. Defaults to 'last_update'.
        last_count_key (str, optional): The key used to store the count in the JSON file. Defaults to 'last_nvd_count'.

    Returns:
        bool: True if the update was successful, False otherwise.

    Example:
        >>> last_update_write_info('last_update.json', '2023-10-27T12:00:00Z', 12345)
        True # Returns True if successful.
    """
    if not isinstance(timestamp, str):
        raise TypeError("timestamp must be a string")
    if not isinstance(count, int):
        raise TypeError("count must be an integer")
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            data = {last_update_key: timestamp, last_count_key: count}
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
        tuple: A tuple containing (timestamp, count) if the file is successfully read and parsed.
               Returns (None, 0) if an error occurs.

    Example:
        >>> last_update_read_info('last_update.json')
        ('2023-10-27T12:00:00Z', 12345)  # If file contains the data
    """
    if not os.path.exists(file_path):
        print(f"\t[!] File doesn't exist: {file_path}")
        return None, 0
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            timestamp = data.get(last_update_key)
            count = data.get(last_count_key)
            return timestamp, count
    except Exception as e:
        print(f'\t[] Error reading {file_path}: {e}')
        return None, 0


def fetch_cve_count_and_chunk_size(base_url, headers, attempts=10, retry_wait=6, params=None):
    """
    Fetches total CVE count an chunk size from the NVD API for ALL CVEs.
    If both lastModStartDate and lastModEndDate are specified, the search is limited to that timeframe.
    Returns the totalResults and resultsPerPage, or exit after exceeding retry attempts.

    Args:
        base_url (str): The base URL of the NVD CVE API.
        headers (dict): HTTP headers for the API requests.
        attempts (int, optional): Maximum retry attempts for API requests. Defaults to 10.
        retry_wait (int, optional): Seconds to wait between retries. Defaults to 6.
        params (dict, optional): Optional parameters for the API calls
    """
    
    # Set parameters
    if not params:
        params = {}
    
    # Get total CVE count and results per page from the API
    for n in range(attempts):
        try:
            response = requests.get(base_url, headers=headers, params=params)
            response.raise_for_status()
            json_data = response.json()
            
            totalResults = json_data['totalResults']
            resultsPerPage = json_data['resultsPerPage']
            
            return totalResults, resultsPerPage
        
        except requests.exceptions.RequestException as e:
            print(f'\t[!] Retry {n+1}, wait {retry_wait}s! Error: {e}')
            time.sleep(retry_wait)
    
    else:  # Exit if all attempts failed
        print(f'\t[!] Failed to get total CVE count after {attempts} attempts. Try again later.')
        exit(1)


def fetch_and_process_chunk(base_url, headers, data_folder, attempts, retry_wait, offset, params):
    """
    This function makes a request to the NVD CVE API with a specified offset,
    processes the retrieved data by extracting and writing CVE information to files,
    and returns the number of CVEs successfully processed in the chunk.

    Args:
        base_url (str): The base URL of the NVD CVE API.
        headers (dict): HTTP headers to be included in the API request.
        data_folder (str): The local directory where CVE JSON files will be stored.
        attempts (int): The maximum number of retry attempts for API requests.
        retry_wait (int): The time (in seconds) to wait between retry attempts.
        offset (int): The starting index for retrieving CVE data from the API.
        params (dict): Parameters for the API calls
    Returns:
        int: The number of CVEs successfully processed in the chunk. Returns None if 
             the request fails after all retry attempts.
    """
    # Update offset in parameters
    params['startIndex'] = offset

    cve_count_chunk = 0
    for n in range(attempts):
        try:
            # API request
            response = requests.get(base_url, headers=headers, params=params)
            response.raise_for_status()
            results = response.json().get('vulnerabilities', [])
            
            # Process the results
            extract_cve_info_and_write_to_files(results, data_folder)
            
            cve_count_chunk = len(results)
            return cve_count_chunk
        
        except requests.exceptions.RequestException as e:
            print(f'\t[!] Error! Retry {n} for offset {params['startIndex']}. {e}')
            time.sleep(retry_wait)
 
    # return None after no more attempts
    return None


def fetch_all_cves_threaded(base_url, headers, data_folder, attempts=10, retry_wait=6, max_workers=3, lastModStartDate=None, lastModEndDate=None):
    """
    Retrieves the total number of CVEs and the chunk size, then fetches all records from the NVD API multi-threaded for speed. 
    Optional lastModStartDate and lastModEndDate provide filtering for CVEs modified during specific timeframe.
    
    Args:
        base_url (str): The base URL of the NVD CVE API.
        headers (dict): HTTP headers for the API requests.
        data_folder (str): The local directory to store CVE JSON files.
        attempts (int, optional): Maximum retry attempts for API requests. Defaults to 10.
        retry_wait (int, optional): Seconds to wait between retries. Defaults to 6.
        max_workers (int, optional): Maximum number of worker threads. Defaults to 3.
        lastModStartDate (datetime, optional): Specify lastModStartDate for CVE changes. Defaults to None.
        lastModEndDate (datetime, optional): Specify lastModEndDate for CVE changes. Defaults to None.
    """
    # Set parameters
    if lastModStartDate and lastModEndDate:
        params = {'lastModStartDate': lastModStartDate, 'lastModEndDate': lastModEndDate}
    else:
        params = {}
        
    # Get total CVE count and results per page from the API
    totalResults, resultsPerPage = fetch_cve_count_and_chunk_size(base_url, headers, attempts, retry_wait, params)
    print(f'\t[*] NVD records: {totalResults}, Chunk Size {resultsPerPage}')

    # Initialize VARs
    offset = 0
    start_download = time.time()
    total_retrieved = 0
    remaining = totalResults
    
    # Fetch data
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        
        # Submitting Tasks to the Executor:
        futures = []
        while offset < totalResults:
            futures.append(executor.submit(fetch_and_process_chunk, base_url, headers, data_folder, attempts, retry_wait, offset, params))
            offset += resultsPerPage

        # Retrieving the results of the tasks 
        for future in concurrent.futures.as_completed(futures):
            try:
                retrieved_count = future.result()
            
                # Raise exception on failed download
                if retrieved_count == -1:
                    raise DownloadError(f'\tMax retries exceeded for data chunk.')

                # Track progress
                total_retrieved += retrieved_count
                remaining = remaining - retrieved_count
                print(f'\t    Retrieved: {total_retrieved}, Remaining: {remaining}')
            
            except DownloadError as e:
                executor.shutdown(wait=False, cancel_futures=True) # Shutdown executor immediately
                print(e)
                print(f'\n\tThe NVD API is currently overloaded. Try again later.')
                exit(1)
            except Exception as e:  # Catch other exceptions
                executor.shutdown(wait=False, cancel_futures=True) # Shutdown executor immediately
                print(e)
                exit(1)

    if totalResults != 0:
        print(f'\n\t[*] NVD download complete in {runtime(start_download)}! Retrieved {total_retrieved} CVEs')
    # else:
    #     print(f'\t[*] No NVD CVE changes.')


def extract_cve_info_and_write_to_files(json_data, output_directory='raw-nvd'):
    """
    Extracts CVE information and groups JSON files in sub-folders by CVE year.

    Args:
        json_data: A list of CVE dictionaries.
        output_directory: The base directory where sub-folders will be created.
    """

    if not isinstance(json_data, list):
        print(f'Error: json_data must be a list. {json_data}')
        return
    
    try:
        os.makedirs(output_directory, exist_ok=True)  # Create base directory

        for cve_entry in json_data:
            if 'cve' in cve_entry and isinstance(cve_entry['cve'], dict) and 'id' in cve_entry['cve']:
                cve_id = cve_entry['cve']['id']

                # Extract the year using a regular expression
                match = re.search(r'CVE-(\d{4})-\d+', cve_id)
                if match:
                    cve_year = match.group(1)
                    year_directory = os.path.join(output_directory, cve_year)
                    os.makedirs(year_directory, exist_ok=True)  # Create year subfolder

                    filename = os.path.join(year_directory, f'{cve_id}.json')
                    try:
                        with open(filename, 'w', encoding='utf-8') as f:
                            json.dump(cve_entry['cve'], f, indent=4, ensure_ascii=False)
                            os.fsync(f.fileno())  # Ensure data is written to disk
                        #print(f'CVE information for {cve_id} written to {filename}')
                    except Exception as e:
                        print(f'\tError writing {cve_id} to file: {e}')
                else:
                    print(f'\tWarning: Could not extract year from CVE ID: {cve_id}')

            else:
                print('\tWarning: Invalid CVE entry found (missing "cve" or "id"). Skipping.')
    except Exception as e:
        print(f'\tAn unexpected error occurred: {e}')


def json_files_combine_concurrent(file_paths, max_workers=None):
    """Combines JSON files into a pandas DataFrame, including file paths.

    Reads each JSON file specified in `file_paths`, processes the data, and
    combines it into a single DataFrame. Includes the file path as a new column.

    Args:
        file_paths: A list of strings, where each string is a path to a JSON file.
        max_workers (int, optional): The maximum number of worker threads.

    Returns:
        A pandas DataFrame containing the combined data and file paths,
        or None if an error occurs. Returns an empty DataFrame if the list of
        file paths is empty or if all files had errors or contained no data.
    """

    if not file_paths:
        return pd.DataFrame()

    all_data = []

    def _read_and_process_json(file_path):
        """Reads and processes a single JSON file, including file path.

        Helper function used by concurrent.futures.

        Args:
            file_path: The path to the JSON file.

        Returns:
            A list of dictionaries, where each dictionary includes the file path,
            or None if an error occurs. Returns an empty list if JSON is invalid.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        item['file_path'] = file_path  # Add file path to each item
                    return data
                elif isinstance(data, dict):
                    data['file_path'] = file_path  # Add file path to the dictionary
                    return [data]
                else:
                    print(f"Warning: JSON data in {file_path} should be a dictionary or a list of dictionaries.")
                    return []
        except FileNotFoundError:
            print(f"Error: File not found: {file_path}")
            return None
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in file: {file_path}")
            return None
        except Exception as e:
            print(f"An error occurred while processing {file_path}: {e}")
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_read_and_process_json, file_path) for file_path in file_paths]

        for future in concurrent.futures.as_completed(futures):
            data = future.result()
            if data is None:
                return None
            all_data.extend(data)

    if not all_data:
        return pd.DataFrame()

    try:
        df = pd.DataFrame(all_data)
        return df
    except Exception as e:
        print(f"An error occurred while creating the DataFrame: {e}")
        return None


def json_normalize_with_primary_preference(df, column='metrics', delim = '_', drop_original_column=False):
    """
    Explodes a DataFrame column with nested JSON-like data, prioritizing Primary sources.

    Handles dictionaries and lists of dictionaries within the nested data, 
    prioritizing 'Primary' sources for cvss metrics.

    Args:
        df: The input DataFrame.
        column: The name of the column containing the nested data.
        drop_original_column: If True, the original column is dropped.
        delim: Delimiter for subkeys. Default '_' .

    Returns:
        A DataFrame with the new columns appended, or the original DataFrame
        if the specified column is not found or an error occurs.
    """

    def process_nested_data(nested_data):
        """
        Helper function to process nested JSON data structure.
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
                None: Results are stored in the global 'result' dictionary where:
                    - Keys are strings representing the flattened hierarchy path
                    - Values are the corresponding leaf values from the input data
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
            df = df.drop(columns=[column], axis=1)
        return df

    except Exception as e:
        print(f"An error occurred: {e}")
        return df


def parse_en_description(descriptions):
    """
    Parse the English ('en') description from a list of dictionaries. The function iterates through the list of
    dictionaries, and returns the value associated with the 'lang' key that matches 'en'.

    Parameters:
    descriptions (list): A JSON string representing a list of dictionaries, each containing a 'lang' key and a 'value' key.

    Returns:
    None: The English description if found, otherwise None.
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
    Extract weakness CWEs from the given entry.

    :param data: List of dictionaries containing CWE descriptions.
    :return: List of extracted CWE values.
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
    cwe_list = sorted(list(cwes))
    
    return cwe_list


def parse_cpe(configurations):
    """
    Extracts CPEs from nested JSON-like data where 'vulnerable' is True.

    Args:
    data (list): A nested structure containing dictionaries and lists, typically resembling a JSON object or similar hierarchical format.

    Returns:
    list: A list of strings representing unique CPEs for which 'vulnerable' is set to True.
    """
    vulnerable_cpe = set()

    def extract_cpe(obj):
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
    cpe_list = sorted(list(vulnerable_cpe))
    
    return cpe_list


def parse_reference_urls(references):
    """
    Extract unique reference URLs from the given entry.

    Args:
        references: A list of reference objects containing URLs.

    Returns:
        A list of unique URLs, or None if the input is invalid.
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
    unique_urls = sorted(list(unique_urls))
    
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

    # Parse Weakness IDs
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
        df.drop(columns=['metrics', 'descriptions','weaknesses', 'references', 'configurations'], axis=1, inplace=True, errors='ignore')

    return df
