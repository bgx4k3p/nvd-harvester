# nvd-harvester

`nvd-harvester` mirrors NIST NVD CVE data locally using concurrent NVD 2.0 API
requests and incremental updates. It preserves each CVE as year-organized JSON
and produces an aggregated, SQL-ready CSV for analysis and downstream systems.

The project is designed for repeatable collection when direct API access is too
slow or unreliable for routine analysis. It retains the source records locally,
retries transient API failures, and processes only changed data after the
initial synchronization.

## Key Features

* **NVD 2.0 API Support:**  `nvd-harvester` utilizes the latest [NVD 2.0 RESTful API](https://nvd.nist.gov/developers/vulnerabilities), ensuring access to the most current and authoritative vulnerability information.

* **Robust API Handling:**  The tool includes configurable API parameters to handle potential issues with the NVD API, such as 503 errors during periods of high utilization.

* **Multi-Threaded for Speed:**  Leveraging multi-threading, `nvd-harvester` maximizes performance by concurrently fetching and processing data, making the data updating process significantly faster.

* **Local NVD Mirroring:**  Create and maintain a local mirror of the NVD CVE database for improved access and reliability. This eliminates dependence on potentially unstable API connections and allows for offline data access.

* **Efficient Updates with Diffs:**  After the initial synchronization, the tool uses diffs to identify and download only changed CVE data, significantly improving update speed and efficiency.

* **Organized JSON Output:**  Raw CVE data is stored in individual JSON files, organized by year, facilitating easy access and analysis of specific CVEs.

* **SQL-Ready CSV Output:**  `nvd-harvester` generates an aggregated CSV file containing all CVE information, formatted for seamless upload to SQL databases.

## Getting Started

### 1. Obtain an NVD API Key

   Request a free NVD API key from the [NVD Developer Portal](https://nvd.nist.gov/developers/request-an-api-key).

### 2. Set the API Key as an Environment Variable

   Set the `NVD_API_KEY` environment variable.  This allows the tool to securely access the NVD API without embedding your key directly in the code.

   ```bash
   export NVD_API_KEY="your_actual_api_key_here"
   ```

### 3. Install Dependencies

Install the required Python packages using pip:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

```bash
(.venv) ➜  nvd-harvester git:(main) ✗ python /nvd-harvester/nvd-harvester.py
#####################################################################################
                             Download NIST NVD Database                             
#####################################################################################

[1] Check CVE counts
        [!] File doesn't exist: data/raw-nvd-json/last_update.json
        [*] NVD: 284517, JSON: 0, CSV: 0, Last Sync: 0

[2] Fetch NVD data
        [*] Performing Full sync. Reason: No previous data
        [*] NVD records: 284517, Chunk Size 2000
            Retrieved: 2000, Remaining: 282517
            Retrieved: 4000, Remaining: 280517
            Retrieved: 6000, Remaining: 278517
            Retrieved: 8000, Remaining: 276517
            ...
            Retrieved: 280517, Remaining: 4000
            Retrieved: 282517, Remaining: 2000
            Retrieved: 284517, Remaining: 0

        [*] NVD download complete in 1m 35s! Retrieved 284517 CVEs
        [*] Full sync successful - 284517 CVEs synced

[3] Find CVE JSON file changes
        [*] Processing All 284517 JSON files for full CSV build

[4] Parse CVE JSON files
        [*] All 284517 CVE files processed successfully

[5] Summary
        [*] NVD: 284517, JSON: 284517, CSV: 284517, Last Sync: 0

[6] Write files
        [*] Writing: data/nvd-cve-kb.csv
```

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Buy Me A Coffee](https://cdn.buymeacoffee.com/buttons/default-orange.png)](https://www.buymeacoffee.com/bgx4k3p)
