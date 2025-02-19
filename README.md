# nvd-harvester

_**Your go-to tool Efficient Multi-Threaded NVD CVE Data Fetching**_

Tired of wrestling with the NVD CVE API? `nvd-harvester` is an open-source tool designed to efficiently fetch, mirror, and manage NVD CVE data. It provides a robust and reliable solution for keeping your vulnerability database up-to-date.

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

[1] Fetch NVD data
        Initial full NVD dump. It can take a while!
        Total Records: 281831, Chunk Size 2000

        Retrieved: 2000, Remaining: 279831
        Retrieved: 4000, Remaining: 277831
        Retrieved: 6000, Remaining: 275831
        Retrieved: 8000, Remaining: 273831
        Retrieved: 10000, Remaining: 271831
        Retrieved: 12000, Remaining: 269831
        Retrieved: 14000, Remaining: 267831
        ...
        
        Download complete in 14m 10s! Retrieved 281831 CVEs

[2] Process CVE files
        nvd-cve-kb.csv is missing!
        281831 CVE updates.

[3] Extract JSON Data
        Total CVEs: 281831

[4] Write files
        Writing: nvd-cve-kb.csv
```

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Buy Me A Coffee](https://cdn.buymeacoffee.com/buttons/default-orange.png)](https://www.buymeacoffee.com/bgx4k3p)
