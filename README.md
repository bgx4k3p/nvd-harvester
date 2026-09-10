# nvd-harvester

**Download, maintain, and use NVD vulnerability data locally.**

The NVD API's instability makes collecting and maintaining CVE data harder than
it should be. Failed requests and interrupted downloads get in the way of
analysis, reporting, vulnerability management, and automated workflows.
`nvd-harvester` was built to handle that recurring work.

The tool downloads and updates a local copy of NVD vulnerability data, detects
gaps and damaged records, and attempts repairs. It stores individual CVE records
as JSON files and produces a consolidated CSV for querying, filtering, and
use in your own tools and data pipelines.

Once the data is local, your tools and workflows can use it without querying
the NVD API each time. Subsequent runs retrieve new and revised CVEs, while
recovery mechanisms help prevent temporary download failures from becoming
permanent gaps.

## Quick start

Request an API key from the [NVD Developer
Portal](https://nvd.nist.gov/developers/request-an-api-key). An API key is
required for online syncs.

Download or clone this repository, then run the following commands from its root
using Bash or zsh:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export NVD_API_KEY="your_api_key"
python nvd-harvester.py
```

Python 3.12 is the tested runtime, with pandas 2.2.3 and 3.0.5. Source syntax
has also been checked on Python 3.9–3.14; those checks do not establish full
runtime or dependency compatibility on every version.

The first successful run downloads the NVD catalogue and builds the CSV. Run the
same command again to update the mirror. Paths are relative to the working
directory, so use the same directory each time to update the same dataset.

## Output

| Path | Contents |
| --- | --- |
| `data/raw-nvd-json/<year>/<CVE-ID>.json` | Individual CVE records downloaded from NVD, organized by year. |
| `data/nvd-cve-kb.csv` | A consolidated table of flattened CVE fields for analysis and import into other tools. |
| `data/raw-nvd-json/last_update.json` | Timestamps and local counts from successful syncs, plus repair state. |
| `data/raw-nvd-json/local_writes.jsonl` | A journal used to distinguish the tool's own writes from later local edits. |

The CSV includes CVE identifiers, descriptions, timestamps, available CVSS
fields, weaknesses, reference URLs, and affected product CPE information. Use
the JSON records when you need the original nested CVE data; the CSV is an
extracted view of those records.

## Keeping the mirror current

The tool uses the [NVD 2.0 CVE
API](https://nvd.nist.gov/developers/vulnerabilities). Each successful online
run records its start timestamp and the local CVE file count. The next
incremental run requests records modified since that timestamp, including
revisions to existing CVEs even when the total count has not changed. Records
published during a download can arrive in a later modification window.

Run the tool manually or through your scheduler. A six-hour schedule is one
option; the script does not schedule itself. The separate `nvd_cool_off` setting
limits repeated full downloads, as described under [Recovery and
retries](#recovery-and-retries). Run only one harvester process at a time
against a given mirror.

### Reading the sync output

This shortened example shows seven records added to the local mirror and 256
existing records updated:

```text
[*] Local  - JSON: 389414, CSV: 389414, Last sync: 389414
[*] Remote - NVD: 389421 total, 7 new CVEs

[*] NVD download complete in 0m 0s! Retrieved 263 CVEs
[*] Differential sync successful - 389421 CVEs (7 new, 256 updated)
```

The Remote line's "new CVEs" is the positive difference between the remote total
and local file count at startup. It can include missing historical records, so
it does not necessarily mean newly published CVEs. The differential result
reports records added and updated during that download. Counts help detect
shortfalls; equal counts alone do not prove that every CVE is present or
current.

### Rebuilding the CSV offline

To rebuild the CSV from the local JSON files without contacting NVD:

```bash
NVD_SKIP_SYNC=1 python nvd-harvester.py
```

No API key is needed. This is useful after changing CSV output options or when
working without network access. An empty or unreadable corpus fails the rebuild
and preserves any existing CSV and successful sync checkpoint. Offline
rebuilding does not advance the online sync timestamp.

## Recovery and retries

Self-healing means attempting to restore detected gaps or local damage, while
keeping unresolved work available for retry. A sync succeeds only after the
required records are written and the CSV is published or confirmed to need no
update.

| Condition | Response |
| --- | --- |
| An API page is empty, short, or inconsistent with its expected population and metadata | Retry the page; fail the run if retries are exhausted. |
| Duplicate CVE IDs appear within or across pages | Fail the download so repeated records cannot count as a complete result. |
| The mirror remains below NVD's count after an incremental sync | Request a full repair, subject to the cooldown. |
| Local JSON files have detected edits, invalid content, or mismatched identities | Save pending repair IDs and refetch the affected records. |
| More than 500 files need repair | Use a full download, subject to the cooldown, and require the pending IDs to be returned. |
| Local file count falls below the last successful count | Request a full download to recover missing files. |
| The modification window exceeds 120 days | Request a full download instead of sending an unsupported date range. |
| NVD is unavailable or a write fails | Report the failure, retain any previously published output where replacement has not completed, and exit nonzero. |

An empty per-ID response or a request failure leaves the repair pending; it does
not establish that NVD has removed the CVE. An unreadable file encountered while
building the CSV is also queued for repair. More than 500 unreadable files
remain pending for a full repair on a later eligible run.

### Full download cooldown

After the first successful sync, full download attempts are separated by at
least six hours by default. The attempt time is saved before downloading, and
failed attempts count toward the interval. This limits excessive NVD API
requests from repeated full downloads.

Set `nvd_cool_off` in the `VARs` section of `nvd-harvester.py` to change the
interval, in hours. For example, `12` means twelve hours and `0.5` means thirty
minutes.

Until a successful sync checkpoint exists, initialization can retry immediately,
even if a previous attempt saved some CVE files. It repeats the full query
rather than resuming individual pages. If a new install keeps downloading the
catalogue on every invocation, inspect why the first sync cannot complete. Once
that sync succeeds, the cooldown applies. Deleting CVE files from an established
mirror does not exempt it.

Incremental downloads and individual repairs can continue during the cooldown
when the mirror qualifies for an incremental sync. An established mirror that
needs a full rebuild for missing files, a stale window, or bulk repairs waits
until the next eligible time. Deferral shows `YYYY-MM-DD HH:MM:SS UTC` and returns
exit status `1`. The interval runs from the actual full download attempt; a
scheduled invocation arriving just before expiry will still defer the download.

### Failed runs and cached data

JSON files, CSV exports, and sync state are written to temporary files in the
same directory and replaced atomically. A failure before replacement leaves the
previous destination intact. A failed sync can still leave some complete JSON
records updated; the whole mirror is not updated as a single transaction.

The successful sync checkpoint advances only after CSV publication or
confirmation that the CSV needs no update. If CSV replacement succeeds but
checkpoint writing fails, the new CSV remains available and the next run repeats
the uncheckpointed work. Operational state, such as pending repairs, can change
during a failed run.

| Exit status | Meaning |
| --- | --- |
| `0` | The requested online sync or offline rebuild completed. |
| `1` | The operation did not complete. A previously published CSV may still be available. |

Scheduled consumers should distinguish a failed refresh from the absence of
usable cached data and apply their own freshness policy. Failure messages report
whether a published CSV and successful sync checkpoint exist. For a deferred
full download, retry at or after the time shown.

## Configuration

Settings are in the `VARs` and `API config` sections near the top of
`nvd-harvester.py`.

| Setting | Default | What it controls |
| --- | --- | --- |
| `nvd_cool_off` | `6` | Minimum hours between full download attempts after the first successful sync. |
| `max_workers` | `4` | Download threads. Increasing this raises concurrent API load; requests are not globally paced. |
| `attempts` | `20` | Maximum attempts per download/repair request, including the first attempt. |
| `retry_wait` | `4` | Seconds between download/repair retries. |
| `max_local_repairs` | `500` | Pending repair count above which a full download replaces individual refetches. |
| `drop_references` | `False` | Omit the reference URL column from the CSV. |
| `drop_cpe` | `False` | Omit the CPE column from the CSV. |
| `keep_diff_csv` | `False` | Save the changed records as a separate CSV during incremental CSV updates. |

The initial catalogue count probe uses the helper defaults: ten total attempts
with six seconds between retries. HTTP requests use a ten-second connect timeout
and a sixty-second read timeout; these are not a deadline for the entire run.

`NVD_API_KEY` supplies the online API credential. `NVD_SKIP_SYNC=1` selects an
offline CSV rebuild. Both are environment variables; the settings in the table
are edited in the script.

## Sync state

Progress is stored in `data/raw-nvd-json/last_update.json`:

| Field | Meaning |
| --- | --- |
| `last_update` | Start time of the last successful online sync. The next incremental request starts here. |
| `last_nvd_count` | Local CVE file count at that success, despite the legacy field name. A later decrease triggers missing-file recovery. |
| `run_completed` | Completion time of the last successful sync. Also serves as a fallback cursor for detecting edits in older mirrors. |
| `local_scan_started_ns` | Start of the last checkpointed local edit scan, in nanoseconds. Can advance even when the sync fails. |
| `last_full_repair_attempt` | Time of the most recent full attempt. Enforces the cooldown after the first successful sync; absent or null if none was attempted. |
| `pending_repairs` | CVE IDs awaiting restoration. Unresolved IDs survive failures; restored IDs can clear before overall success. Omitted after successful completion. |

A first run can write operational fields before succeeding, while an early
failure may leave no state file at all. The presence of the file alone does not
establish a successful sync: initialization ends when `last_update` has been
recorded.

Deleting the state file discards sync and pending-repair tracking and forces a
full download on the next online run. Existing CVE files remain and are replaced
as matching records arrive. A copied mirror without its successful state is
treated as uninitialized. Older numeric shortfall markers are ignored and do not
suppress repair.

The separate `local_writes.jsonl` journal records filenames, nanosecond
modification times, and sizes before downloaded CVE files replace their
predecessors. The next scan excludes files still matching those writes, saves
detected outside edits and its scan cursor, then rotates the journal. This
prevents writes from an interrupted run from becoming a large queue of false
outside edits. Scanning operates independently of the last successful sync
timestamp, including during initialization.

## Known limitations

- **Completeness:** Counts are a diagnostic. Offset pagination does not provide
  an immutable snapshot, and a catalogue changing during download can affect the
  result.
- **Local validation:** Checks cover file identity and required top-level parser
  fields, not the entire NVD schema or every nested value. They are not a
  checksum audit; changes that preserve timestamps or are overwritten during a
  run may escape detection. Reading a file without changing it does not trigger
  repair.
- **API load:** Retries are bounded per request. There is no global request
  pacing, exponential backoff, jitter, or handling of `Retry-After`. Mirrors
  without a successful sync can repeat full downloads on every invocation until
  initialization completes.
- **Concurrent processes:** The journal coordinates worker threads, but there is
  no lock preventing separate harvester processes from writing the same mirror.
- **Durability:** Atomic replacement protects individual files from failed
  writes. Directory entries are not fsynced, so this is not a guarantee against
  sudden power loss. Different files may reflect different stages of an
  interrupted sync.
- **Performance:** Journal persistence adds disk I/O per CVE. No full catalogue
  performance benchmark is included; throughput depends on the API and local
  storage.

## Tests

The suite runs the real sync against a simulated NVD API in temporary mirrors.
It requires the installed dependencies, but no network connection or API key.

```bash
python -W error tests/test_sync.py
```

Scenarios cover initial and incremental downloads, revisions at unchanged
counts, empty and partial bootstrap recovery, cooldown enforcement after
success, persistent local repairs, malformed and duplicate pages, atomic writes,
offline rebuilding, CSV parsing, and concurrent pagination. `-W error` treats
warnings as errors.

## License

[MIT](LICENSE)
