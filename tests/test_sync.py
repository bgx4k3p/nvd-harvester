"""
End-to-end tests for nvd-harvester.

Runs the real main() against a simulated NVD API. Nothing here touches the network,
and every scenario asserts on outcomes - files on disk, CSV contents, requests actually
issued - rather than on printed text, so the tests survive wording changes.

Run:  python tests/test_sync.py
"""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import pandas as pd
import requests

from utils import utils

PAGE = 2000


def iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def ago(**kw):
    return iso(datetime.now(timezone.utc) - timedelta(**kw))


class FakeNVD:
    """
    A stand-in for the NVD 2.0 CVE API.

    Holds a catalogue of CVE records keyed by id, serves them paged, and honours the
    lastModified window so that records with old timestamps are genuinely unreachable
    by a differential - the condition that makes a shortfall unrepairable incrementally.
    """

    def __init__(self, count, modified=None, page=PAGE):
        self.page = page
        self.records = {}
        for i in range(count):
            self.add(f'CVE-2026-{i:06d}', last_modified=modified or ago(days=400))
        self.requests = []
        self.offsets = []
        self.fail_count_probe = False
        self.fail_chunks = False
        self.drop_offsets = set()
        self.empty_once_offsets = set()
        self.fail_ids = set()
        self.lock = threading.Lock()

    def add(self, cve_id, last_modified=None):
        self.records[cve_id] = {
            'id': cve_id,
            'published': '2026-01-01T00:00:00.000',
            'lastModified': (last_modified or ago(days=400)).rstrip('Z'),
            'vulnStatus': 'Analyzed',
            'sourceIdentifier': 'test@example.com',
            'descriptions': [{'lang': 'en', 'value': f'description for {cve_id}'}],
            'weaknesses': [{'description': [{'lang': 'en', 'value': 'CWE-79'}]}],
            'references': [{'url': f'https://example.com/{cve_id}'}],
            'configurations': [{'nodes': [{'cpeMatch': [
                {'vulnerable': True, 'criteria': f'cpe:2.3:a:x:y:{cve_id}:*:*:*:*:*:*:*'}]}]}],
            'metrics': {'cvssMetricV31': [{'type': 'Primary', 'cvssData': {'baseScore': 7.5}}]},
        }

    def _matching(self, params):
        ids = sorted(self.records)
        start, end = params.get('lastModStartDate'), params.get('lastModEndDate')
        if start and end:
            s, e = start.rstrip('Z'), end.rstrip('Z')
            ids = [i for i in ids if s <= self.records[i]['lastModified'] <= e]
        return ids

    def get(self, url, headers=None, params=None, **kw):
        params = dict(params or {})
        with self.lock:
            self.requests.append(params)
        probe = 'startIndex' not in params and 'cveId' not in params

        class Response:
            def __init__(self, payload, fail=False):
                self._payload, self._fail = payload, fail

            def raise_for_status(self):
                if self._fail:
                    raise requests.exceptions.RequestException('simulated 503')

            def json(self):
                return self._payload

        if probe:
            if self.fail_count_probe:
                return Response({}, fail=True)
            ids = self._matching(params)
            return Response({'totalResults': len(ids),
                             'resultsPerPage': min(self.page, len(ids))})

        if 'cveId' in params:
            if params['cveId'] in self.fail_ids:
                return Response({}, fail=True)
            record = self.records.get(params['cveId'])
            return Response({'vulnerabilities': [{'cve': record}] if record else []})

        if self.fail_chunks:
            return Response({}, fail=True)

        offset = params['startIndex']
        with self.lock:
            self.offsets.append(offset)
        with self.lock:
            empty = offset in self.drop_offsets or offset in self.empty_once_offsets
            self.empty_once_offsets.discard(offset)
        ids = [] if empty else self._matching(params)[offset:offset + params.get('resultsPerPage', self.page)]
        return Response({'vulnerabilities': [{'cve': self.records[i]} for i in ids],
                         'startIndex': offset, 'resultsPerPage': len(ids)})


class Mirror:
    """A local mirror on disk, in a throwaway directory."""

    def __init__(self):
        self.dir = tempfile.mkdtemp()
        self.repo = f'{self.dir}/data/raw-nvd-json'
        self.csv = f'{self.dir}/data/nvd-cve-kb.csv'
        self.watermark = f'{self.repo}/last_update.json'
        os.makedirs(self.repo, exist_ok=True)

    def seed(self, api, ids=None, watermark=None, count=None, write_csv=True):
        ids = sorted(api.records) if ids is None else ids
        for cve_id in ids:
            year = cve_id.split('-')[1]
            os.makedirs(f'{self.repo}/{year}', exist_ok=True)
            with open(f'{self.repo}/{year}/{cve_id}.json', 'w', encoding='utf-8') as f:
                json.dump(api.records[cve_id], f)
        if watermark:
            utils.last_update_write_info(self.watermark, watermark,
                                         len(ids) if count is None else count)
        if write_csv:
            with open(self.csv, 'w', encoding='utf-8') as f:
                f.write('cve\n' + '\n'.join(ids) + '\n')

    def files(self):
        return len(utils.enumerate_files_in_folder(self.repo)) if os.path.isdir(self.repo) else 0

    def has(self, cve_id):
        return os.path.exists(f'{self.repo}/{cve_id.split("-")[1]}/{cve_id}.json')

    def csv_ids(self):
        if not os.path.exists(self.csv):
            return []
        return sorted(pd.read_csv(self.csv, dtype=str)['cve'].tolist())

    def checkpoint(self):
        return utils.last_update_read_info(self.watermark)

    def pending(self):
        return utils.watermark_read(self.watermark, utils.PENDING_REPAIRS_KEY, [])

    def expire_full_repair(self):
        utils.watermark_merge(self.watermark, **{
            utils.FULL_REPAIR_ATTEMPT_KEY: time.time() - 6 * 3600 - 1})

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.cleanup()

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def run(mirror, api, env=None):
    """Execute the real main() against the fake API, in the mirror's directory."""
    real_get, real_sleep = requests.get, utils.time.sleep
    saved_env, cwd = dict(os.environ), os.getcwd()
    requests.get = api.get
    utils.time.sleep = lambda *a: None
    os.environ['NVD_API_KEY'] = 'test-key'
    for key, value in (env or {}).items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    os.chdir(mirror.dir)
    spec = importlib.util.spec_from_file_location('harvester', f'{REPO}/nvd-harvester.py')
    module = importlib.util.module_from_spec(spec)
    out, code = io.StringIO(), 0
    try:
        spec.loader.exec_module(module)
        with contextlib.redirect_stdout(out):
            module.main()
    except SystemExit as e:
        code = e.code or 0
    finally:
        requests.get, utils.time.sleep = real_get, real_sleep
        os.environ.clear()
        os.environ.update(saved_env)
        os.chdir(cwd)
    return code, out.getvalue()


# --------------------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------------------

def test_fresh_start_downloads_everything():
    api, m = FakeNVD(4500), Mirror()
    code, _ = run(m, api)
    assert code == 0
    assert m.files() == 4500, m.files()
    assert m.csv_ids() == sorted(api.records)
    m.cleanup()


def test_differential_fetches_only_new_records():
    api = FakeNVD(3000)
    m = Mirror()
    m.seed(api, watermark=ago(days=1))
    api.add('CVE-2026-999001', last_modified=ago(minutes=5))
    api.add('CVE-2026-999002', last_modified=ago(minutes=5))
    before = len(api.offsets)
    code, _ = run(m, api)
    assert code == 0
    assert m.files() == 3002, m.files()
    assert m.has('CVE-2026-999001') and m.has('CVE-2026-999002')
    # only the two changed records were downloaded, not the whole catalogue
    fetched = sum(len(r) for r in [api.offsets[before:]])
    assert fetched == 1, fetched
    m.cleanup()


def test_no_changes_downloads_no_records():
    """The window still runs, but an empty one costs a probe and fetches nothing."""
    api = FakeNVD(2500)
    m = Mirror()
    m.seed(api, watermark=ago(days=1))
    code, _ = run(m, api)
    assert code == 0
    assert api.offsets == [], f'records were downloaded with nothing to fetch: {api.offsets}'
    assert m.files() == 2500


def test_nvd_revision_is_picked_up_when_the_total_is_unchanged():
    """
    NVD revises records in place - rescoring CVSS, moving a status on from Awaiting
    Analysis - without the catalogue total changing. Gating the differential on matching
    counts meant those revisions were never collected.
    """
    api = FakeNVD(800)
    m = Mirror()
    m.seed(api, watermark=ago(days=1))
    target = 'CVE-2026-000400'
    api.records[target]['descriptions'] = [{'lang': 'en', 'value': 'REVISED BY NVD'}]
    api.records[target]['lastModified'] = ago(minutes=5).rstrip('Z')

    code, _ = run(m, api)
    assert code == 0
    assert m.files() == 800, 'a revision must not change the count'
    with open(f'{m.repo}/2026/{target}.json', encoding='utf-8') as f:
        assert json.load(f)['descriptions'][0]['value'] == 'REVISED BY NVD'
    row = pd.read_csv(m.csv, dtype=str).set_index('cve').loc[target]
    assert row['description'] == 'REVISED BY NVD', 'the revision must reach the CSV'
    m.cleanup()


def test_new_and_revised_records_are_reported_separately():
    """
    The window returns everything NVD touched. Reporting only the count change makes the
    revisions look like an unexplained surplus, which is what made a real run confusing.
    """
    api = FakeNVD(1000)
    m = Mirror()
    m.seed(api, watermark=ago(days=1))
    for i in range(39):                                  # newly published
        api.add(f'CVE-2026-9{i:05d}', last_modified=ago(minutes=5))
    for cve_id in sorted(api.records)[:228]:             # revised in place
        api.records[cve_id]['lastModified'] = ago(minutes=5).rstrip('Z')

    code, out = run(m, api)
    assert code == 0
    assert '(39 new, 228 updated)' in out, out
    assert m.files() == 1039
    m.cleanup()


def test_missing_records_are_repaired_automatically():
    """The case that motivated this: old records absent, unreachable by any window."""
    api = FakeNVD(5000)
    m = Mirror()
    stale = sorted(api.records)[:4000]          # mirror holds only 4000 of 5000
    m.seed(api, ids=stale, watermark=ago(days=1))
    assert not m.has('CVE-2026-004500')
    code, _ = run(m, api)
    assert code == 0
    assert m.files() == 5000, m.files()
    assert m.has('CVE-2026-004500'), 'repair did not recover the missing records'
    assert m.csv_ids() == sorted(api.records)
    assert m.pending() == [], 'pending repairs should clear after success'
    m.cleanup()


def test_incomplete_page_is_retried_after_api_recovers():
    api = FakeNVD(5000)
    api.drop_offsets = {4000}                   # this page never arrives, ever
    m = Mirror()
    m.seed(api, ids=sorted(api.records)[:4000], watermark=ago(days=1))

    checkpoint = m.checkpoint()
    old_csv = Path(m.csv).read_bytes()
    code, _ = run(m, api)
    assert code == 1
    assert m.checkpoint() == checkpoint
    assert Path(m.csv).read_bytes() == old_csv
    first_round = len(api.offsets)
    assert first_round > 0

    api.offsets.clear()
    api.drop_offsets.clear()
    m.expire_full_repair()
    code, _ = run(m, api)
    assert code == 0
    assert 4000 in api.offsets
    assert m.files() == 5000
    assert m.csv_ids() == sorted(api.records)
    m.cleanup()


def test_stale_watermark_skips_the_rejected_window():
    api = FakeNVD(3000)
    m = Mirror()
    m.seed(api, ids=sorted(api.records)[:2000], watermark=ago(days=550))
    code, _ = run(m, api)
    assert code == 0
    # a 550-day window would be refused by NVD, so no windowed request may be sent
    assert not any('lastModStartDate' in r for r in api.requests)
    assert m.files() == 3000
    m.cleanup()


def test_deleted_local_files_trigger_a_full_pull():
    api = FakeNVD(3000)
    m = Mirror()
    m.seed(api, watermark=ago(days=1))
    for cve_id in sorted(api.records)[:500]:     # simulate files lost on disk
        os.remove(f'{m.repo}/2026/{cve_id}.json')
    assert m.files() == 2500
    code, _ = run(m, api)
    assert code == 0
    assert m.files() == 3000
    m.cleanup()


def test_missing_csv_is_rebuilt_from_local_json():
    api = FakeNVD(2000)
    m = Mirror()
    m.seed(api, watermark=ago(days=1), write_csv=False)
    code, _ = run(m, api)
    assert code == 0
    assert m.csv_ids() == sorted(api.records)
    m.cleanup()


def test_api_outage_keeps_the_existing_mirror():
    api = FakeNVD(2000)
    m = Mirror()
    m.seed(api, watermark=ago(days=1))
    api.fail_count_probe = True
    code, _ = run(m, api)
    assert code == 1, 'cached data remains usable, but the sync must report failure'
    assert m.files() == 2000, 'existing data must survive an outage'
    assert m.csv_ids() == sorted(api.records)
    m.cleanup()


def test_api_outage_with_no_data_exits_nonzero():
    api, m = FakeNVD(2000), Mirror()
    api.fail_count_probe = True
    code, _ = run(m, api)
    assert code == 1, code
    m.cleanup()


def test_chunk_failure_keeps_the_existing_mirror():
    api = FakeNVD(3000)
    m = Mirror()
    m.seed(api, ids=sorted(api.records)[:2000], watermark=ago(days=1))
    api.fail_chunks = True
    code, _ = run(m, api)
    assert code == 1
    assert m.files() == 2000, 'a failed sync must not damage what is on disk'
    m.cleanup()


def test_offline_mode_rebuilds_without_network_or_key():
    api = FakeNVD(2000)
    m = Mirror()
    m.seed(api, watermark=ago(days=1), write_csv=False)
    env = dict(os.environ)
    env.pop('NVD_API_KEY', None)
    real = dict(os.environ)
    os.environ.pop('NVD_API_KEY', None)
    try:
        code, _ = run(m, api, env={'NVD_SKIP_SYNC': '1', 'NVD_API_KEY': None})
    finally:
        os.environ.clear()
        os.environ.update(real)
    assert code == 0
    assert api.requests == [], 'offline mode must not contact the API'
    assert m.csv_ids() == sorted(api.records)
    m.cleanup()


def test_csv_contents_match_the_json_on_disk():
    api = FakeNVD(1500)
    m = Mirror()
    code, _ = run(m, api)
    assert code == 0
    df = pd.read_csv(m.csv, dtype=str)
    assert len(df) == m.files() == 1500
    assert df['cve'].is_unique
    assert df['description'].notna().all()
    assert df['cwe'].notna().all()
    assert 'cvss31_baseScore' in df.columns
    m.cleanup()


def _pages_requested(workers, chunks):
    """Run the real fetch loop against a stub and report which offsets it asked for."""
    total = chunks
    seen = []
    lock = threading.Lock()

    class Page:
        def __init__(self, offset=0):
            self.offset = offset

        def raise_for_status(self):
            pass

        def json(self):
            return {'vulnerabilities': [{'cve': {'id': f'CVE-2026-{self.offset:06d}'}}],
                    'startIndex': self.offset, 'resultsPerPage': 1}

    class Probe(Page):
        def json(self):
            return {'totalResults': total, 'resultsPerPage': 1}

    def get(url, headers=None, params=None, **kw):
        if 'startIndex' not in params:
            return Probe()
        with lock:
            seen.append(params['startIndex'])
        return Page(params['startIndex'])

    real_get, real_sleep = requests.get, utils.time.sleep
    requests.get, utils.time.sleep = get, lambda *a: None
    try:
        with contextlib.redirect_stdout(io.StringIO()), patch.object(
                utils, 'extract_cve_info_and_write_to_files',
                side_effect=lambda records, _, **_kw: {entry['cve']['id'] for entry in records}):
            utils.fetch_all_cves_threaded('http://x', {}, tempfile.mkdtemp(),
                                          attempts=1, retry_wait=0, max_workers=workers)
    finally:
        requests.get, utils.time.sleep = real_get, real_sleep
    return seen, set(range(total))


def test_no_page_is_skipped_under_concurrency():
    """Regression: workers once shared one params dict and overwrote each other."""
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)          # force frequent preemption to expose any race
    try:
        for workers in (4, 8, 16):
            seen, expected = _pages_requested(workers, chunks=400)
            skipped = expected - set(seen)
            duplicated = len(seen) - len(set(seen))
            assert not skipped, f'{workers} workers: {len(skipped)} pages never requested'
            assert not duplicated, f'{workers} workers: {duplicated} pages requested twice'
    finally:
        sys.setswitchinterval(previous)


def test_corrupted_local_file_is_repaired_before_export():
    """A damaged file must not abort the run, and must not lose the row already held."""
    api = FakeNVD(1200)
    m = Mirror()
    m.seed(api, watermark=ago(days=1))
    target = 'CVE-2026-000500'
    with open(f'{m.repo}/2026/{target}.json', 'w', encoding='utf-8') as f:
        f.write('{ not valid json')

    code, out = run(m, api)
    assert code == 0, f'a single bad file aborted the run: {out[-400:]}'
    assert 'Skipped 1 unreadable file' in out, 'the skip must be reported, not silent'
    # The incremental CSV path keeps rows it already had, so the previously parsed
    # record survives the file being damaged.
    assert len(m.csv_ids()) == 1200, len(m.csv_ids())
    assert target in m.csv_ids()
    m.cleanup()


def test_corrupted_file_on_a_full_rebuild_is_repaired():
    """Do not publish an incomplete export when the damaged record can be restored."""
    api = FakeNVD(1200)
    m = Mirror()
    m.seed(api, watermark=ago(days=1), write_csv=False)
    target = 'CVE-2026-000500'
    with open(f'{m.repo}/2026/{target}.json', 'w', encoding='utf-8') as f:
        f.write('{ not valid json')

    code, out = run(m, api)
    assert code == 0
    assert 'Skipped 1 unreadable file' in out
    assert len(m.csv_ids()) == 1200, len(m.csv_ids())
    assert target in m.csv_ids()
    assert m.pending() == []
    m.cleanup()


def test_untouched_mirror_flags_no_edits():
    """The tool's own writes must never be mistaken for outside edits."""
    api = FakeNVD(600)
    m = Mirror()
    m.seed(api, watermark=ago(days=1))
    run(m, api)                               # stamps the finish time
    code, out = run(m, api)
    assert code == 0
    assert 'outside this tool' not in out, out
    m.cleanup()


def test_hand_edited_file_is_detected_and_restored():
    """A local edit is invisible to NVD's window, so it is refetched by id."""
    api = FakeNVD(600)
    m = Mirror()
    m.seed(api, watermark=ago(days=1))
    run(m, api)
    target = 'CVE-2026-000300'
    path = f'{m.repo}/2026/{target}.json'
    time.sleep(0.05)
    with open(path, encoding='utf-8') as f:
        record = json.load(f)
    record['descriptions'] = [{'lang': 'en', 'value': 'LOCALLY EDITED'}]
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(record, f)

    code, out = run(m, api)
    assert code == 0
    assert 'Restored 1 CVE file' in out
    with open(path, encoding='utf-8') as f:
        assert json.load(f)['descriptions'][0]['value'] == f'description for {target}'
    row = pd.read_csv(m.csv, dtype=str).set_index('cve').loc[target]
    assert row['description'] == f'description for {target}', 'the CSV must show the restored text'
    m.cleanup()


def test_corrupted_file_is_detected_and_restored():
    """Corruption is caught by the same mtime check and repaired by id."""
    api = FakeNVD(600)
    m = Mirror()
    m.seed(api, watermark=ago(days=1))
    run(m, api)
    target = 'CVE-2026-000400'
    path = f'{m.repo}/2026/{target}.json'
    time.sleep(0.05)
    with open(path, 'w', encoding='utf-8') as f:
        f.write('{ corrupted')

    code, out = run(m, api)
    assert code == 0
    assert 'Restored 1 CVE file' in out
    with open(path, encoding='utf-8') as f:
        assert json.load(f)['id'] == target, 'the file must be valid JSON again'
    m.cleanup()


def test_mass_local_change_triggers_a_full_repair():
    """A restored backup or bulk touch should not become thousands of requests."""
    api = FakeNVD(600)
    m = Mirror()
    m.seed(api, watermark=ago(days=1))
    run(m, api)
    time.sleep(0.05)
    now = time.time()
    for path in utils.enumerate_files_in_folder(m.repo):
        os.utime(path, (now, now))            # e.g. a wholesale restore from backup

    before = len([r for r in api.requests if 'cveId' in r])
    code, out = run(m, api)
    after = len([r for r in api.requests if 'cveId' in r])
    assert code == 0
    assert 'files need repair; performing a full pull' in out
    assert after == before, 'a bulk change must not trigger per-file requests'
    assert m.pending() == []
    m.cleanup()


def test_window_limit_boundary():
    assert utils.window_exceeds_api_limit(ago(days=119)) is False
    assert utils.window_exceeds_api_limit(ago(days=121)) is True
    assert utils.window_exceeds_api_limit(None) is False
    assert utils.window_exceeds_api_limit('not a date') is False


def test_empty_page_recovers_within_the_retry_budget():
    api = FakeNVD(6, page=2)
    api.empty_once_offsets = {2}
    with Mirror() as m:
        code, _ = run(m, api)
        assert code == 0
        assert api.offsets.count(2) == 2
        assert m.csv_ids() == sorted(api.records)


def test_legacy_gap_marker_does_not_suppress_repair():
    api = FakeNVD(6, page=2)
    with Mirror() as m:
        m.seed(api, ids=sorted(api.records)[:4], watermark=ago(days=1))
        utils.watermark_merge(m.watermark, repair_attempted_gap=2)
        code, _ = run(m, api)
        assert code == 0
        assert m.csv_ids() == sorted(api.records)
        assert 'repair_attempted_gap' not in json.loads(Path(m.watermark).read_text())


def test_failed_local_repair_stays_pending_until_api_recovers():
    api = FakeNVD(3)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        run(m, api)
        checkpoint = m.checkpoint()
        old_csv = Path(m.csv).read_bytes()
        target = min(api.records)
        path = Path(m.repo) / '2026' / f'{target}.json'
        path.write_text('{ broken')
        api.fail_ids.add(target)
        code, out = run(m, api)
        assert code == 1
        assert 'no longer served' not in out
        assert m.checkpoint() == checkpoint
        assert target in m.pending()
        assert Path(m.csv).read_bytes() == old_csv
        api.fail_ids.clear()
        api.requests.clear()
        code, _ = run(m, api)
        assert code == 0
        assert any(r.get('cveId') == target for r in api.requests)
        assert json.loads(path.read_text()) == api.records[target]
        assert m.pending() == []


def test_bulk_repair_survives_a_failed_full_pull():
    api = FakeNVD(501)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        run(m, api)
        checkpoint = m.checkpoint()
        old_csv = Path(m.csv).read_bytes()
        for path in utils.enumerate_files_in_folder(m.repo):
            record = json.loads(Path(path).read_text())
            record['descriptions'][0]['value'] = 'BAD BULK EDIT'
            Path(path).write_text(json.dumps(record))
        api.fail_chunks = True
        code, _ = run(m, api)
        assert code == 1
        assert len(m.pending()) == 501
        assert m.checkpoint() == checkpoint
        assert Path(m.csv).read_bytes() == old_csv
        api.fail_chunks = False
        m.expire_full_repair()
        code, _ = run(m, api)
        assert code == 0
        assert m.pending() == []
        df = pd.read_csv(m.csv)
        assert not (df['description'] == 'BAD BULK EDIT').any()
        assert not any('cveId' in r for r in api.requests)


def test_failed_json_replacement_preserves_revision_for_replay():
    api = FakeNVD(3)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        checkpoint = m.checkpoint()
        target = min(api.records)
        path = Path(m.repo) / '2026' / f'{target}.json'
        old_json, old_csv = path.read_bytes(), Path(m.csv).read_bytes()
        api.records[target]['descriptions'][0]['value'] = 'REVISED'
        api.records[target]['lastModified'] = ago(minutes=5).rstrip('Z')
        real_replace = os.replace

        def fail_replace(src, dst):
            if os.path.realpath(dst) == os.path.realpath(path):
                raise PermissionError('simulated write failure')
            return real_replace(src, dst)

        with patch.object(os, 'replace', side_effect=fail_replace):
            code, _ = run(m, api)
        assert code == 1
        assert path.read_bytes() == old_json
        assert Path(m.csv).read_bytes() == old_csv
        assert m.checkpoint() == checkpoint
        assert not list(path.parent.glob('*.tmp'))
        code, _ = run(m, api)
        assert code == 0
        assert json.loads(path.read_text())['descriptions'][0]['value'] == 'REVISED'
        assert pd.read_csv(m.csv).set_index('cve').loc[target, 'description'] == 'REVISED'


def test_interrupted_json_serialization_preserves_the_previous_file():
    api = FakeNVD(1)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        path = Path(m.repo) / '2026' / 'CVE-2026-000000.json'
        old_json = path.read_bytes()

        def partial_dump(_record, handle, **_kwargs):
            handle.write('{"id":')
            raise OSError('simulated disk full during serialization')

        with patch.object(json, 'dump', side_effect=partial_dump):
            try:
                utils.extract_cve_info_and_write_to_files([{'cve': api.records['CVE-2026-000000']}], m.repo)
            except utils.DownloadError:
                pass
            else:
                raise AssertionError('A persistence failure must reach the caller')
        assert path.read_bytes() == old_json
        assert not list(path.parent.glob('*.tmp'))


def test_failed_csv_publication_preserves_csv_and_checkpoint():
    api = FakeNVD(3)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        checkpoint = m.checkpoint()
        old_csv = Path(m.csv).read_bytes()
        api.add('CVE-2026-999999', last_modified=ago(minutes=5))

        def partial_csv(_df, handle, **_kwargs):
            handle.write('cve\nCVE-2026-')
            raise OSError('simulated disk full during CSV publication')

        with patch.object(pd.DataFrame, 'to_csv', partial_csv):
            code, _ = run(m, api)
        assert code == 1
        assert Path(m.csv).read_bytes() == old_csv
        assert m.checkpoint() == checkpoint
        code, _ = run(m, api)
        assert code == 0
        assert m.csv_ids() == sorted(api.records)


def test_only_changed_file_is_corrupt_and_repair_can_be_retried():
    api = FakeNVD(3)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        for path in utils.enumerate_files_in_folder(m.repo):
            os.utime(path, (time.time() - 172800,) * 2)
        os.utime(m.csv, (time.time() - 86400,) * 2)
        target = min(api.records)
        path = Path(m.repo) / '2026' / f'{target}.json'
        path.write_text('{ broken')
        old_csv = Path(m.csv).read_bytes()
        api.fail_ids.add(target)
        code, _ = run(m, api)
        assert code == 1
        assert Path(m.csv).read_bytes() == old_csv
        assert target in m.pending()
        api.fail_ids.clear()
        code, _ = run(m, api)
        assert code == 0
        assert m.csv_ids() == sorted(api.records)
        assert json.loads(path.read_text()) == api.records[target]


def test_offline_empty_and_corrupt_batches_exit_cleanly():
    api = FakeNVD(1)
    with Mirror() as m:
        code, out = run(m, api, env={'NVD_SKIP_SYNC': '1', 'NVD_API_KEY': None})
        assert code == 1 and 'No CVE records' in out
        assert not Path(m.csv).exists()
        m.seed(api, watermark=ago(days=1))
        old_csv = Path(m.csv).read_bytes()
        path = Path(m.repo) / '2026' / 'CVE-2026-000000.json'
        path.write_text('{ broken')
        checkpoint = Path(m.watermark).read_bytes()
        code, _ = run(m, api, env={'NVD_SKIP_SYNC': '1', 'NVD_API_KEY': None})
        assert code == 1
        assert Path(m.csv).read_bytes() == old_csv
        assert Path(m.watermark).read_bytes() == checkpoint
        assert api.requests == []


def test_wrong_record_identity_is_not_published():
    api = FakeNVD(3)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        target = min(api.records)
        path = Path(m.repo) / '2026' / f'{target}.json'
        record = json.loads(path.read_text())
        record['id'] = 'CVE-2026-999999'
        path.write_text(json.dumps(record))
        code, _ = run(m, api)
        assert code == 0
        assert m.csv_ids() == sorted(api.records)


def test_checkpoint_replacement_failure_keeps_the_previous_state():
    with Mirror() as m:
        utils.last_update_write_info(m.watermark, ago(days=1), 3)
        before = Path(m.watermark).read_bytes()
        with patch.object(os, 'replace', side_effect=OSError('simulated checkpoint failure')):
            assert not utils.last_update_write_info(m.watermark, ago(minutes=1), 4)
        assert Path(m.watermark).read_bytes() == before
        assert not list(Path(m.repo).glob('*.tmp'))


def test_overlapping_pages_do_not_count_as_a_complete_download():
    api = FakeNVD(6, page=2)
    real_get = api.get

    def repeated_page(url, headers=None, params=None, **kw):
        response = real_get(url, headers, params, **kw)
        if params and params.get('startIndex') == 2:
            response._payload['vulnerabilities'] = [
                {'cve': api.records[cve_id]} for cve_id in sorted(api.records)[:2]]
        return response

    api.get = repeated_page
    with Mirror() as m:
        code, _ = run(m, api)
        assert code == 1
        assert not Path(m.csv).exists()
        assert m.checkpoint() == (None, 0)
        assert utils.watermark_read(m.watermark, utils.FULL_REPAIR_ATTEMPT_KEY) is not None


def test_full_pull_cannot_clear_a_repair_that_nvd_did_not_return():
    api = FakeNVD(501)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        checkpoint = m.checkpoint()
        pending = [*api.records, 'CVE-2026-999999']
        utils.watermark_merge(m.watermark, **{utils.PENDING_REPAIRS_KEY: pending})
        old_csv = Path(m.csv).read_bytes()
        code, _ = run(m, api)
        assert code == 1
        assert 'CVE-2026-999999' in m.pending()
        assert m.checkpoint() == checkpoint
        assert Path(m.csv).read_bytes() == old_csv


def test_invalid_per_id_response_keeps_the_repair_pending():
    api = FakeNVD(1)
    real_get = api.get

    def invalid_record(url, headers=None, params=None, **kw):
        response = real_get(url, headers, params, **kw)
        if params and 'cveId' in params:
            response._payload['vulnerabilities'] = [None]
        return response

    api.get = invalid_record
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        utils.watermark_merge(m.watermark, **{utils.PENDING_REPAIRS_KEY: ['CVE-2026-000000']})
        checkpoint = m.checkpoint()
        code, _ = run(m, api)
        assert code == 1
        assert m.pending() == ['CVE-2026-000000']
        assert m.checkpoint() == checkpoint


def run_with_count_skew(mirror, api):
    """Startup count is one higher than the complete catalogue served to full pulls."""
    real_get = api.get
    first = True

    def get(*args, **kwargs):
        nonlocal first
        response = real_get(*args, **kwargs)
        if first:
            first = False
            response._payload['totalResults'] += 1
        return response

    with patch.object(api, 'get', side_effect=get):
        return run(mirror, api)


def full_pages(api):
    return [r for r in api.requests if 'startIndex' in r and 'lastModStartDate' not in r]


def test_persistent_shortfall_does_not_amplify_across_runs():
    api = FakeNVD(1000, page=200)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        assert run(m, api)[0] == 0
        checkpoint, old_csv = m.checkpoint(), Path(m.csv).read_bytes()
        completion = utils.watermark_read(m.watermark, utils.RUN_COMPLETED_KEY)
        for invocation in range(3):
            api.requests.clear()
            code, out = run_with_count_skew(m, api)
            assert code == 1
            assert len(full_pages(api)) == (5 if invocation == 0 else 0)
            assert m.pending() == []
            assert Path(m.watermark).stat().st_size < 1024
            assert m.checkpoint() == checkpoint
            assert utils.watermark_read(m.watermark, utils.RUN_COMPLETED_KEY) == completion
            assert Path(m.csv).read_bytes() == old_csv
            if invocation:
                assert 'Full repair deferred until' in out
                displayed = out.split('Full repair deferred until ', 1)[1].split(' UTC', 1)[0]
                assert datetime.strptime(displayed, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
                assert 'retry the full download at or after that time' in out
                assert 'retry next run' not in out
                assert 'Published CSV is unchanged.' in out
                assert (Path(m.repo) / 'local_writes.jsonl').stat().st_size == 0
        m.expire_full_repair()
        api.requests.clear()
        assert run_with_count_skew(m, api)[0] == 1
        assert len(full_pages(api)) == 5
        assert m.pending() == []
        assert run(m, api)[0] == 0
        assert m.csv_ids() == sorted(api.records)
        assert utils.watermark_read(m.watermark, utils.FULL_REPAIR_ATTEMPT_KEY) is not None


def test_real_edit_is_repaired_during_shortfall_cooldown():
    api = FakeNVD(3)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        assert run(m, api)[0] == 0
        assert run_with_count_skew(m, api)[0] == 1
        checkpoint = m.checkpoint()
        target = min(api.records)
        path = Path(m.repo) / '2026' / f'{target}.json'
        path.write_text('{ external damage')
        api.requests.clear()
        assert run_with_count_skew(m, api)[0] == 1
        assert [r['cveId'] for r in api.requests if 'cveId' in r] == [target]
        assert not full_pages(api)
        assert json.loads(path.read_text()) == api.records[target]
        assert m.pending() == []
        assert m.checkpoint() == checkpoint


def test_failed_bootstrap_retries_and_preserves_pending_edits():
    api = FakeNVD(3)
    with Mirror() as m:
        assert run_with_count_skew(m, api)[0] == 1
        assert m.checkpoint() == (None, 0)
        assert utils.watermark_read(m.watermark, utils.RUN_COMPLETED_KEY) is None
        assert utils.watermark_read(m.watermark, utils.LOCAL_SCAN_KEY) is not None
        target = min(api.records)
        path = Path(m.repo) / '2026' / f'{target}.json'
        path.write_text('{ outside edit')
        api.fail_chunks = True
        for _ in range(2):
            api.requests.clear()
            assert run(m, api)[0] == 1
            assert full_pages(api)
            assert m.pending() == [target]
            assert not Path(m.csv).exists()
        api.fail_chunks = False
        assert run(m, api)[0] == 0
        assert m.pending() == []
        assert json.loads(path.read_text()) == api.records[target]


def test_failed_full_attempt_is_checkpointed_before_network_work():
    api = FakeNVD(3)
    with Mirror() as m:
        m.seed(api, ids=sorted(api.records)[:1], watermark=ago(days=130), write_csv=False)
        real_fetch = utils.fetch_all_cves_threaded

        def fail_after_checkpoint(*args, **kwargs):
            assert utils.watermark_read(m.watermark, utils.FULL_REPAIR_ATTEMPT_KEY) is not None
            raise utils.DownloadError('simulated interruption before full query')

        with patch.object(utils, 'fetch_all_cves_threaded', side_effect=fail_after_checkpoint):
            assert run(m, api)[0] == 1
        with patch.object(utils, 'fetch_all_cves_threaded', wraps=real_fetch) as fetch:
            assert run(m, api)[0] == 1
            assert not fetch.called
        m.expire_full_repair()
        assert run(m, api)[0] == 0


def test_empty_bootstrap_retries_without_waiting_or_deleting_state():
    api = FakeNVD(3)
    with Mirror() as m:
        api.fail_chunks = True
        for _ in range(2):
            api.requests.clear()
            code, out = run(m, api)
            assert code == 1
            assert full_pages(api), 'empty initialization must attempt the download again'
            assert m.files() == 0
            assert m.checkpoint() == (None, 0)
            assert utils.watermark_read(m.watermark, utils.FULL_REPAIR_ATTEMPT_KEY) is not None
            assert 'No published CSV is available.' in out
            assert 'No successful sync checkpoint has been recorded.' in out
            assert 'CSV and sync checkpoint are unchanged' not in out
            assert 'Full repair deferred until' not in out
        api.fail_chunks = False
        api.requests.clear()
        assert run(m, api)[0] == 0
        assert len(full_pages(api)) == 1
        assert m.csv_ids() == sorted(api.records)
        assert m.checkpoint()[0] is not None


def test_partial_bootstrap_retries_immediately_then_gates_after_success():
    api = FakeNVD(2, page=1)
    api.drop_offsets = {1}
    with Mirror() as m:
        assert run(m, api)[0] == 1
        assert m.files() == 1
        assert m.checkpoint() == (None, 0)
        api.drop_offsets.clear()
        api.requests.clear()
        code, out = run(m, api)
        assert code == 0
        assert len(full_pages(api)) == 2
        assert 'Full repair deferred until' not in out
        assert m.csv_ids() == sorted(api.records)
        assert m.checkpoint()[0] is not None
        checkpoint, old_csv = m.checkpoint(), Path(m.csv).read_bytes()
        api.requests.clear()
        code, out = run_with_count_skew(m, api)
        assert code == 1 and 'Full repair deferred until' in out
        assert not full_pages(api)
        assert m.checkpoint() == checkpoint
        assert Path(m.csv).read_bytes() == old_csv


def test_deleting_all_files_from_an_established_mirror_does_not_bypass_cooldown():
    api = FakeNVD(3)
    with Mirror() as m:
        assert run(m, api)[0] == 0
        checkpoint, old_csv = m.checkpoint(), Path(m.csv).read_bytes()
        for path in utils.enumerate_files_in_folder(m.repo):
            Path(path).unlink()
        assert m.files() == 0
        api.requests.clear()
        code, out = run(m, api)
        assert code == 1 and 'Full repair deferred until' in out
        assert not full_pages(api)
        assert m.checkpoint() == checkpoint
        assert Path(m.csv).read_bytes() == old_csv
        assert 'Published CSV is unchanged.' in out
        assert 'Last successful sync checkpoint is unchanged.' in out


def test_failed_attempt_checkpoint_prevents_full_download():
    api = FakeNVD(3)
    real_merge = utils.watermark_merge

    def merge(path, **fields):
        if utils.FULL_REPAIR_ATTEMPT_KEY in fields:
            return False
        return real_merge(path, **fields)

    with Mirror() as m, patch.object(utils, 'watermark_merge', side_effect=merge):
        assert run(m, api)[0] == 1
        assert len(api.requests) == 1
        assert not full_pages(api)
        assert m.checkpoint() == (None, 0)


def test_journal_failure_leaves_existing_json_intact():
    api = FakeNVD(1)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        target = min(api.records)
        path = Path(m.repo) / '2026' / f'{target}.json'
        before = path.read_bytes()
        checkpoint = m.checkpoint()
        api.records[target]['lastModified'] = ago(minutes=1).rstrip('Z')
        with patch.object(utils.LocalWriteJournal, 'record', side_effect=OSError('journal disk failure')):
            assert run(m, api)[0] == 1
        assert path.read_bytes() == before
        assert m.checkpoint() == checkpoint
        assert not list(path.parent.glob('*.tmp'))
        assert run(m, api)[0] == 0


def test_journal_survives_scan_checkpoint_failure():
    api = FakeNVD(3)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        assert run_with_count_skew(m, api)[0] == 1
        journal = Path(m.repo) / 'local_writes.jsonl'
        before = journal.read_bytes()
        api.requests.clear()
        with patch.object(utils, 'watermark_merge', return_value=False):
            assert run_with_count_skew(m, api)[0] == 1
        assert journal.read_bytes() == before
        assert not full_pages(api)
        assert run_with_count_skew(m, api)[0] == 1
        assert m.pending() == []


def test_journal_tail_and_unapplied_replacement_do_not_hide_edits():
    with Mirror() as m:
        journal = utils.LocalWriteJournal(f'{m.repo}/local_writes.jsonl')
        path = Path(m.repo) / 'CVE-2026-000001.json'
        path.write_text('original')
        cutoff = time.time_ns()
        with patch.object(os, 'replace', side_effect=OSError('interrupted replacement')):
            try:
                with utils.atomic_text_file(path, before_replace=journal.record) as f:
                    f.write('never replaced')
            except OSError:
                pass
            else:
                raise AssertionError('replacement should fail')
        path.write_text('outside edit')
        with open(journal.path, 'a', encoding='utf-8') as f:
            f.write('["incomplete')
        assert utils.find_external_edits([str(path)], cutoff, journal.read()) == [str(path)]
        assert path.read_text() == 'outside edit'


def test_journal_reset_failure_preserves_edits_for_retry():
    api = FakeNVD(3)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        assert run(m, api)[0] == 0
        target = min(api.records)
        (Path(m.repo) / '2026' / f'{target}.json').write_text('{ damage')
        with patch.object(utils.LocalWriteJournal, 'reset', side_effect=OSError('reset failure')):
            assert run(m, api)[0] == 1
        assert m.pending() == [target]
        assert run(m, api)[0] == 0
        assert m.pending() == []


def test_incremental_csv_merge_preserves_all_na_cached_columns():
    api = FakeNVD(3)
    with Mirror() as m:
        m.seed(api, watermark=ago(days=1))
        Path(m.csv).write_text('cve,cvss31_baseScore\n' +
                               ''.join(f'{cve_id},\n' for cve_id in sorted(api.records)))
        for path in utils.enumerate_files_in_folder(m.repo):
            os.utime(path, (time.time() - 172800,) * 2)
        os.utime(m.csv, (time.time() - 86400,) * 2)
        target = min(api.records)
        api.records[target]['lastModified'] = ago(minutes=5).rstrip('Z')
        assert run(m, api)[0] == 0
        frame = pd.read_csv(m.csv).set_index('cve')
        assert frame.loc[target, 'cvss31_baseScore'] == 7.5
        assert frame.drop(index=target)['cvss31_baseScore'].isna().all()
        assert sorted(frame.index) == sorted(api.records)


def test_mirror_is_current_semantics():
    assert utils.mirror_is_current(100, 100) is True
    assert utils.mirror_is_current(101, 100) is True     # drift during a long sync
    assert utils.mirror_is_current(99, 100) is False     # a real shortfall
    assert utils.mirror_is_current(100, None) is False   # count unavailable


def main():
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith('test_') and callable(f)]
    failures = []
    print(f'Running {len(tests)} scenarios against a simulated NVD API\n')
    for name, fn in tests:
        label = name[5:].replace('_', ' ')
        try:
            fn()
            print(f'  PASS  {label}')
        except Exception as e:  # a test runner reports failures, it does not raise
            failures.append((label, e))
            print(f'  FAIL  {label}\n          {type(e).__name__}: {e}')
    print(f'\n{len(tests) - len(failures)}/{len(tests)} passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
