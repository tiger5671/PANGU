"""Check the published research materials without IDA, network, or extra packages."""
import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NS = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
TEMPLATES = {
    'route_classification.txt': ['URL_PATH', 'ACTION_MAP', 'RESOURCE_MAP', 'RESOLVED', 'UNRESOLVED'],
    'security_check_verification.txt': ['AUTHENTICATION', 'AUTHORIZATION', 'NON_SECURITY', 'UNRESOLVED'],
    'detective_agent.txt': ['CANDIDATE', 'NO_FINDING', 'INSUFFICIENT_EVIDENCE'],
    'reviewer_agent.txt': ['SUPPORTED', 'REJECTED', 'UNRESOLVED'],
}
FORMATS = [
    {'class': str, 'is_executable_route': bool, 'handler_ref': (str, type(None)),
     'evidence_refs': list, 'explanation': str, 'status': str},
    {'check_label': str, 'checkpoint_ref': str, 'evidence_refs': list,
     'explanation': str, 'source_kind': str},
    {'route_id': str, 'handler_ref': str, 'decision': str,
     'hypothesized_weakness': (str, type(None)),
     'sensitive_operation_ref': (str, type(None)), 'auth_check_refs': list,
     'evidence_refs': list, 'reasoning_summary': str,
     'assumptions_and_open_questions': list, 'verification_targets': list},
    {'route_id': str, 'finding_ref': str, 'decision': str,
     'verified_weakness': (str, type(None)), 'supporting_evidence_refs': list,
     'counterevidence_refs': list, 'unresolved_assumptions': list, 'review_summary': str},
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_json(relative):
    return json.loads((ROOT / relative).read_text(encoding='utf-8'))


def display_version(raw):
    return raw.replace(' [decoded]', '').replace(
        '20220721 (release identifier; version unspecified)', '20220721 (release build)')


def workbook_rows(path):
    """Read cell values from the unchanged source workbook using the standard library."""
    with zipfile.ZipFile(path) as archive:
        strings = []
        if 'xl/sharedStrings.xml' in archive.namelist():
            root = ET.fromstring(archive.read('xl/sharedStrings.xml'))
            strings = [''.join(si.itertext()) for si in root.findall('s:si', NS)]
        sheet = ET.fromstring(archive.read('xl/worksheets/sheet1.xml'))
        rows = []
        for row in sheet.findall('s:sheetData/s:row', NS):
            if int(row.attrib['r']) == 1:
                continue
            cells = {}
            for cell in row.findall('s:c', NS):
                column = re.match(r'[A-Z]+', cell.attrib['r']).group()
                value = cell.find('s:v', NS)
                text = value.text if value is not None else ''
                if cell.attrib.get('t') == 's':
                    text = strings[int(text)]
                elif cell.attrib.get('t') == 'inlineStr':
                    text = ''.join(cell.find('s:is', NS).itertext())
                cells[column] = text or ''
            if cells.get('A'):
                rows.append((int(cells['A']), cells.get('B', ''), cells.get('C', ''),
                             cells.get('D', ''), cells.get('E', '')))
        return rows


def verify_inventory():
    manifest = load_json('dataset/firmware_manifest.json')
    images = manifest['images']
    require(len(images) == 42, 'Expected 42 firmware records.')
    require([r['image_id'] for r in images] == list(range(1, 43)), 'Image IDs must be 1..42 in order.')
    vendors = {r['vendor'] for r in images}
    cves = [cve for r in images for cve in r['known_bac_cves']]
    require(len(vendors) == 13, 'Expected 13 vendors.')
    require(len(cves) == len(set(cves)) == 78, 'Expected 78 distinct known CVE references.')
    require(all(re.fullmatch(r'CVE-\d{4}-\d{4,}', cve) for cve in cves), 'Malformed CVE ID.')
    require(manifest['counts'] == {'images': 42, 'vendors': 13, 'known_bac_cves': 78},
            'Inventory summary counts differ from the benchmark.')
    workbook = ROOT / 'dataset' / manifest['source_workbook']['file']
    digest = hashlib.sha256(workbook.read_bytes()).hexdigest()
    require(digest == manifest['source_workbook']['sha256'], 'Source workbook SHA-256 mismatch.')
    source_rows = workbook_rows(workbook)
    require(len(source_rows) == 42, 'Source workbook must contain 42 data rows.')
    markdown = (ROOT / 'dataset/firmware_manifest.md').read_text(encoding='utf-8')
    for item, row in zip(images, source_rows):
        ident, vendor, model, version, cve_text = row
        require((item['image_id'], item['vendor'], item['device_model'],
                 item['firmware_version_source']) == (ident, vendor, model, version),
                'JSON differs from source workbook at image %s.' % ident)
        require(item['known_bac_cves'] == re.findall(r'CVE-\d{4}-\d+', cve_text),
                'CVE mapping differs at image %s.' % ident)
        require(item['firmware_version'] == display_version(version),
                'Undocumented version display change at image %s.' % ident)
        line = '| %s | %s | %s | %s | %s |' % (
            ident, vendor, model, item['firmware_version'], '; '.join(item['known_bac_cves']) or '\u2014')
        require(line in markdown, 'Markdown inventory differs at image %s.' % ident)
    sources = load_json('dataset/vendor_sources.json')
    require({r['vendor'] for r in sources['vendors']} == vendors, 'Vendor portals do not cover the inventory.')
    require(all(r['scope'] == 'support_or_download_portal' for r in sources['vendors']),
            'Portal references must not claim exact-image downloads.')
    print('Inventory: 42 images, 13 vendors, 78 known CVEs; JSON/Markdown match the source workbook.')


def verify_prompts():
    for filename, labels in TEMPLATES.items():
        text = (ROOT / 'prompts' / filename).read_text(encoding='utf-8')
        require('INPUT:' in text and 'OUTPUT' in text, 'Missing input/output description in ' + filename)
        require(all(label in text for label in labels), 'Missing documented label in ' + filename)
    reviewer = (ROOT / 'prompts/reviewer_agent.txt').read_text(encoding='utf-8')
    require(not re.search(r'available_runtime|runtime_test_observations|STATIC_AND_RUNTIME|validation_basis',
                          reviewer, re.I), 'Reviewer template contains a runtime-validation field.')
    settings = load_json('prompts/model_configuration.json')
    require(settings['model'] == 'gpt-4.1', 'Unexpected documented model.')
    require(settings['maximum_total_attempts_per_request'] == 3, 'Expected three total attempts.')
    for parameter in ['temperature', 'top_p', 'maximum_output_length']:
        require(settings[parameter] == {'explicit_override': False},
                'Unexpected documented override: ' + parameter)
    text = (ROOT / 'prompts/output_formats.md').read_text(encoding='utf-8')
    examples = [json.loads(block) for block in re.findall(r'```json\s*\n(.*?)\n```', text, re.S)]
    require(len(examples) == 4, 'Expected four illustrative JSON examples.')
    for example, fields in zip(examples, FORMATS):
        require(set(example) == set(fields), 'Example fields differ from the documented format.')
        for field, expected in fields.items():
            require(isinstance(example[field], expected), 'Unexpected type for ' + field)
            if expected is list:
                require(all(isinstance(value, str) for value in example[field]), 'Expected string references.')
    require(examples[0]['class'] in TEMPLATES['route_classification.txt'][:3], 'Invalid route class.')
    require(examples[0]['status'] in ['RESOLVED', 'UNRESOLVED'], 'Invalid route status.')
    require(examples[1]['check_label'] in TEMPLATES['security_check_verification.txt'], 'Invalid check label.')
    require(examples[1]['source_kind'] in ['PATH_DOMINATING', 'ASYMMETRIC_GUARD'], 'Invalid check source.')
    require(examples[2]['decision'] in TEMPLATES['detective_agent.txt'], 'Invalid Detective decision.')
    require(examples[3]['decision'] in TEMPLATES['reviewer_agent.txt'], 'Invalid Reviewer decision.')
    print('Prompts: four templates, static Reviewer, reported settings, and four valid JSON examples.')


def verify_links():
    for doc in ROOT.rglob('*.md'):
        for target in re.findall(r'(?<!!)\[[^\]]*\]\(([^)]+)\)', doc.read_text(encoding='utf-8')):
            if '://' in target or target.startswith(('#', 'mailto:')):
                continue
            target = target.split('#', 1)[0]
            require((doc.parent / target).exists(), 'Missing local link in %s: %s' % (doc.name, target))
    print('Documentation: all local Markdown links resolve.')


def checksum_files():
    return sorted(p for p in ROOT.rglob('*') if p.is_file()
                  and p.name != 'checksums.sha256' and '__pycache__' not in p.parts
                  and p.suffix != '.pyc')


def verify_checksums(refresh):
    expected = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in checksum_files()}
    path = ROOT / 'checksums.sha256'
    if refresh:
        path.write_text(''.join('%s  %s\n' % (digest, name) for name, digest in expected.items()), encoding='utf-8')
    recorded = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        digest, name = line.split('  ', 1)
        require(name not in recorded, 'Duplicate checksum entry: ' + name)
        recorded[name] = digest
    require(recorded == expected, 'File set or checksum mismatch; investigate before refreshing checksums.')
    print('Integrity: %s file checksums verified.' % len(expected))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh-checksums', action='store_true',
                        help='Refresh checksums after intentional material edits; data checks still run first.')
    args = parser.parse_args()
    verify_inventory()
    verify_prompts()
    verify_links()
    verify_checksums(args.refresh_checksums)
    print('These checks validate the materials; no firmware experiment or application-code audit was run.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, zipfile.BadZipFile, ET.ParseError) as exc:
        print('Material check failed: %s' % exc, file=sys.stderr)
        sys.exit(1)
