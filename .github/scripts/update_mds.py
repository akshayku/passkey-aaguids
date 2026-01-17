#!/usr/bin/env python3
"""Download FIDO MDS and write per-AAGUID metadata.json files.

This script is intended to be invoked from the GitHub Action workflow.
"""
import argparse
import requests
import jwt
import json
import shutil
import re
import time
from pathlib import Path
from datetime import datetime, timezone


def _http_get(url, *, timeout=30, headers=None, max_attempts=5):
    """HTTP GET with small retry/backoff for transient failures (e.g. 429)."""
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.get(url, timeout=timeout, headers=headers)
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                try:
                    wait_s = int(retry_after) if retry_after else 0
                except Exception:
                    wait_s = 0
                # Fallback exponential backoff with a small floor.
                wait_s = max(wait_s, min(60, 2 ** (attempt - 1)))
                print(f"Received 429 for {url}; retrying in {wait_s}s (attempt {attempt}/{max_attempts})")
                time.sleep(wait_s)
                continue

            resp.raise_for_status()
            return resp
        except Exception as e:
            last_exc = e
            if attempt >= max_attempts:
                break
            wait_s = min(60, 2 ** (attempt - 1))
            print(f"Request failed for {url}: {e}; retrying in {wait_s}s (attempt {attempt}/{max_attempts})")
            time.sleep(wait_s)

    raise last_exc


def download_mds():
    """Download the FIDO MDS JWT blob"""
    url = "https://mds3.fidoalliance.org/"
    print(f"Downloading MDS from {url}")

    response = _http_get(url, timeout=30)
    return response.text


def download_combined_aaguid():
    """Download the combined AAGUID JSON from the GitHub raw URL."""
    url = "https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/refs/heads/main/combined_aaguid.json"
    print(f"Downloading combined AAGUID JSON from {url}")

    try:
        resp = _http_get(url, timeout=30)
        return resp.text
    except Exception as e:
        print(f"Failed to download combined AAGUID JSON: {e}")
        return None


def download_c_mds():
    """Download the c-MDS AAGUID JSON blob.

    c-MDS currently serves JSON as application/octet-stream.
    """
    url = "https://c-mds.fidoalliance.org/"
    print(f"Downloading c-MDS from {url}")

    try:
        resp = _http_get(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "passkey-aaguids-update-script",
            },
        )
        # Content-Type may be application/octet-stream, so decode explicitly.
        return resp.content.decode('utf-8', errors='replace')
    except Exception as e:
        print(f"Failed to download c-MDS JSON: {e}")
        return None


def parse_combined_map(raw_text):
    """Parse combined JSON text into a mapping keyed by normalized aaguid.

    Normalization: lowercased string. Also add a version without hyphens to
    improve matching against other AAGUID formats.
    """
    if not raw_text:
        return None
    try:
        parsed = json.loads(raw_text)
    except Exception as e:
        print(f"Could not parse combined JSON: {e}")
        return None

    out = {}

    def add_key(k, v):
        if not k:
            return
        k1 = str(k).lower()
        out[k1] = v
        k2 = k1.replace('-', '')
        if k2 != k1:
            out[k2] = v

    if isinstance(parsed, dict):
        # assume dict keyed by aaguid
        for k, v in parsed.items():
            add_key(k, v)
    elif isinstance(parsed, list):
        for e in parsed:
            if not isinstance(e, dict):
                continue
            # try common fields
            k = e.get('aaguid') or e.get('AAGUID') or e.get('id') or e.get('idHex')
            if k:
                add_key(k, e)
    else:
        return None

    return out


def parse_c_mds_map(raw_text):
    """Parse c-MDS JSON text into a normalized mapping.

    The c-MDS JSON shape is compatible with the combined map parser.
    """
    return parse_combined_map(raw_text)


def lookup_normalized(mapping, aaguid):
    """Look up an AAGUID in a mapping with normalized keys.

    Tries lowercased hyphenated and non-hyphenated forms.
    """
    if not mapping or not aaguid:
        return None

    a = str(aaguid).lower()
    for k in (a, a.replace('-', '')):
        if k in mapping:
            return mapping[k]
    return None


def _normalize_single_line(text):
    if text is None:
        return None
    s = str(text)
    # Collapse all whitespace (including newlines/tabs) into single spaces.
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def _format_for_log(text, max_len=140):
    if text is None:
        return "None"
    s = _normalize_single_line(text) or ""
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


def _friendly_name_from_entry(entry):
    if not isinstance(entry, dict):
        return None
    fn = entry.get('friendlyNames')
    if isinstance(fn, dict) and fn:
        # Prefer common English locales
        for lang in ('en-US', 'en', 'en-GB'):
            v = fn.get(lang)
            if v:
                return _normalize_single_line(v)
        # Otherwise pick any value deterministically
        for _, v in sorted(fn.items(), key=lambda kv: str(kv[0])):
            if v:
                return _normalize_single_line(v)
    # fallbacks
    v = entry.get('friendlyName') or entry.get('name')
    return _normalize_single_line(v) if v else None


def parse_jwt(jwt_token):
    """Parse JWT token without verification (MDS is publicly available)"""
    try:
        decoded = jwt.decode(jwt_token, options={"verify_signature": False})
        return decoded
    except Exception as e:
        print(f"Error decoding JWT: {e}")
        return None


def extract_aaguids(mds_data):
    """Extract AAGUIDs and their metadata from MDS.

    Returns a mapping of aaguid -> list of metadata items. Multiple MDS entries
    may refer to the same aaguid; preserve all of them.
    """
    entries = mds_data.get('entries', [])
    aaguid_data = {}

    for entry in entries:
        metadata_statement = entry.get('metadataStatement', {})
        aaguid = metadata_statement.get('aaguid')
        if not aaguid:
            continue

        description = metadata_statement.get('description', 'Unknown')
        name = description
        if isinstance(description, dict):
            name = description.get('en', description.get('english', str(description)))

        item = {
            'name': str(name),
            'description': description,
            'metadataStatement': metadata_statement,
            'mds_entry': entry,
        }

        aaguid_data.setdefault(aaguid, []).append(item)

    return aaguid_data


def _choose_name_for_aaguid(aaguid, items, combined_map=None, c_mds_map=None):
    """Choose the display name for an AAGUID using the current precedence rules."""
    first = items[0] if items else {}
    new_name = first.get('name', 'Unknown')

    combined_entry = lookup_normalized(combined_map, aaguid) if combined_map else None
    c_mds_entry = lookup_normalized(c_mds_map, aaguid) if c_mds_map else None

    # Name precedence: combined primary, c-MDS fallback, then MDS.
    if isinstance(combined_entry, dict):
        ce_name = combined_entry.get('name')
        if ce_name:
            new_name = ce_name
        else:
            c_name = _friendly_name_from_entry(c_mds_entry)
            if c_name:
                new_name = c_name
    else:
        c_name = _friendly_name_from_entry(c_mds_entry)
        if c_name:
            new_name = c_name

    return _normalize_single_line(new_name) if new_name is not None else 'Unknown'


def create_aaguid_directories(aaguid_data, base_path=Path('.'), dry_run=False, combined_map=None, c_mds_map=None):
    """Create directories and files for each AAGUID under base_path"""
    base_path = Path(base_path)
    base_path.mkdir(parents=True, exist_ok=True)

    created_count = 0
    updated_count = 0

    for aaguid, items in aaguid_data.items():
        aaguid_dir = base_path / aaguid
        if aaguid_dir.exists():
            updated_count += 1
        else:
            created_count += 1

        aaguid_dir.mkdir(exist_ok=True)

        name_file = aaguid_dir / 'name.txt'
        new_name = _choose_name_for_aaguid(aaguid, items, combined_map=combined_map, c_mds_map=c_mds_map)

        # If extra sources provided, allow them to override/fill icon fields
        combined_entry = lookup_normalized(combined_map, aaguid) if combined_map else None
        c_mds_entry = lookup_normalized(c_mds_map, aaguid) if c_mds_map else None
        # Write only if changed
        if name_file.exists():
            try:
                old_name = name_file.read_text(encoding='utf-8')
            except Exception:
                old_name = None
        else:
            old_name = None

        if old_name != new_name:
            if dry_run:
                old_preview = _format_for_log(old_name)
                new_preview = _format_for_log(new_name)
                print(
                    f"[dry-run] Would update {name_file} (len_old={len(old_name) if old_name else 0}, len_new={len(new_name)}): "
                    f"{old_preview!r} -> {new_preview!r}"
                )
            else:
                name_file.write_text(new_name, encoding='utf-8')

        # Save full metadata list to metadata.json only if changed
        metadata_file = aaguid_dir / 'metadata.json'
        new_metadata = json.dumps(items, ensure_ascii=False, indent=2, sort_keys=True)
        if metadata_file.exists():
            try:
                old_metadata = metadata_file.read_text(encoding='utf-8')
            except Exception:
                old_metadata = None
        else:
            old_metadata = None

        if old_metadata != new_metadata:
            if dry_run:
                print(f"[dry-run] Would write {metadata_file} (size {len(new_metadata)} bytes)")
            else:
                with open(metadata_file, 'w', encoding='utf-8') as mf:
                    mf.write(new_metadata)

        # Extract icon fields from metadataStatement(s) and write icons.json if any.
        # Use an explicit canonical key list derived from repository analysis to
        # avoid false positives. Historically the repo uses the exact key "icon"
        # in the majority of metadata.json files.
        icons = []
        canonical_icon_keys = {"icon"}
        for item in items:
            ms = item.get('metadataStatement', {}) or {}
            for k, v in ms.items():
                # Case-insensitive match against the canonical key set
                if str(k).lower() in canonical_icon_keys:
                    # Normalize supported value shapes: string, list, or dict
                    if isinstance(v, list):
                        for elem in v:
                            icons.append({'source_key': k, 'value': elem, 'name': item.get('name')})
                    else:
                        icons.append({'source_key': k, 'value': v, 'name': item.get('name')})

        # Instead of producing icons.json, write only the first icon value
        # encountered (if any) to a plain text file `icon.txt`.
        icon_file = aaguid_dir / 'icon.txt'
        # Icon precedence: c-MDS primary, then MDS metadataStatement icon.
        first_icon_value = None
        if isinstance(c_mds_entry, dict):
            ci = c_mds_entry.get('icon')
            if ci:
                first_icon_value = str(ci)

        if first_icon_value is None:
            # canonical_icon_keys defined above; iterate again to find the first value
            for item in items:
                ms = item.get('metadataStatement', {}) or {}
                for k, v in ms.items():
                    if str(k).lower() in canonical_icon_keys:
                        # normalize value: if list -> first element; if dict -> compact JSON
                        if isinstance(v, list) and v:
                            val = v[0]
                        elif isinstance(v, dict):
                            try:
                                val = json.dumps(v, ensure_ascii=False, separators=(',', ':'))
                            except Exception:
                                val = str(v)
                        else:
                            val = v

                        # convert non-str values to string
                        if not isinstance(val, str):
                            try:
                                val = json.dumps(val, ensure_ascii=False)
                            except Exception:
                                val = str(val)

                        first_icon_value = val
                        break
                if first_icon_value is not None:
                    break

        if first_icon_value is not None:
            # Write only the raw icon value into icon.txt (no JSON wrapper)
            if icon_file.exists():
                try:
                    old_icon = icon_file.read_text(encoding='utf-8')
                except Exception:
                    old_icon = None
            else:
                old_icon = None

            if old_icon != first_icon_value:
                if dry_run:
                    print(f"[dry-run] Would write {icon_file} (length={len(first_icon_value)})")
                else:
                    with open(icon_file, 'w', encoding='utf-8') as f:
                        f.write(first_icon_value)
        else:
            # No icon found: remove stale icon.txt if present
            if icon_file.exists() and not dry_run:
                try:
                    icon_file.unlink()
                    print(f"Removed stale {icon_file}")
                except Exception:
                    pass

        # Write c_mds.json for this AAGUID when present
        c_mds_file = aaguid_dir / 'c_mds.json'
        if isinstance(c_mds_entry, dict) and c_mds_entry:
            new_c_mds = json.dumps(c_mds_entry, ensure_ascii=False, indent=2, sort_keys=True)
            if c_mds_file.exists():
                try:
                    old_c_mds = c_mds_file.read_text(encoding='utf-8')
                except Exception:
                    old_c_mds = None
            else:
                old_c_mds = None

            if old_c_mds != new_c_mds:
                if dry_run:
                    print(f"[dry-run] Would write {c_mds_file} (size {len(new_c_mds)} bytes)")
                else:
                    c_mds_file.write_text(new_c_mds, encoding='utf-8')
        else:
            # No c-MDS entry: remove stale file
            if c_mds_file.exists() and not dry_run:
                try:
                    c_mds_file.unlink()
                    print(f"Removed stale {c_mds_file}")
                except Exception:
                    pass

        # Write icon_light.txt and icon_dark.txt from combined_entry if present
        if combined_entry:
            # icon_light
            il = combined_entry.get('icon_light')
            light_file = aaguid_dir / 'icon_light.txt'
            if il:
                try:
                    old = light_file.read_text(encoding='utf-8') if light_file.exists() else None
                except Exception:
                    old = None
                if old != il:
                    if dry_run:
                        print(f"[dry-run] Would write {light_file} (length={len(il)})")
                    else:
                        with open(light_file, 'w', encoding='utf-8') as f:
                            f.write(il)
            else:
                if light_file.exists() and not dry_run:
                    try:
                        light_file.unlink()
                        print(f"Removed stale {light_file}")
                    except Exception:
                        pass

            # icon_dark
            idk = combined_entry.get('icon_dark')
            dark_file = aaguid_dir / 'icon_dark.txt'
            if idk:
                try:
                    oldd = dark_file.read_text(encoding='utf-8') if dark_file.exists() else None
                except Exception:
                    oldd = None
                if oldd != idk:
                    if dry_run:
                        print(f"[dry-run] Would write {dark_file} (length={len(idk)})")
                    else:
                        with open(dark_file, 'w', encoding='utf-8') as f:
                            f.write(idk)
            else:
                if dark_file.exists() and not dry_run:
                    try:
                        dark_file.unlink()
                        print(f"Removed stale {dark_file}")
                    except Exception:
                        pass

    print(f"Processed AAGUID: {aaguid} -> {_format_for_log(new_name)}")

    return created_count, updated_count


def main(dry_run=False, output_dir=None, sample_jwt=None):
    try:
        if sample_jwt:
            # Read JWT from file
            jwt_blob = Path(sample_jwt).read_text(encoding='utf-8')
            print(f"Loaded sample JWT from {sample_jwt}")
        else:
            jwt_blob = download_mds()
            print("MDS downloaded successfully")

        mds_data = parse_jwt(jwt_blob)
        if not mds_data:
            raise Exception("Failed to parse MDS JWT")

        print("MDS JWT parsed successfully")

        aaguid_data = extract_aaguids(mds_data)
        print(f"Found {len(aaguid_data)} AAGUIDs in MDS")

        # Always download the combined AAGUID JSON from the canonical remote
        combined_map = None
        raw_combined = download_combined_aaguid()
        combined_map = parse_combined_map(raw_combined) if raw_combined else None
        if combined_map is not None:
            print(f"Loaded remote combined map with {len(combined_map)} entries")

        # Download c-MDS map (3rd source)
        c_mds_map = None
        raw_c_mds = download_c_mds()
        c_mds_map = parse_c_mds_map(raw_c_mds) if raw_c_mds else None
        if c_mds_map is not None:
            print(f"Loaded c-MDS map with {len(c_mds_map)} entries")

        # Ensure we process the union of AAGUIDs present in MDS and the combined map.
        # The combined map keys are normalized (lowercase, with and without hyphens).
        # Normalize MDS aaguid keys the same way and merge-in any combined-only entries
        # so directories get created even if the AAGUID isn't present in MDS.
        if combined_map or c_mds_map:
            # Build a set of normalized aaguid keys from MDS data
            normalized_mds_keys = set()
            for a in list(aaguid_data.keys()):
                k = str(a).lower()
                normalized_mds_keys.add(k)
                normalized_mds_keys.add(k.replace('-', ''))

            def ensure_placeholders(external_map, name_fn):
                if not external_map:
                    return
                for ck in list(external_map.keys()):
                    if ck in normalized_mds_keys:
                        continue
                    entry = external_map.get(ck)
                    canonical_aaguid = None
                    if isinstance(entry, dict):
                        canonical_aaguid = entry.get('aaguid') or entry.get('AAGUID') or entry.get('id') or entry.get('idHex')
                    if not canonical_aaguid:
                        s = ck
                        if len(s) == 32:
                            canonical_aaguid = f"{s[0:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:32]}"
                        else:
                            canonical_aaguid = ck

                    if canonical_aaguid not in aaguid_data:
                        placeholder = {
                            'name': _normalize_single_line(name_fn(entry)) or str(canonical_aaguid),
                            'description': entry.get('description') if isinstance(entry, dict) else '',
                            'metadataStatement': {},
                            'mds_entry': {},
                        }
                        aaguid_data[canonical_aaguid] = [placeholder]

            # Ensure we create directories for entries that exist only in the external sources.
            ensure_placeholders(combined_map, lambda e: e.get('name') if isinstance(e, dict) else None)
            ensure_placeholders(c_mds_map, _friendly_name_from_entry)

        base_path = Path(output_dir) if output_dir else Path('.')
        created, updated = create_aaguid_directories(
            aaguid_data,
            base_path=base_path,
            dry_run=dry_run,
            combined_map=combined_map,
            c_mds_map=c_mds_map,
        )
        print(f"Created {created} new AAGUID directories")
        print(f"Updated {updated} existing AAGUID directories")

        summary = {
            'total_aaguids': len(aaguid_data),
            'created_directories': created,
            'updated_directories': updated,
            'last_updated': datetime.now(timezone.utc).isoformat(),
        }

        # Write summary only when changed
        summary_file = base_path / 'mds_summary.json'
        new_summary = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True)
        if summary_file.exists():
            try:
                old_summary = summary_file.read_text(encoding='utf-8')
            except Exception:
                old_summary = None
        else:
            old_summary = None

        if old_summary != new_summary:
            if dry_run:
                print(f"[dry-run] Would update {summary_file} (total_aaguids={summary['total_aaguids']})")
            else:
                summary_file.parent.mkdir(parents=True, exist_ok=True)
                with open(summary_file, 'w', encoding='utf-8') as f:
                    f.write(new_summary)

        # Write a compact combined file containing only aaguid and name.
        # Uses the same name precedence rules as name.txt.
        names_file = base_path / 'aaguids.json'
        names_list = [
            {
                'aaguid': aaguid,
                'name': _choose_name_for_aaguid(aaguid, items, combined_map=combined_map, c_mds_map=c_mds_map),
            }
            for aaguid, items in sorted(aaguid_data.items(), key=lambda kv: str(kv[0]).lower())
        ]
        new_names = json.dumps(names_list, ensure_ascii=False, indent=2)
        if names_file.exists():
            try:
                old_names = names_file.read_text(encoding='utf-8')
            except Exception:
                old_names = None
        else:
            old_names = None

        if old_names != new_names:
            if dry_run:
                print(f"[dry-run] Would update {names_file} (total_aaguids={len(names_list)})")
            else:
                names_file.parent.mkdir(parents=True, exist_ok=True)
                names_file.write_text(new_names, encoding='utf-8')

        print("MDS update completed successfully")

    except Exception as e:
        print(f"Error: {e}")
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Update FIDO MDS metadata files')
    parser.add_argument('-n', '--dry-run', action='store_true', help='Show planned changes without writing files')
    parser.add_argument('-o', '--output-dir', help='Directory to write output files into (for testing)')
    parser.add_argument('-s', '--sample-jwt', help='Path to a sample JWT file to parse instead of downloading')
    args = parser.parse_args()
    main(dry_run=args.dry_run, output_dir=args.output_dir, sample_jwt=args.sample_jwt)
