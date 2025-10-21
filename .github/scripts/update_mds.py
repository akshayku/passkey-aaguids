#!/usr/bin/env python3
"""Download FIDO MDS and write per-AAGUID metadata.json files.

This script is intended to be invoked from the GitHub Action workflow.
"""
import argparse
import requests
import jwt
import json
import shutil
from pathlib import Path
from datetime import datetime, timezone


def download_mds():
    """Download the FIDO MDS JWT blob"""
    url = "https://mds3.fidoalliance.org/"
    print(f"Downloading MDS from {url}")

    response = requests.get(url)
    response.raise_for_status()

    return response.text


def download_combined_aaguid():
    """Download the combined AAGUID JSON from the GitHub raw URL."""
    url = "https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/refs/heads/main/combined_aaguid.json"
    print(f"Downloading combined AAGUID JSON from {url}")

    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"Failed to download combined AAGUID JSON: {e}")
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


def create_aaguid_directories(aaguid_data, base_path=Path('.'), dry_run=False, combined_map=None):
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

        # Use the first item's name for name.txt
        first = items[0]
        name_file = aaguid_dir / 'name.txt'
        new_name = first.get('name', 'Unknown')

        # If combined_map provided, allow it to override name/icon fields
        combined_entry = None
        if combined_map:
            # try normalized keys: lowercased and without hyphens
            cand_keys = {str(aaguid).lower(), str(aaguid).lower().replace('-', '')}
            for k in cand_keys:
                if k in combined_map:
                    combined_entry = combined_map[k]
                    break
            # if combined entry has a name, it wins
            if combined_entry:
                ce_name = combined_entry.get('name')
                if ce_name:
                    new_name = ce_name
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
                print(f"[dry-run] Would update {name_file}: '{old_name}' -> '{new_name}'")
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
        first_icon_value = None
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

        print(f"Processed AAGUID: {aaguid} -> {new_name}")

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

        # Ensure we process the union of AAGUIDs present in MDS and the combined map.
        # The combined map keys are normalized (lowercase, with and without hyphens).
        # Normalize MDS aaguid keys the same way and merge-in any combined-only entries
        # so directories get created even if the AAGUID isn't present in MDS.
        if combined_map:
            # Build a set of normalized aaguid keys from MDS data
            normalized_mds_keys = set()
            for a in list(aaguid_data.keys()):
                k = str(a).lower()
                normalized_mds_keys.add(k)
                normalized_mds_keys.add(k.replace('-', ''))

            # For any combined_map key not represented in normalized_mds_keys,
            # create a placeholder entry in aaguid_data so create_aaguid_directories
            # will create the directory and write combined-supplied files (name/icon_light/icon_dark).
            for ck in list(combined_map.keys()):
                # combined_map may contain both hyphenated and non-hyphenated variants
                if ck in normalized_mds_keys:
                    continue
                # Derive a canonical AAGUID string to use as directory name.
                # Prefer the hyphenated form if present in the combined entry, else use the key.
                combined_entry = combined_map.get(ck)
                canonical_aaguid = None
                if isinstance(combined_entry, dict):
                    # try common fields for canonical id
                    canonical_aaguid = combined_entry.get('aaguid') or combined_entry.get('AAGUID') or combined_entry.get('id') or combined_entry.get('idHex')
                if not canonical_aaguid:
                    # fallback: use the key itself; if it's the non-hyphenated form, try to insert hyphens
                    # attempt to format 32-char hex into hyphenated uuid form
                    s = ck
                    if len(s) == 32:
                        canonical_aaguid = f"{s[0:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:32]}"
                    else:
                        canonical_aaguid = ck

                # Only add if not already present exactly (preserve any MDS items)
                if canonical_aaguid not in aaguid_data:
                    # create a minimal placeholder item. name will be overridden by combined_map in create_aaguid_directories
                    placeholder = {
                        'name': combined_entry.get('name') if isinstance(combined_entry, dict) else str(canonical_aaguid),
                        'description': combined_entry.get('description') if isinstance(combined_entry, dict) else '',
                        'metadataStatement': {},
                        'mds_entry': {},
                    }
                    aaguid_data[canonical_aaguid] = [placeholder]

        base_path = Path(output_dir) if output_dir else Path('.')
        created, updated = create_aaguid_directories(aaguid_data, base_path=base_path, dry_run=dry_run, combined_map=combined_map)
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
