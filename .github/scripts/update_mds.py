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


def create_aaguid_directories(aaguid_data, base_path=Path('.'), dry_run=False):
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

        print(f"Processed AAGUID: {aaguid} -> {first.get('name')}")

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

        base_path = Path(output_dir) if output_dir else Path('.')
        created, updated = create_aaguid_directories(aaguid_data, base_path=base_path, dry_run=dry_run)
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
