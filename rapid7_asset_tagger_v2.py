"""
Rapid7 InsightVM / Nexpose - Asset Tag Automation Script
=========================================================
Automates tagging/untagging assets by hostname or IP address.

Endpoints used (confirmed via Burp):
  - GET  /api/3/assets/search   -> find asset IDs by hostname/IP
  - GET  /api/3/assets/{id}/tags -> list tags on an asset
  - POST /data/tag?assetID={id} -> add tag to asset (JSON body)
  - DELETE /data/tag/{tagID}?assetID={id} -> remove tag from asset

Usage Examples:
  # Add a tag to assets (type defaults to CUSTOM)
  python rapid7_asset_tagger_v2.py --url https://rapid7.quinstreet.net add --tag "A-Test" --assets "server1,server2,10.0.0.5"

  # Add a tag with specific type (CUSTOM, OWNER, LOCATION, CRITICALITY)
  python rapid7_asset_tagger_v2.py --url https://rapid7.quinstreet.net add --tag "A-Test" --tag-type OWNER --assets "server1"

  # Remove a tag from assets
  python rapid7_asset_tagger_v2.py --url https://rapid7.quinstreet.net remove --tag "Deprecated" --assets "server1,10.0.0.5"

  # Replace tag1 with tag2 on specific assets
  python rapid7_asset_tagger_v2.py --url https://rapid7.quinstreet.net replace --old-tag "tag1" --new-tag "tag2" --assets "server1,server2"

  # Bulk add from CSV file
  python rapid7_asset_tagger_v2.py --url https://rapid7.quinstreet.net add --tag "PCI-Scope" --csv assets.csv
"""

import argparse
import csv
import json
import logging
import os
import sys
from pathlib import Path

import requests
import urllib3

# Suppress insecure HTTPS warnings (common for on-prem Rapid7 consoles)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PAGE_SIZE = 500


# ---------------------------------------------------------------------------
# Rapid7 Client
# ---------------------------------------------------------------------------
class Rapid7Client:
    """Client for Rapid7 InsightVM/Nexpose using cookie-based authentication."""

    def __init__(self, base_url: str, cookies: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = self.verify_ssl

        # Parse cookies
        self._set_cookies(cookies)

        # Set headers matching what the console expects (from Burp capture)
        self.session.headers.update({
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/json; charset=UTF-8",
        })

        # Set Nexposeccsessionid header (required for write operations)
        self._apply_session_id_header()

    def _set_cookies(self, cookie_string: str):
        """Parse a raw cookie header string and load into the session."""
        if not cookie_string:
            return
        for pair in cookie_string.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, value = pair.split("=", 1)
                self.session.cookies.set(name.strip(), value.strip())

    def _apply_session_id_header(self):
        """
        Extract nexposeCCSessionID from cookies and set as request header.
        The console requires this header for CSRF protection on write ops.
        """
        session_id = None
        for name in self.session.cookies.keys():
            if name.lower() in ("nexposeccsessionid",):
                session_id = self.session.cookies.get(name)
                break

        if session_id:
            self.session.headers["Nexposeccsessionid"] = session_id
            log.debug("Set Nexposeccsessionid header.")
        else:
            log.warning(
                "Could not find 'nexposeCCSessionID' in cookies. "
                "Write operations will likely fail with 406."
            )

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------
    def test_connection(self) -> bool:
        """Verify authentication works."""
        try:
            resp = self.session.get(
                f"{self.base_url}/api/3/tags",
                params={"size": 1, "page": 0},
            )
            if resp.status_code == 401:
                log.error(
                    "401 Unauthorized — session cookie is invalid or expired.\n"
                    "  Log into the console again and copy fresh cookies."
                )
                return False
            if resp.status_code == 403:
                log.error("403 Forbidden — account lacks API permissions.")
                return False
            resp.raise_for_status()
            return True
        except requests.ConnectionError as exc:
            log.error("Cannot connect to %s — %s", self.base_url, exc)
            return False

    # ------------------------------------------------------------------
    # Asset search (uses REST API v3 — GET works fine with cookies)
    # ------------------------------------------------------------------
    def search_assets(self, identifier: str) -> list[dict]:
        """
        Search for assets by hostname or IP.
        Returns list of asset dicts with 'id', 'ip', 'hostName', etc.
        """
        identifier = identifier.strip()
        if not identifier:
            return []

        # Determine filter field
        if self._looks_like_ip(identifier):
            filters = [{"field": "ip-address", "operator": "is", "value": identifier}]
        else:
            filters = [{"field": "host-name", "operator": "is", "value": identifier}]

        payload = {"filters": filters, "match": "all"}
        results = []
        page = 0

        while True:
            resp = self.session.post(
                f"{self.base_url}/api/3/assets/search",
                json=payload,
                params={"size": PAGE_SIZE, "page": page},
            )
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("resources", []))
            total_pages = data.get("page", {}).get("totalPages", 1)
            if page + 1 >= total_pages:
                break
            page += 1

        # If IP search returned nothing, try hostname search as fallback
        if not results and self._looks_like_ip(identifier):
            pass  # Already tried IP, no fallback needed
        elif not results:
            # Try IP search as fallback for hostname
            filters = [{"field": "ip-address", "operator": "is", "value": identifier}]
            payload = {"filters": filters, "match": "all"}
            resp = self.session.post(
                f"{self.base_url}/api/3/assets/search",
                json=payload,
                params={"size": PAGE_SIZE, "page": 0},
            )
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("resources", []))

        return results

    # ------------------------------------------------------------------
    # Tag operations (uses /data/tag endpoint — confirmed via Burp)
    # ------------------------------------------------------------------
    def get_asset_tags(self, asset_id: int) -> list[dict]:
        """Get all tags currently on an asset (via REST API v3 GET)."""
        resp = self.session.get(
            f"{self.base_url}/api/3/assets/{asset_id}/tags",
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("resources", [])

    def add_tag_to_asset(self, asset_id: int, tag_name: str, tag_type: str = "CUSTOM"):
        """
        Add a tag to an asset.

        Endpoint: POST /data/tag?assetID={asset_id}
        Body: [{"type": "<TAG_TYPE>", "name": "<tag_name>"}]

        tag_type: CUSTOM, OWNER, LOCATION, CRITICALITY
        """
        url = f"{self.base_url}/data/tag"
        params = {"assetID": asset_id}
        body = [{"type": tag_type.upper(), "name": tag_name}]

        resp = self.session.post(url, params=params, json=body)

        if resp.status_code == 406:
            log.error(
                "406 from POST /data/tag?assetID=%s — check Nexposeccsessionid header.\n"
                "  Response: %s", asset_id, resp.text[:300]
            )
        resp.raise_for_status()
        return resp

    def remove_tag_from_asset(self, asset_id: int, tag_id: int):
        """
        Remove a tag from an asset.

        Endpoint: DELETE /data/tag/{tagID}?assetID={asset_id}
        """
        url = f"{self.base_url}/data/tag/{tag_id}"
        params = {"assetID": asset_id}

        resp = self.session.delete(url, params=params)
        if resp.status_code == 406:
            log.error(
                "406 from DELETE /data/tag/%s?assetID=%s\n  Response: %s",
                tag_id, asset_id, resp.text[:300]
            )
        resp.raise_for_status()
        return resp

    def find_tag_id_on_asset(self, asset_id: int, tag_name: str) -> int | None:
        """Find the tag ID for a given tag name on a specific asset."""
        tags = self.get_asset_tags(asset_id)
        for tag in tags:
            if tag.get("name", "").lower() == tag_name.lower():
                return tag["id"]
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        parts = value.split(".")
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# ---------------------------------------------------------------------------
# CSV loader
# ---------------------------------------------------------------------------
def load_identifiers_from_csv(csv_path: str) -> list[str]:
    """Read asset identifiers from a CSV file."""
    identifiers = []
    path = Path(csv_path)
    if not path.is_file():
        log.error("CSV file not found: %s", csv_path)
        sys.exit(1)

    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        headers_lower = {h.lower(): h for h in (reader.fieldnames or [])}

        col = None
        for candidate in ("hostname", "host", "ip", "ip_address", "ipaddress", "asset"):
            if candidate in headers_lower:
                col = headers_lower[candidate]
                break
        if col is None and reader.fieldnames:
            col = reader.fieldnames[0]

        if col is None:
            log.error("CSV has no recognizable column. Add a 'hostname' or 'ip' header.")
            sys.exit(1)

        for row in reader:
            val = row.get(col, "").strip()
            if val:
                identifiers.append(val)

    log.info("Loaded %d identifiers from %s", len(identifiers), csv_path)
    return identifiers


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
def action_add(client: Rapid7Client, tag_name: str, tag_type: str, identifiers: list[str]):
    """Add a tag to every resolved asset."""
    success, skipped, failed = 0, 0, 0

    for ident in identifiers:
        assets = client.search_assets(ident)
        if not assets:
            log.warning("No asset found for '%s' — skipping.", ident)
            skipped += 1
            continue

        for asset in assets:
            asset_id = asset["id"]
            label = asset.get("hostName") or asset.get("ip", str(asset_id))
            try:
                client.add_tag_to_asset(asset_id, tag_name, tag_type)
                log.info("Tagged '%s' (id=%s) with '%s' [%s].", label, asset_id, tag_name, tag_type)
                success += 1
            except requests.HTTPError as exc:
                log.error("Failed to tag '%s': %s", label, exc)
                failed += 1

    _summary("ADD", tag_name, success, skipped, failed)


def action_remove(client: Rapid7Client, tag_name: str, identifiers: list[str]):
    """Remove a tag from every resolved asset."""
    success, skipped, failed = 0, 0, 0

    for ident in identifiers:
        assets = client.search_assets(ident)
        if not assets:
            log.warning("No asset found for '%s' — skipping.", ident)
            skipped += 1
            continue

        for asset in assets:
            asset_id = asset["id"]
            label = asset.get("hostName") or asset.get("ip", str(asset_id))

            # Find the tag ID on this asset
            tag_id = client.find_tag_id_on_asset(asset_id, tag_name)
            if tag_id is None:
                log.info("Asset '%s' does not have tag '%s' — skipping.", label, tag_name)
                skipped += 1
                continue

            try:
                client.remove_tag_from_asset(asset_id, tag_id)
                log.info("Removed tag '%s' (id=%s) from '%s'.", tag_name, tag_id, label)
                success += 1
            except requests.HTTPError as exc:
                log.error("Failed to remove tag from '%s': %s", label, exc)
                failed += 1

    _summary("REMOVE", tag_name, success, skipped, failed)


def action_replace(
    client: Rapid7Client,
    old_tag_name: str,
    new_tag_name: str,
    new_tag_type: str,
    identifiers: list[str],
):
    """Replace old_tag with new_tag on every resolved asset."""
    success, skipped, failed = 0, 0, 0

    for ident in identifiers:
        assets = client.search_assets(ident)
        if not assets:
            log.warning("No asset found for '%s' — skipping.", ident)
            skipped += 1
            continue

        for asset in assets:
            asset_id = asset["id"]
            label = asset.get("hostName") or asset.get("ip", str(asset_id))

            # Find the old tag on this asset
            old_tag_id = client.find_tag_id_on_asset(asset_id, old_tag_name)
            if old_tag_id is None:
                log.info("Asset '%s' does not have tag '%s' — skipping.", label, old_tag_name)
                skipped += 1
                continue

            try:
                # Add new tag first
                client.add_tag_to_asset(asset_id, new_tag_name, new_tag_type)
                # Remove old tag
                client.remove_tag_from_asset(asset_id, old_tag_id)
                log.info(
                    "Replaced '%s' → '%s' on '%s' (id=%s).",
                    old_tag_name, new_tag_name, label, asset_id,
                )
                success += 1
            except requests.HTTPError as exc:
                log.error("Failed to replace tag on '%s': %s", label, exc)
                failed += 1

    _summary("REPLACE", f"{old_tag_name} → {new_tag_name}", success, skipped, failed)


def _summary(action: str, tag_info: str, success: int, skipped: int, failed: int):
    total = success + skipped + failed
    print("\n" + "=" * 60)
    print(f"  {action} summary for: {tag_info}")
    print(f"  Total processed     : {total}")
    print(f"  Successful          : {success}")
    print(f"  Skipped (not found) : {skipped}")
    print(f"  Failed              : {failed}")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rapid7 InsightVM / Nexpose — Asset Tag Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--url", required=True,
        help="Console URL, e.g. https://rapid7.quinstreet.net",
    )
    parser.add_argument(
        "--cookies",
        help="Session cookies (e.g. 'nexposeCCSessionID=abc123'). "
             "If omitted, you'll be prompted.",
    )
    parser.add_argument(
        "--user",
        help="Username for Basic Auth (alternative to cookies).",
    )
    parser.add_argument(
        "--verify-ssl", action="store_true", default=False,
        help="Verify TLS certificate (default: skip).",
    )

    sub = parser.add_subparsers(dest="action", required=True)

    # --- add ---
    p_add = sub.add_parser("add", help="Add a tag to assets.")
    p_add.add_argument("--tag", required=True, help="Tag name to apply.")
    p_add.add_argument(
        "--tag-type", default="CUSTOM",
        choices=["CUSTOM", "OWNER", "LOCATION", "CRITICALITY"],
        help="Tag type (default: CUSTOM).",
    )
    _add_asset_args(p_add)

    # --- remove ---
    p_rem = sub.add_parser("remove", help="Remove a tag from assets.")
    p_rem.add_argument("--tag", required=True, help="Tag name to remove.")
    _add_asset_args(p_rem)

    # --- replace ---
    p_rep = sub.add_parser("replace", help="Replace one tag with another.")
    p_rep.add_argument("--old-tag", required=True, help="Tag to remove.")
    p_rep.add_argument("--new-tag", required=True, help="Tag to apply.")
    p_rep.add_argument(
        "--tag-type", default="CUSTOM",
        choices=["CUSTOM", "OWNER", "LOCATION", "CRITICALITY"],
        help="Type of the new tag (default: CUSTOM).",
    )
    _add_asset_args(p_rep)

    return parser


def _add_asset_args(subparser):
    group = subparser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--assets",
        help="Comma-separated hostnames or IPs (e.g. 'server1,10.0.0.5')",
    )
    group.add_argument(
        "--csv",
        help="Path to CSV file with 'hostname' or 'ip' column.",
    )


def main():
    parser = build_parser()
    args = parser.parse_args()

    # --- Authentication ---
    if args.user:
        from getpass import getpass as _getpass
        password = _getpass(f"Password for '{args.user}': ")
        client = Rapid7Client(base_url=args.url, cookies="", verify_ssl=args.verify_ssl)
        client.session.auth = (args.user, password)
    else:
        cookies = args.cookies or os.environ.get("RAPID7_COOKIES", "")
        if not cookies:
            print("\nPaste your full cookie string from browser DevTools (Network tab → Cookie header).")
            print("Must include nexposeCCSessionID=<value>\n")
            cookies = input("Cookies: ").strip()
        if not cookies:
            log.error("No cookies provided. Exiting.")
            sys.exit(1)
        client = Rapid7Client(base_url=args.url, cookies=cookies, verify_ssl=args.verify_ssl)

    # Validate connection
    log.info("Testing connection to %s ...", args.url)
    if not client.test_connection():
        sys.exit(1)
    log.info("Authentication successful.")

    # Resolve identifiers
    if args.assets:
        identifiers = [i.strip() for i in args.assets.split(",") if i.strip()]
    elif args.csv:
        identifiers = load_identifiers_from_csv(args.csv)
    else:
        identifiers = []

    if not identifiers:
        log.error("No assets provided.")
        sys.exit(1)

    # Dispatch
    if args.action == "add":
        action_add(client, args.tag, args.tag_type, identifiers)
    elif args.action == "remove":
        action_remove(client, args.tag, identifiers)
    elif args.action == "replace":
        action_replace(client, args.old_tag, args.new_tag, args.tag_type, identifiers)


if __name__ == "__main__":
    main()
