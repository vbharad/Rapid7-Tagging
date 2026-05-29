"""
Rapid7 InsightVM / Nexpose - Asset Tag Automation Script
=========================================================
Automates tagging/untagging assets by hostname or IP address.

Features:
  - Add a tag to a list of assets (by hostname or IP)
  - Remove a tag from a list of assets
  - Replace one tag with another across assets
  - Bulk operations via CSV file
  - Cookie-based authentication

Usage Examples:
  # Add a tag to assets
  python rapid7_asset_tagger.py add --tag "PCI-Scope" --assets "server1,server2,10.0.0.5"

  # Remove a tag from assets
  python rapid7_asset_tagger.py remove --tag "Deprecated" --assets "server1,10.0.0.5"

  # Replace tag1 with tag2 on all assets that have tag1
  python rapid7_asset_tagger.py replace --old-tag "Environment:Dev" --new-tag "Environment:Prod"

  # Bulk add from CSV file
  python rapid7_asset_tagger.py add --tag "PCI-Scope" --csv assets.csv

  # Replace tag only for specific assets
  python rapid7_asset_tagger.py replace --old-tag "tag1" --new-tag "tag2" --assets "server1,server2"

  # Replace tag for all assets that currently have it
  python rapid7_asset_tagger.py replace --old-tag "tag1" --new-tag "tag2"
"""

import argparse
import csv
import json
import logging
import os
import sys
import urllib.parse
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
API_BASE = "/api/3"
PAGE_SIZE = 500  # max items per API page


# ---------------------------------------------------------------------------
# Rapid7 API Client
# ---------------------------------------------------------------------------
class Rapid7Client:
    """Thin wrapper around the InsightVM / Nexpose REST API v3."""

    def __init__(self, base_url: str, cookies: str, verify_ssl: bool = False):
        """
        Parameters
        ----------
        base_url : str
            Console URL, e.g. https://insightvm.company.com:3780
        cookies : str
            Raw cookie string, e.g. "nexposeCCSessionID=abc123; ..."
        verify_ssl : bool
            Whether to verify TLS certificates (default False for on-prem).
        """
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = self.verify_ssl

        # Parse and set cookies
        self._set_cookies(cookies)

        # Common headers — must include X-Requested-With and the session ID header
        # Rapid7 console uses Nexposeccsessionid header as CSRF protection
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        })

        # Extract session ID and set it as the Nexposeccsessionid header
        self._apply_session_id_header()

    def _set_cookies(self, cookie_string: str):
        """Parse a raw cookie header string and load into the session."""
        for pair in cookie_string.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, value = pair.split("=", 1)
                self.session.cookies.set(name.strip(), value.strip())

    def _apply_session_id_header(self):
        """
        Extract the nexposeCCSessionID from cookies and set it as
        the 'Nexposeccsessionid' request header.
        Rapid7 requires this for ALL state-changing (POST/PUT/DELETE) requests
        when using cookie-based auth — without it you get 406.
        """
        # Try common session cookie names (case-insensitive search)
        session_id = None
        for name in self.session.cookies.keys():
            if name.lower() == "nexposeccsessionid":
                session_id = self.session.cookies.get(name)
                break

        if session_id:
            self.session.headers["Nexposeccsessionid"] = session_id
            log.debug("Set Nexposeccsessionid header from cookie.")
        else:
            log.warning(
                "Could not find 'nexposeCCSessionID' in cookies. "
                "Write operations may fail with 406. "
                "Make sure your cookie string includes nexposeCCSessionID=<value>."
            )

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------
    def _url(self, path: str) -> str:
        return f"{self.base_url}{API_BASE}{path}"

    def test_connection(self) -> bool:
        """Verify authentication by hitting a lightweight endpoint."""
        try:
            resp = self.session.get(self._url("/tags"), params={"size": 1, "page": 0})
            if resp.status_code == 401:
                log.error(
                    "401 Unauthorized — authentication failed.\n"
                    "  Possible causes:\n"
                    "  1. Session cookie has expired — log in again and copy fresh cookies.\n"
                    "  2. Cookie string was pasted incorrectly or truncated.\n"
                    "  3. Missing required cookie (e.g. nexposeCCSessionID).\n"
                    "  4. Console requires a different auth method (try Basic Auth with --user).\n"
                )
                return False
            if resp.status_code == 403:
                log.error("403 Forbidden — your account lacks API permissions.")
                return False
            resp.raise_for_status()
            return True
        except requests.ConnectionError as exc:
            log.error("Cannot connect to %s — %s", self.base_url, exc)
            return False

    def _get(self, path: str, params: dict | None = None) -> dict:
        resp = self.session.get(self._url(path), params=params)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, payload=None) -> requests.Response:
        resp = self.session.post(self._url(path), json=payload)
        if resp.status_code == 406:
            log.error(
                "406 Not Acceptable from %s.\n"
                "  Response body: %s\n"
                "  Ensure your cookie string includes 'nexposeCCSessionID=<value>'.\n"
                "  The session ID must be present for write operations.\n"
                "  Alternatively, use --user for Basic Auth.",
                path,
                resp.text[:500],
            )
        resp.raise_for_status()
        return resp

    def _put(self, path: str, payload=None) -> requests.Response:
        resp = self.session.put(self._url(path), json=payload)
        if resp.status_code == 406:
            log.error("406 Not Acceptable from %s. Ensure nexposeCCSessionID is in cookies. Response: %s", path, resp.text[:500])
        resp.raise_for_status()
        return resp

    def _delete(self, path: str) -> requests.Response:
        resp = self.session.delete(self._url(path))
        resp.raise_for_status()
        return resp

    def _paginate(self, path: str, params: dict | None = None) -> list:
        """Fetch all pages of a paginated resource and return combined list."""
        params = dict(params or {})
        params.setdefault("size", PAGE_SIZE)
        params.setdefault("page", 0)
        results = []
        while True:
            data = self._get(path, params=params)
            resources = data.get("resources", [])
            results.extend(resources)
            page_info = data.get("page", {})
            total_pages = page_info.get("totalPages", 1)
            current_page = page_info.get("number", 0)
            if current_page + 1 >= total_pages:
                break
            params["page"] = current_page + 1
        return results

    # ------------------------------------------------------------------
    # Tag operations
    # ------------------------------------------------------------------
    def get_all_tags(self) -> list[dict]:
        """Return every tag defined in the console."""
        return self._paginate("/tags")

    def find_tag_by_name(self, tag_name: str) -> dict | None:
        """Find a tag by exact name (case-insensitive comparison)."""
        tags = self.get_all_tags()
        for t in tags:
            if t.get("name", "").lower() == tag_name.lower():
                return t
        return None

    def create_tag(self, tag_name: str, tag_type: str = "custom") -> dict:
        """
        Create a new custom tag.

        tag_type: 'custom', 'owner', 'location', 'criticality'
        """
        payload = {
            "name": tag_name,
            "type": tag_type,
        }
        resp = self._post("/tags", payload)
        # The response Location header or body contains the new tag
        if resp.status_code == 201:
            tag_id = resp.json().get("id")
            return self._get(f"/tags/{tag_id}")
        return resp.json()

    def get_or_create_tag(self, tag_name: str, tag_type: str = "custom") -> dict:
        """Find tag by name; create it if it doesn't exist."""
        tag = self.find_tag_by_name(tag_name)
        if tag:
            log.info("Tag '%s' already exists (id=%s).", tag_name, tag["id"])
            return tag
        log.info("Tag '%s' not found — creating it.", tag_name)
        return self.create_tag(tag_name, tag_type)

    def get_tag_assets(self, tag_id: int) -> list[dict]:
        """Return all assets associated with a tag."""
        return self._paginate(f"/tags/{tag_id}/assets")

    def tag_asset(self, tag_id: int, asset_id: int):
        """Add a tag to a single asset."""
        self._put(f"/tags/{tag_id}/assets/{asset_id}")

    def untag_asset(self, tag_id: int, asset_id: int):
        """Remove a tag from a single asset."""
        self._delete(f"/tags/{tag_id}/assets/{asset_id}")

    # ------------------------------------------------------------------
    # Asset search
    # ------------------------------------------------------------------
    def search_asset_by_ip(self, ip: str) -> list[dict]:
        """Search for assets matching an IP address."""
        payload = {
            "filters": [
                {"field": "ip-address", "operator": "is", "value": ip}
            ],
            "match": "all",
        }
        return self._post_search(payload)

    def search_asset_by_hostname(self, hostname: str) -> list[dict]:
        """Search for assets matching a hostname."""
        payload = {
            "filters": [
                {"field": "host-name", "operator": "is", "value": hostname}
            ],
            "match": "all",
        }
        return self._post_search(payload)

    def _post_search(self, payload: dict) -> list[dict]:
        """Execute an asset search and return all matching assets (paginated)."""
        page = 0
        results = []
        while True:
            resp = self.session.post(
                self._url(f"/assets/search"),
                json=payload,
                params={"size": PAGE_SIZE, "page": page},
            )
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("resources", []))
            page_info = data.get("page", {})
            total_pages = page_info.get("totalPages", 1)
            if page + 1 >= total_pages:
                break
            page += 1
        return results

    def resolve_identifier(self, identifier: str) -> list[dict]:
        """
        Resolve a hostname or IP to asset(s).
        Returns a list of matching asset dicts.
        """
        identifier = identifier.strip()
        if not identifier:
            return []

        # Simple heuristic: if it looks like an IP, search by IP first
        if _looks_like_ip(identifier):
            assets = self.search_asset_by_ip(identifier)
            if assets:
                return assets

        # Fall back / also try hostname
        assets = self.search_asset_by_hostname(identifier)
        return assets


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def _looks_like_ip(value: str) -> bool:
    """Quick check whether a string looks like an IPv4 address."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def load_identifiers_from_csv(csv_path: str) -> list[str]:
    """
    Read asset identifiers from a CSV file.
    Expects a column named 'hostname' or 'ip' (case-insensitive),
    or falls back to the first column.
    """
    identifiers: list[str] = []
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
            col = reader.fieldnames[0]  # fallback to first column

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
# High-level actions
# ---------------------------------------------------------------------------
def action_add(client: Rapid7Client, tag_name: str, identifiers: list[str]):
    """Add *tag_name* to every asset in *identifiers*."""
    tag = client.get_or_create_tag(tag_name)
    tag_id = tag["id"]
    success, skipped, failed = 0, 0, 0

    for ident in identifiers:
        assets = client.resolve_identifier(ident)
        if not assets:
            log.warning("No asset found for '%s' — skipping.", ident)
            skipped += 1
            continue
        for asset in assets:
            asset_id = asset["id"]
            asset_label = asset.get("hostName") or asset.get("ip", asset_id)
            try:
                client.tag_asset(tag_id, asset_id)
                log.info("Tagged asset '%s' (id=%s) with '%s'.", asset_label, asset_id, tag_name)
                success += 1
            except requests.HTTPError as exc:
                log.error("Failed to tag asset '%s': %s", asset_label, exc)
                failed += 1

    _print_summary("ADD", tag_name, success, skipped, failed)


def action_remove(client: Rapid7Client, tag_name: str, identifiers: list[str]):
    """Remove *tag_name* from every asset in *identifiers*."""
    tag = client.find_tag_by_name(tag_name)
    if not tag:
        log.error("Tag '%s' does not exist. Nothing to remove.", tag_name)
        return
    tag_id = tag["id"]
    success, skipped, failed = 0, 0, 0

    for ident in identifiers:
        assets = client.resolve_identifier(ident)
        if not assets:
            log.warning("No asset found for '%s' — skipping.", ident)
            skipped += 1
            continue
        for asset in assets:
            asset_id = asset["id"]
            asset_label = asset.get("hostName") or asset.get("ip", asset_id)
            try:
                client.untag_asset(tag_id, asset_id)
                log.info("Removed tag '%s' from asset '%s' (id=%s).", tag_name, asset_label, asset_id)
                success += 1
            except requests.HTTPError as exc:
                log.error("Failed to untag asset '%s': %s", asset_label, exc)
                failed += 1

    _print_summary("REMOVE", tag_name, success, skipped, failed)


def action_replace(
    client: Rapid7Client,
    old_tag_name: str,
    new_tag_name: str,
    identifiers: list[str] | None = None,
):
    """
    Replace *old_tag_name* with *new_tag_name*.

    If *identifiers* is provided, only process those assets.
    Otherwise, process ALL assets currently tagged with old_tag_name.
    """
    old_tag = client.find_tag_by_name(old_tag_name)
    if not old_tag:
        log.error("Old tag '%s' does not exist. Nothing to replace.", old_tag_name)
        return
    new_tag = client.get_or_create_tag(new_tag_name)
    old_tag_id = old_tag["id"]
    new_tag_id = new_tag["id"]

    # Determine which assets to process
    if identifiers:
        # Resolve provided identifiers then filter to those that actually have old_tag
        target_assets = []
        tagged_asset_ids = {a["id"] for a in client.get_tag_assets(old_tag_id)}
        for ident in identifiers:
            found = client.resolve_identifier(ident)
            if not found:
                log.warning("No asset found for '%s' — skipping.", ident)
                continue
            for a in found:
                if a["id"] in tagged_asset_ids:
                    target_assets.append(a)
                else:
                    log.info(
                        "Asset '%s' does not have tag '%s' — skipping.",
                        a.get("hostName") or a.get("ip", a["id"]),
                        old_tag_name,
                    )
    else:
        # Get all assets that currently carry the old tag
        target_assets = client.get_tag_assets(old_tag_id)
        if not target_assets:
            log.info("No assets currently have tag '%s'. Nothing to replace.", old_tag_name)
            return
        log.info("Found %d assets with tag '%s'.", len(target_assets), old_tag_name)

    success, failed = 0, 0
    for asset in target_assets:
        asset_id = asset["id"]
        asset_label = asset.get("hostName") or asset.get("ip", asset_id)
        try:
            # Add new tag first, then remove old tag
            client.tag_asset(new_tag_id, asset_id)
            client.untag_asset(old_tag_id, asset_id)
            log.info(
                "Replaced '%s' → '%s' on asset '%s' (id=%s).",
                old_tag_name,
                new_tag_name,
                asset_label,
                asset_id,
            )
            success += 1
        except requests.HTTPError as exc:
            log.error("Failed to replace tag on asset '%s': %s", asset_label, exc)
            failed += 1

    _print_summary("REPLACE", f"{old_tag_name} → {new_tag_name}", success, 0, failed)


def _print_summary(action: str, tag_info: str, success: int, skipped: int, failed: int):
    total = success + skipped + failed
    print("\n" + "=" * 60)
    print(f"  {action} summary for tag: {tag_info}")
    print(f"  Total processed : {total}")
    print(f"  Successful      : {success}")
    print(f"  Skipped (not found): {skipped}")
    print(f"  Failed          : {failed}")
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
        "--url",
        required=True,
        help="Rapid7 console URL, e.g. https://insightvm.company.com:3780",
    )
    parser.add_argument(
        "--cookies",
        help="Session cookies string (e.g. 'nexposeCCSessionID=abc123'). "
             "If not provided, you'll be prompted to enter them.",
    )
    parser.add_argument(
        "--user",
        help="Username for Basic Auth (alternative to cookies). Will prompt for password.",
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        default=False,
        help="Verify TLS certificate (default: skip verification).",
    )

    sub = parser.add_subparsers(dest="action", required=True)

    # --- add ---
    p_add = sub.add_parser("add", help="Add a tag to assets.")
    p_add.add_argument("--tag", required=True, help="Tag name to apply.")
    p_add.add_argument(
        "--tag-type",
        default="custom",
        choices=["custom", "owner", "location", "criticality"],
        help="Tag type if creating a new tag (default: custom).",
    )
    _add_asset_args(p_add)

    # --- remove ---
    p_rem = sub.add_parser("remove", help="Remove a tag from assets.")
    p_rem.add_argument("--tag", required=True, help="Tag name to remove.")
    _add_asset_args(p_rem)

    # --- replace ---
    p_rep = sub.add_parser("replace", help="Replace one tag with another.")
    p_rep.add_argument("--old-tag", required=True, help="Tag to remove.")
    p_rep.add_argument("--new-tag", required=True, help="Tag to apply instead.")
    p_rep.add_argument(
        "--tag-type",
        default="custom",
        choices=["custom", "owner", "location", "criticality"],
        help="Tag type if creating the new tag (default: custom).",
    )
    _add_asset_args(p_rep, required=False)

    return parser


def _add_asset_args(subparser, required: bool = True):
    """Add --assets and --csv arguments to a subparser."""
    group = subparser.add_mutually_exclusive_group(required=required)
    group.add_argument(
        "--assets",
        help="Comma-separated hostnames or IPs, e.g. 'server1,10.0.0.5,server2'",
    )
    group.add_argument(
        "--csv",
        help="Path to CSV file with a 'hostname' or 'ip' column.",
    )


def main():
    parser = build_parser()
    args = parser.parse_args()

    # --- Authentication ---
    if args.user:
        # Basic Auth mode
        from getpass import getpass as _getpass
        password = _getpass(f"Password for '{args.user}': ")
        client = Rapid7Client(
            base_url=args.url,
            cookies="",
            verify_ssl=args.verify_ssl,
        )
        client.session.auth = (args.user, password)
    else:
        # Cookie-based auth
        cookies = args.cookies or os.environ.get("RAPID7_COOKIES", "")
        if not cookies:
            print("\nEnter your Rapid7 session cookies.")
            print("(Paste the full cookie string from browser DevTools → Network → Cookie header)")
            print("Example: nexposeCCSessionID=abc123; _csrf_token=xyz\n")
            cookies = input("Cookies: ").strip()
        if not cookies:
            log.error("No cookies provided. Exiting.")
            sys.exit(1)

        client = Rapid7Client(
            base_url=args.url,
            cookies=cookies,
            verify_ssl=args.verify_ssl,
        )

    # Validate connection
    log.info("Testing connection to %s ...", args.url)
    if not client.test_connection():
        sys.exit(1)
    log.info("Authentication successful.")

    # Resolve identifiers
    identifiers: list[str] | None = None
    if getattr(args, "assets", None):
        identifiers = [i.strip() for i in args.assets.split(",") if i.strip()]
    elif getattr(args, "csv", None):
        identifiers = load_identifiers_from_csv(args.csv)

    # Dispatch
    if args.action == "add":
        if not identifiers:
            log.error("No assets provided. Use --assets or --csv.")
            sys.exit(1)
        action_add(client, args.tag, identifiers)

    elif args.action == "remove":
        if not identifiers:
            log.error("No assets provided. Use --assets or --csv.")
            sys.exit(1)
        action_remove(client, args.tag, identifiers)

    elif args.action == "replace":
        action_replace(client, args.old_tag, args.new_tag, identifiers)


if __name__ == "__main__":
    main()
