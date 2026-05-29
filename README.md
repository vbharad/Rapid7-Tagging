# Rapid7 Asset Tagger — Quick Reference

## Prerequisites

```
pip install requests
```

## Usage

All commands require `--url` (your Rapid7 console URL). Cookies are entered interactively as a secure prompt.

### 1. Add a tag to specific assets

```bash
# By hostname/IP (comma-separated)
python rapid7_asset_tagger.py --url https://insightvm.company.com:3780 add --tag "PCI-Scope" --assets "server1,server2,10.0.0.5"

# From a CSV file
python rapid7_asset_tagger.py --url https://insightvm.company.com:3780 add --tag "PCI-Scope" --csv sample_assets.csv
```

### 2. Remove a tag from assets

```bash
python rapid7_asset_tagger.py --url https://insightvm.company.com:3780 remove --tag "Deprecated" --assets "server1,10.0.0.5"
```

### 3. Replace one tag with another

```bash
# Replace on ALL assets that currently have the old tag
python rapid7_asset_tagger.py --url https://insightvm.company.com:3780 replace --old-tag "Environment:Dev" --new-tag "Environment:Prod"

# Replace only on specific assets
python rapid7_asset_tagger.py --url https://insightvm.company.com:3780 replace --old-tag "tag1" --new-tag "tag2" --assets "server1,server2"
```

### 4. Verify SSL (optional)

Add `--verify-ssl` if your console uses a trusted certificate:

```bash
python rapid7_asset_tagger.py --url https://insightvm.company.com:3780 --verify-ssl add --tag "MyTag" --assets "server1"
```

## CSV Format

The CSV file should have a header row with one of these column names (case-insensitive):
`hostname`, `host`, `ip`, `ip_address`, `ipaddress`, `asset`

If none match, the first column is used.

```csv
hostname
server1
server2
10.0.0.5
```

## How Cookies Work

When prompted, paste the full cookie string from your browser's Developer Tools:
1. Log into the Rapid7 console in your browser
2. Open DevTools → Network tab → pick any API request
3. Copy the `Cookie` header value
4. Paste it when the script prompts `Cookies:`

Example cookie string:
```
nexposeCCSessionID=abcdef1234567890; _csrf_token=xyz
```
