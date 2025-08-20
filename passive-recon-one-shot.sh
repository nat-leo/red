#!/usr/bin/env bash
# Usage: ./passive_recon.sh example.com
set -euo pipefail

DOMAIN="${1:?Give apex domain like example.com}"
OUTDIR="recon_${DOMAIN}"
mkdir -p "$OUTDIR"
cd "$OUTDIR"

echo "[*] WHOIS / registrar"
whois "$DOMAIN" | tee whois.txt >/dev/null

echo "[*] DNS posture (NS/MX/TXT/CAA, DMARC/SPF/DKIM)"
dig +short NS "$DOMAIN"   | tee ns.txt   >/dev/null
dig +short MX "$DOMAIN"   | tee mx.txt   >/dev/null
dig +short CAA "$DOMAIN"  | tee caa.txt  >/dev/null
dig +short TXT "$DOMAIN"  | tee txt.txt  >/dev/null
# DMARC/SPF/DKIM specifics:
dig +short TXT "_dmarc.${DOMAIN}" | tee dmarc.txt >/dev/null
dig +short TXT "${DOMAIN}" | grep -i spf | tee spf.txt >/dev/null
# DKIM selectors are org-specific; note presence is enough at passive stage.

echo "[*] CT logs via crt.sh (no auth)"
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
 | jq -r '.[].name_value' \
 | tr -d '\r' | sed 's/\*\.//g' \
 | sort -u > ct_subs.txt || true

echo "[*] Amass (passive only)"
amass enum -passive -d "$DOMAIN" -silent | sort -u > amass_subs.txt || true

echo "[*] Subfinder (passive only)"
subfinder -silent -passive -d "$DOMAIN" | sort -u > subfinder_subs.txt || true

echo "[*] (Optional) Brand/typo discovery"
dnstwist -r -c 50 -f csv "$DOMAIN" > dnstwist.csv || true

echo "[*] Merge with source tags"
{
  awk '{print $1",ct"}' ct_subs.txt 2>/dev/null
  awk '{print $1",amass"}' amass_subs.txt 2>/dev/null
  awk '{print $1",subfinder"}' subfinder_subs.txt 2>/dev/null
} | sort -u > subs_sources.csv

echo "[*] Add a simple role guess heuristic"
awk -F, -v OFS=, '
function role(h) {
  if (h ~ /(^|[.-])(api|graphql)([.-]|$)/)        return "api";
  if (h ~ /(^|[.-])(auth|login|sso)([.-]|$)/)     return "auth";
  if (h ~ /(^|[.-])(admin|adm|manage)([.-]|$)/)   return "admin";
  if (h ~ /(^|[.-])(dev|test|qa|staging|stage)([.-]|$)/) return "nonprod";
  if (h ~ /(^|[.-])(cdn|static|assets)([.-]|$)/)  return "cdn/static";
  if (h ~ /(^|[.-])(docs|status|help|support)([.-]|$)/) return "docs/status";
  return "unknown"
}
BEGIN { print "host,role_guess,first_seen_source" }
{ print $1, role($1), $2 }
' subs_sources.csv > surface_inventory.csv

echo "[*] Summaries"
echo "Total unique subdomains: $(tail -n +2 surface_inventory.csv | wc -l)"
echo "CSV ready: $PWD/surface_inventory.csv"
