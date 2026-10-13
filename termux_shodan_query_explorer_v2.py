#!/usr/bin/env python3
"""
Shodan Query Explorer for Termux
Interactive helper for composing and running Shodan Search API queries.
It does not bypass Shodan permissions, plan limits, or indexing.
"""
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime

BASE = "https://api.shodan.io"

# Shodan search filters commonly used with /shodan/host/search.
# Filter names and accepted values can evolve; check Shodan's official docs.
FILTERS = [
    ("asn", "AS number", "asn:AS####", "Find results associated with an autonomous system."),
    ("city", "City", 'city:"Abuja"', "Filter by city name."),
    ("country", "Country code", "country:NG", "Two-letter country code, e.g. NG or DE."),
    ("geo", "Coordinates", "geo:9.0765,7.3986", "Latitude,longitude coordinates."),
    ("has_ipv6", "IPv6 presence", "has_ipv6:true", "Filter for IPv6-related results where supported."),
    ("has_screenshot", "Screenshot", "has_screenshot:true", "Filter for results with screenshots where supported."),
    ("hostname", "Hostname", "hostname:.com.ng", "Match hostnames, e.g. hostname:.com.ng."),
    ("http.component", "HTTP component", "http.component:nginx", "Filter by detected HTTP component."),
    ("http.html", "HTTP page text", 'http.html:"Welcome"', "Search indexed HTTP page content."),
    ("http.status", "HTTP status", "http.status:200", "Filter by HTTP status code."),
    ("http.title", "HTTP title", 'http.title:"Login"', "Search indexed HTTP page titles."),
    ("isp", "ISP", 'isp:"Example ISP"', "Filter by Internet service provider."),
    ("net", "Network/CIDR", "net:203.0.113.0/24", "Filter by IP range (replace example range)."),
    ("org", "Organization", 'org:"Example Org"', "Filter by organization associated with an IP."),
    ("os", "Operating system", 'os:"Linux"', "Filter by detected operating system where available."),
    ("port", "Port", "port:443", "Filter by open/indexed service port."),
    ("product", "Product", "product:Apache", "Filter by detected product."),
    ("region", "Region", 'region:"FCT"', "Filter by region/state where available."),
    (" state", "State", 'state:"FCT"', "Example only; verify support and values in official docs."),
    ("ssl", "TLS/SSL field", "ssl:true", "Generic example; use specific SSL filters supported by Shodan."),
    ("ssl.cert.subject.cn", "Certificate common name", "ssl.cert.subject.cn:example.com", "Search certificate subject common name."),
    ("ssl.cert.issuer.cn", "Certificate issuer", 'ssl.cert.issuer.cn:"Example CA"', "Search certificate issuer common name."),
    ("ssl.cert.expired", "Expired certificate", "ssl.cert.expired:true", "Filter for expired certificates where supported."),
    ("ssl.version", "TLS version", 'ssl.version:"TLSv1.3"', "Search observed TLS version where supported."),
    ("tag", "Tag", "tag:cloud", "Filter by Shodan tags."),
    ("vuln", "CVE", "vuln:CVE-2021-44228", "Search for vulnerability tags in indexed results; validate findings."),
]

EXAMPLES = [
    ("Nigerian .com.ng HTTPS", "hostname:.com.ng port:443"),
    ("Nigerian domains on HTTP", "hostname:.com.ng port:80"),
    ("Nigerian country-code domains", "hostname:.ng"),
    ("Germany HTTPS", "country:DE port:443"),
    ("Nigeria HTTPS", "country:NG port:443"),
    ("Nginx on HTTPS", "product:nginx port:443"),
    ("Apache web servers", "product:Apache port:80"),
    ("A specific network", "net:203.0.113.0/24"),
    ("TLS certificate name", "ssl.cert.subject.cn:example.com"),
    ("Custom query", None),
]

def api_get(path, params):
    url = BASE + path + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "Termux-Shodan-Query-Explorer/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            message = json.loads(body).get("error", body)
        except json.JSONDecodeError:
            message = body
        print(f"\n[Shodan API error {e.code}] {message}")
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"\n[Connection error] {e}")
    except json.JSONDecodeError:
        print("\n[Error] Shodan returned invalid JSON.")
    return None

def show_result(item, idx):
    loc = item.get("location") or {}
    hosts = ", ".join(item.get("hostnames") or []) or "(none listed)"
    domains = ", ".join(item.get("domains") or []) or "(none listed)"
    place = ", ".join(x for x in [loc.get("city"), loc.get("region_code"), loc.get("country_code")] if x) or "unknown"
    banner = re.sub(r"\s+", " ", (item.get("data") or "").strip())[:220]
    print(f"\n{idx}. {item.get('ip_str', '?')}:{item.get('port', '?')}/{item.get('transport', '?')}")
    print(f"   Hostnames: {hosts}")
    print(f"   Domains:   {domains}")
    print(f"   Org/ISP:   {item.get('org') or '(unknown)'} / {item.get('isp') or '(unknown)'}")
    print(f"   Location:  {place}")
    if banner:
        print(f"   Banner:    {banner}")

def save_json(results, query):
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", query)[:48].strip("_") or "query"
    filename = f"shodan_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump({"query": query, "count_saved": len(results), "matches": results}, f, indent=2, ensure_ascii=False)
        print(f"Saved {len(results)} results to {os.path.abspath(filename)}")
    except OSError as e:
        print(f"Save failed: {e}")

def run_search(api_key, query):
    page = 1
    gathered = []
    while True:
        print(f"\nQuery: {query} | page {page}")
        data = api_get("/shodan/host/search", {"key": api_key, "query": query, "page": page})
        if data is None:
            return
        matches = data.get("matches") or []
        print(f"Total reported by Shodan: {data.get('total', 'unknown')} | this page: {len(matches)}")
        if not matches:
            print("No results on this page.")
            return
        for i, match in enumerate(matches, start=(page - 1) * 100 + 1):
            show_result(match, i)
        gathered.extend(matches)
        choice = input("\n[N]ext page, [S]ave JSON, [Q]uit search: ").strip().lower()
        if choice == "n":
            page += 1
        elif choice == "s":
            save_json(gathered, query)
        elif choice in ("q", ""):
            return
        else:
            print("Please choose N, S, or Q.")

def show_help():
    print("\n=== SHODAN QUERY FILTER HELP ===")
    print("Syntax: filter:value filter:value")
    print("Example: hostname:.com.ng port:443 country:DE")
    print("Use quotes for values containing spaces. Combine filters with spaces.")
    print("These are commonly used filters/examples, not every possible Shodan filter.")
    print("Availability and behavior depend on Shodan's current documentation and plan.\n")
    for name, label, example, desc in FILTERS:
        name = name.strip()
        print(f"{name:<25} {example:<42} {desc}")
    print("\nUseful query operators:")
    print("  AND: spaces between filters, e.g. hostname:.com.ng port:443")
    print("  OR:  use Shodan's supported Boolean syntax where applicable")
    print("  NOT: use Shodan's supported exclusion syntax where applicable")
    print("\nOfficial references:")
    print("  Search filters: https://www.shodan.io/search/filters")
    print("  Search API:     https://developer.shodan.io/api")
    print("  CLI reference:  https://cli.shodan.io/")
    input("\nPress Enter to return to menu...")

def main():
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not key:
        print('Set your API key first: export SHODAN_API_KEY="YOUR_API_KEY"')
        print("Get it from https://account.shodan.io/ and keep it private.")
        return 1
    while True:
        print("\n=== SHODAN QUERY EXPLORER v2 — TERMUX ===")
        print("1. Search with preset")
        print("2. Custom query")
        print("3. Filter/-help reference")
        print("4. Open official Shodan filter docs")
        print("0. Exit")
        choice = input("Select: ").strip()
        if choice == "0":
            return 0
        if choice == "1":
            for i, (label, _) in enumerate(EXAMPLES, 1):
                print(f"{i}. {label}")
            picked = input("Preset number: ").strip()
            if not picked.isdigit() or not 1 <= int(picked) <= len(EXAMPLES):
                print("Invalid preset.")
                continue
            label, query = EXAMPLES[int(picked) - 1]
            if query is None:
                query = input("Enter query: ").strip()
            if query:
                run_search(key, query)
        elif choice == "2":
            query = input("Shodan query: ").strip()
            if query:
                run_search(key, query)
        elif choice == "3":
            show_help()
        elif choice == "4":
            print("Opening docs is not automatic in this CLI.")
            print("In Termux run: termux-open-url https://www.shodan.io/search/filters")
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        sys.exit(0)
