"""
Lightweight Cortex XDR incident fetcher and KPI summarizer.

This module keeps the functionality intentionally small: it authenticates to the
Advanced API, fetches incidents for the current month, and prints basic counts.
"""

from __future__ import annotations

import calendar
import hashlib
import logging
import secrets
import string
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)

PAGE_SIZE = 100
MAX_PAGES = 10
DEFAULT_REGION_DOMAIN = "xdr.us.paloaltonetworks.com"


# --- Cortex XDR Advanced API authentication + request wrapper ---
def advanced_authentication(
    api_key_id: str,
    api_key: str,
    url: str,
    data: Optional[Dict[str, Any]],
    timeout: int = 30,
) -> Optional[requests.Response]:
    """
    Builds the Cortex XDR Advanced API auth headers (nonce + timestamp + SHA256 signature),
    sends a POST request, and validates the HTTP response.
    """
    nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
    timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)

    # The API expects SHA256(api_key + nonce + timestamp)
    auth_key = f"{api_key}{nonce}{timestamp}".encode("utf-8")
    api_key_hash = hashlib.sha256(auth_key).hexdigest()

    headers = {
        "x-xdr-timestamp": str(timestamp),
        "x-xdr-nonce": nonce,
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key_hash,
        "Content-Type": "application/json",
    }

    request_body = {"request_data": data if data is not None else {}}

    try:
        response = requests.post(url=url, headers=headers, json=request_body, timeout=timeout)
        response.raise_for_status()
        validate_response(response)
        return response
    except requests.exceptions.RequestException as exc:
        LOGGER.error("Request failed: %s", exc)
        return None


def validate_response(response: requests.Response) -> None:
    """Lightweight response validation/logging (kept intentionally minimal)."""
    if response is not None:
        LOGGER.debug("HTTP Status Code: %s", response.status_code)


# --- Request payload builders ---
def qt_incidents(epoch_first_day: int, epoch_last_day: int, page_from: int, page_to: int) -> Dict[str, Any]:
    """
    Builds the payload for /incidents/get_incidents using a creation_time time range and paging.
    """
    return {
        "filters": [
            {"field": "creation_time", "operator": "gte", "value": epoch_first_day},
            {"field": "creation_time", "operator": "lte", "value": epoch_last_day},
        ],
        "search_from": page_from,
        "search_to": page_to,
        "sort": {"field": "creation_time", "keyword": "asc"},
    }


# --- Output formatting helper ---
def pretty(title: str, data: Any) -> None:
    """
    Prints nested dictionaries/lists in a readable format.
    """
    print(f"{title}:")

    # Remove 'reply' only if 'data' is a dict
    if isinstance(data, dict):
        data = data.get("reply", data)

    if isinstance(data, list):
        # List of tuples (name, value) or simple items
        for item in data:
            if isinstance(item, tuple) and len(item) == 2:
                k, v = item
                print(f"  {k}: {v}")
            else:
                print(f"  {item}")
        return

    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, dict) and len(v) == 1:
                subk, subv = next(iter(v.items()))
                print(f"  {k}: {subv} ({subk})")
            else:
                if isinstance(v, str):
                    v = v.split(",", 1)[0].strip()
                print(f"  {k}: {v}")
        return

    print(f"  {data}")


# --- Date/time utilities ---
def get_month_epoch_range_utc(reference_utc: Optional[datetime] = None) -> Tuple[int, int]:
    """
    Returns (epoch_first_day_ms, epoch_last_day_ms) for the month of the provided UTC datetime.
    """
    now_utc = reference_utc or datetime.now(timezone.utc)

    first_day_utc = datetime(
        year=now_utc.year,
        month=now_utc.month,
        day=1,
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
        tzinfo=timezone.utc,
    )

    last_day = calendar.monthrange(now_utc.year, now_utc.month)[1]
    last_day_utc = datetime(
        year=now_utc.year,
        month=now_utc.month,
        day=last_day,
        hour=23,
        minute=59,
        second=59,
        microsecond=999000,
        tzinfo=timezone.utc,
    )

    return int(first_day_utc.timestamp() * 1000), int(last_day_utc.timestamp() * 1000)


def build_urls(tenant_name: str, region_domain: str = DEFAULT_REGION_DOMAIN) -> Tuple[str, str]:
    """
    Builds the main API endpoints based on the tenant name.
    The tenant name is the part before '.xdr' in the Cortex XDR URL.
    """
    base_url = f"https://api-{tenant_name}.{region_domain}"
    url_get_incidents = f"{base_url}/public_api/v1/incidents/get_incidents"
    url_tenant_info = f"{base_url}/public_api/v1/system/get_tenant_info"
    return url_get_incidents, url_tenant_info


# --- Core processing functions ---
def fetch_all_incidents_paged(
    api_key_id: str,
    api_key: str,
    url_get_incidents: str,
    epoch_first_day: int,
    epoch_last_day: int,
    page_size: int = PAGE_SIZE,
    max_pages: int = MAX_PAGES,
) -> List[Dict[str, Any]]:
    """
    Fetches incidents using paging. Keeps the same general structure as the original loop,
    but makes it reusable and safer.
    """
    page_from = 0
    page_to = page_size
    all_incidents: List[Dict[str, Any]] = []

    for _ in range(max_pages):
        payload = qt_incidents(epoch_first_day, epoch_last_day, page_from, page_to)
        response = advanced_authentication(api_key_id, api_key, url_get_incidents, data=payload)

        if not response:
            LOGGER.error("Failed to fetch incidents (no response).")
            break

        response_json = response.json()
        incidents = response_json.get("reply", {}).get("incidents", []) or []

        all_incidents.extend(incidents)

        page_from += page_size
        page_to += page_size

        # Stop when the API returns an empty page
        if not incidents:
            break

    return all_incidents


def compute_mitre_stats(all_incidents: List[Dict[str, Any]]) -> Tuple[int, Dict[Any, int], Dict[Any, int]]:
    """
    Aggregates alert count and counts MITRE tactics/techniques occurrences across incidents.
    """
    total_alerts = 0
    tactics_count: Dict[Any, int] = {}
    techniques_count: Dict[Any, int] = {}

    for inc in all_incidents:
        total_alerts += inc.get("alert_count", 0)

        tactics = inc.get("mitre_tactics_ids_and_names") or []
        techniques = inc.get("mitre_techniques_ids_and_names") or []

        for t in tactics:
            tactics_count[t] = tactics_count.get(t, 0) + 1

        for tech in techniques:
            techniques_count[tech] = techniques_count.get(tech, 0) + 1

    return total_alerts, tactics_count, techniques_count


def top_n(counter_dict: Dict[Any, int], n: int = 10) -> List[Tuple[Any, int]]:
    """Returns top-N items by count (descending)."""
    return sorted(counter_dict.items(), key=lambda x: x[1], reverse=True)[:n]


# --- Main program ---
def main() -> None:
    # User inputs
    tenant_name = input(
        "Enter your Cortex XDR tenant name (the part before '.xdr' in the URL): "
    ).strip()

    api_key_id = input("Enter your API Key ID: ").strip()
    api_key = input("Enter your API Key: ").strip()

    url_get_incidents, url_tenant_info = build_urls(tenant_name)

    epoch_first_day, epoch_last_day = get_month_epoch_range_utc()

    # Fetch incidents (paged)
    all_incidents = fetch_all_incidents_paged(
        api_key_id=api_key_id,
        api_key=api_key,
        url_get_incidents=url_get_incidents,
        epoch_first_day=epoch_first_day,
        epoch_last_day=epoch_last_day,
        page_size=PAGE_SIZE,
        max_pages=MAX_PAGES,
    )

    # Tenant info request
    response_tenant_info = advanced_authentication(api_key_id, api_key, url_tenant_info, data={})
    tenant_info_payload = response_tenant_info.json() if response_tenant_info else {}

    # Compute stats
    total_alerts, tactics_count, techniques_count = compute_mitre_stats(all_incidents)

    top10_tactics = top_n(tactics_count, 10)
    top10_techniques = top_n(techniques_count, 10)

    # Output KPIs
    print("Number of cases in the month:", len(all_incidents))
    print("Number of alerts in the month:", total_alerts)
    pretty("Top 10 MITRE tactics", top10_tactics)
    pretty("Top 10 MITRE techniques", top10_techniques)
    pretty("Tenant info", tenant_info_payload)


if __name__ == "__main__":
    main()
