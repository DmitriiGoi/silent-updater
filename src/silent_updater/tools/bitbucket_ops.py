from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class BitbucketCoords:
    base_url: str           # e.g. https://bitbucket.bank.local
    project_key: str        # e.g. PROJ
    repo_slug: str          # e.g. app
    token: str


class BitbucketError(RuntimeError):
    pass


def create_pull_request(
    coords: BitbucketCoords,
    title: str,
    description: str,
    source_branch: str,
    target_branch: str,
    *,
    client: httpx.Client | None = None,
) -> str:
    """POST /rest/api/1.0/projects/{KEY}/repos/{slug}/pull-requests
    Returns PR URL on success.
    """
    path = (
        f"/rest/api/1.0/projects/{coords.project_key}"
        f"/repos/{coords.repo_slug}/pull-requests"
    )
    url = coords.base_url.rstrip("/") + path
    payload = {
        "title": title,
        "description": description,
        "state": "OPEN",
        "open": True,
        "closed": False,
        "fromRef": {
            "id": f"refs/heads/{source_branch}",
            "repository": {
                "slug": coords.repo_slug,
                "project": {"key": coords.project_key},
            },
        },
        "toRef": {
            "id": f"refs/heads/{target_branch}",
            "repository": {
                "slug": coords.repo_slug,
                "project": {"key": coords.project_key},
            },
        },
    }
    headers = {
        "Authorization": f"Bearer {coords.token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    owns_client = client is None
    if client is None:
        client = httpx.Client(timeout=30.0)
    try:
        resp = client.post(url, json=payload, headers=headers)
    finally:
        if owns_client:
            client.close()

    if resp.status_code >= 400:
        raise BitbucketError(
            f"POST {url} -> {resp.status_code}: {resp.text[:1000]}"
        )

    data = resp.json()
    pr_id = data.get("id")
    self_link = ""
    links = data.get("links", {}).get("self") or []
    if links and isinstance(links, list):
        self_link = links[0].get("href", "")
    if self_link:
        return self_link
    return f"{coords.base_url.rstrip('/')}/projects/{coords.project_key}/repos/{coords.repo_slug}/pull-requests/{pr_id}"
