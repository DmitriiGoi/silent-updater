from __future__ import annotations

import httpx
import pytest

from silent_updater.tools.bitbucket_ops import (
    BitbucketCoords,
    BitbucketError,
    create_pull_request,
)


def _coords() -> BitbucketCoords:
    return BitbucketCoords(
        base_url="https://bb.example.com",
        project_key="PROJ",
        repo_slug="app",
        token="pat_secret",
    )


def test_create_pr_success(httpx_mock):  # noqa: ANN001
    expected_url = "https://bb.example.com/rest/api/1.0/projects/PROJ/repos/app/pull-requests"
    httpx_mock.add_response(
        url=expected_url,
        method="POST",
        json={
            "id": 123,
            "links": {
                "self": [{"href": "https://bb.example.com/projects/PROJ/repos/app/pull-requests/123"}]
            },
        },
    )
    with httpx.Client() as c:
        url = create_pull_request(
            _coords(),
            title="Auto-update",
            description="d",
            source_branch="deps/x",
            target_branch="main",
            client=c,
        )
    assert url == "https://bb.example.com/projects/PROJ/repos/app/pull-requests/123"

    request = httpx_mock.get_request()
    assert request.headers["Authorization"] == "Bearer pat_secret"
    import json
    body = json.loads(request.content)
    assert body["fromRef"]["id"] == "refs/heads/deps/x"
    assert body["toRef"]["id"] == "refs/heads/main"


def test_create_pr_error_status(httpx_mock):  # noqa: ANN001
    httpx_mock.add_response(status_code=409, text="conflict")
    with httpx.Client() as c:
        with pytest.raises(BitbucketError, match="409"):
            create_pull_request(
                _coords(), title="t", description="d",
                source_branch="x", target_branch="main", client=c,
            )


def test_create_pr_falls_back_to_constructed_url(httpx_mock):  # noqa: ANN001
    httpx_mock.add_response(method="POST", json={"id": 7, "links": {}})
    with httpx.Client() as c:
        url = create_pull_request(
            _coords(), title="t", description="d",
            source_branch="x", target_branch="main", client=c,
        )
    assert url.endswith("/projects/PROJ/repos/app/pull-requests/7")
