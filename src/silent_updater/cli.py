from __future__ import annotations

import logging
import os
import sys
import tempfile
from pathlib import Path

import click

from silent_updater.agent.dependency_updater import DependencyUpdaterAgent
from silent_updater.auth import github_device_flow
from silent_updater.auth.token_store import BB_KEY, GH_KEY, default_store
from silent_updater.inputs.compliance import load_compliance
from silent_updater.inputs.excel_loader import load_vulnerable_libs
from silent_updater.llm.github_models_client import GitHubModelsClient
from silent_updater.tools import git_ops
from silent_updater.tools.bitbucket_ops import BitbucketCoords


# Public client_id for the OAuth App registered for silent-updater.
# (User can override via env if they prefer their own OAuth App.)
DEFAULT_CLIENT_ID = os.environ.get("SILENT_UPDATER_GH_CLIENT_ID", "")
# App-scoped proxy (overrides ambient http(s)_proxy ONLY for our GitHub calls).
DEFAULT_PROXY = os.environ.get("SILENT_UPDATER_PROXY", "")


@click.group()
@click.option("--verbose", is_flag=True, help="Verbose logging")
def main(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


@main.command()
@click.option("--client-id", default=DEFAULT_CLIENT_ID,
              help="GitHub OAuth App client_id (or set SILENT_UPDATER_GH_CLIENT_ID).")
@click.option("--proxy", default=DEFAULT_PROXY,
              help="HTTP(S) proxy URL for GitHub calls only "
                   "(e.g. http://USER:PASS@user-proxy.host:port). "
                   "Falls back to SILENT_UPDATER_PROXY env. "
                   "Ambient http_proxy/https_proxy are NOT used for our requests "
                   "unless you set them here.")
def login(client_id: str, proxy: str) -> None:
    """Authenticate with GitHub via device flow."""
    if not client_id:
        click.echo("ERROR: --client-id required (or set SILENT_UPDATER_GH_CLIENT_ID).",
                   err=True)
        sys.exit(2)
    token = github_device_flow.login(client_id=client_id, proxy=proxy or None)
    click.echo(f"Saved GitHub token (len={len(token)}). You can now run `silent-updater run`.")


@main.command()
def logout() -> None:
    """Forget the stored GitHub token."""
    github_device_flow.logout()
    click.echo("Logged out.")


@main.command("set-bitbucket-token")
@click.argument("token")
def set_bitbucket_token(token: str) -> None:
    """Store a Bitbucket Server HTTP Access Token in OS keyring."""
    default_store().save(BB_KEY, token)
    click.echo("Saved Bitbucket token.")


@main.command()
@click.option("--repo-url", required=True, help="Bitbucket repo URL (git clone target).")
@click.option("--pipeline-cmd", required=True,
              help="Regression pipeline command, e.g. 'mvn clean verify -DskipITs'.")
@click.option("--compliance", "compliance_path", required=True, type=click.Path(exists=True),
              help="Path to compliance_config.json.")
@click.option("--vuln-xlsx", required=True, type=click.Path(exists=True),
              help="Path to vulnerable_libs.xlsx.")
@click.option("--workdir", type=click.Path(),
              help="Working directory (default: temp dir).")
@click.option("--bitbucket-base", help="Base URL of Bitbucket Server (e.g. https://bitbucket.bank.local).")
@click.option("--project-key", help="Bitbucket project key.")
@click.option("--repo-slug", help="Bitbucket repo slug.")
@click.option("--model", default="gpt-4o", help="Model id from GitHub Models catalog.")
@click.option("--max-iterations", default=100, type=int)
@click.option("--pipeline-timeout", default=1800, type=int)
@click.option("--dry-run", is_flag=True, help="Plan only — do not modify files or git.")
@click.option("--client-id", default=DEFAULT_CLIENT_ID, help="GitHub OAuth App client_id.")
@click.option("--proxy", default=DEFAULT_PROXY,
              help="HTTP(S) proxy URL for GitHub calls only. "
                   "Falls back to SILENT_UPDATER_PROXY env. Bitbucket is NOT proxied.")
@click.option("--branch", default=None, help="Existing branch to clone (default: repo HEAD).")
def run(
    repo_url: str,
    pipeline_cmd: str,
    compliance_path: str,
    vuln_xlsx: str,
    workdir: str | None,
    bitbucket_base: str | None,
    project_key: str | None,
    repo_slug: str | None,
    model: str,
    max_iterations: int,
    pipeline_timeout: int,
    dry_run: bool,
    client_id: str,
    proxy: str,
    branch: str | None,
) -> None:
    """Clone, update vulnerable deps, push PR."""
    store = default_store()
    if not client_id:
        click.echo("ERROR: --client-id required (or env SILENT_UPDATER_GH_CLIENT_ID).",
                   err=True)
        sys.exit(2)
    token = github_device_flow.get_or_login(
        client_id=client_id, store=store, proxy=proxy or None,
    )

    bitbucket: BitbucketCoords | None = None
    if bitbucket_base and project_key and repo_slug:
        bb_token = store.load(BB_KEY) or os.environ.get("BITBUCKET_TOKEN", "")
        if not bb_token:
            click.echo(
                "WARN: --bitbucket-base/--project-key/--repo-slug supplied but no token in "
                "keyring nor BITBUCKET_TOKEN env. PR creation will be disabled.",
                err=True,
            )
        else:
            bitbucket = BitbucketCoords(
                base_url=bitbucket_base,
                project_key=project_key,
                repo_slug=repo_slug,
                token=bb_token,
            )

    vuln_entries = load_vulnerable_libs(vuln_xlsx)
    if not vuln_entries:
        click.echo("No vulnerable entries found in Excel. Nothing to do.")
        return
    compliance = load_compliance(compliance_path)

    if workdir:
        wd = Path(workdir).resolve()
        wd.mkdir(parents=True, exist_ok=True)
    else:
        wd = Path(tempfile.mkdtemp(prefix="silent-updater-"))

    clone_target = wd / _repo_dir_name(repo_url)
    if not clone_target.exists():
        click.echo(f"Cloning {repo_url} → {clone_target}")
        git_ops.clone(repo_url, clone_target, branch=branch)
    else:
        click.echo(f"Reusing existing clone at {clone_target}")

    llm = GitHubModelsClient(token=token, model=model, proxy=proxy or None)
    transcript = clone_target / "run.log.jsonl"

    agent = DependencyUpdaterAgent(
        workdir=clone_target,
        repo_url=repo_url,
        pipeline_cmd=pipeline_cmd,
        pipeline_timeout=pipeline_timeout,
        vuln_entries=vuln_entries,
        compliance=compliance,
        bitbucket=bitbucket,
        llm_client=llm,
        model=model,
        max_iterations=max_iterations,
        dry_run=dry_run,
        transcript_log=transcript,
    )
    try:
        report = agent.run()
    finally:
        llm.close()

    click.echo("")
    click.echo(f"Updated: {len(report.succeeded)}")
    click.echo(f"Gave up: {len(report.gave_up)}")
    click.echo(f"Skipped: {len(report.skipped)}")
    click.echo(f"Branch:  {report.branch or '(none)'}")
    if report.pr_url:
        click.echo(f"PR:      {report.pr_url}")
    click.echo(f"Report:  {clone_target / 'update_report.md'}")


def _repo_dir_name(url: str) -> str:
    name = url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name or "repo"


if __name__ == "__main__":
    main()
