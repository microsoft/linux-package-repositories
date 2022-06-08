# TODO: have script output to file

import re
from typing import List, Optional

import click
from requests.exceptions import HTTPError

from .apt import check_apt_repo
from .utils import RepoErrors, destroy_gpg, generate_random_folder, get_url, initialize_gpg, output_result, urljoin
from .yum import check_yum_repo

recursive_option = click.option(
    "--recursive",
    "-r",
    is_flag=True,
    help=(
        "Attempt to recursively check repos. Requires URL to point to a directory "
        "listing with links to the repos."
    ),
)

file_option = click.option(
    "--output",
    "-o",
    help=(
        "Output results to a specified file"
    ),
)

pubkey_option = click.option(
    "--pubkeys",
    "-p",
    help=(
        "Comma separated list of the url of public keys. "
        "When provided, signatures will be verified to make "
        "sure they match one of the public keys."
    )
)


def _get_repo_urls(url: str) -> List[str]:
    try:
        resp = get_url(url)
    except HTTPError as e:
        raise click.ClickException(
            f"{e}\n"
            "Please check the url or explicitly use repo urls without the --recursive option."
        )
    links = re.findall(r"href=[\"'](.*)[\"']", resp.text)
    return [urljoin(url, link) for link in links if ".." not in link]


@click.group()
def main() -> None:
    """Audit a repo by validating its repo metadata and packages."""
    pass


@main.command()
@recursive_option
@click.argument("url")
@click.option("--dists", help="Comma separated list of distributions.")
@file_option
@pubkey_option
def apt(recursive: bool, url: str, dists: str, output: str, pubkeys: str) -> None:
    """Validate an apt repository at URL."""
    if recursive:
        urls = _get_repo_urls(url)
    else:
        urls = [url]

    if dists:
        dist_set = set(dists.split(","))
    else:
        dist_set = None

    if pubkeys:
        try:
            gpg = initialize_gpg(pubkeys.split(","))
        except HTTPError as e:
            raise click.ClickException(
                f"{e}\n"
                "Please check the url for the public key"
            )
    else:
        gpg = None

    errors = RepoErrors()

    for repo_url in urls:
        if not check_apt_repo(repo_url, dist_set, gpg, errors):
            break

    destroy_gpg(gpg)
    output_result(errors, output)


@main.command()
@recursive_option
@click.argument("url")
@file_option
@pubkey_option
def yum(recursive: bool, url: str, output: str, pubkeys: str) -> None:
    """Validate a yum repository at URL."""
    if recursive:
        urls = _get_repo_urls(url)
    else:
        urls = [url]

    if pubkeys:
        try:
            gpg = initialize_gpg(pubkeys.split(","))
        except HTTPError as e:
            raise click.ClickException(
                f"{e}\n"
                "Please check the url for the public key"
            )
    else:
        gpg = None

    errors = RepoErrors()

    temp_gpg_path = generate_random_folder()

    for repo_url in urls:
        if not check_yum_repo(repo_url, gpg, temp_gpg_path, errors):
            break

    destroy_gpg(gpg)
    output_result(errors, output)
