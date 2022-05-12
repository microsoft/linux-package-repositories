import re
from typing import List

import click
from requests.exceptions import HTTPError

from .apt import check_apt_repo
from .utils import get_url
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


def _get_repo_urls(url: str) -> List[str]:
    try:
        resp = get_url(url)
    except HTTPError as e:
        raise click.ClickException(
            f"{e}\n"
            "Please check the url or explicitly use repo urls without the --recursive option."
        )
    links = re.findall(r"href=[\"'](.*)[\"']", resp.text)
    return [f"{url}/{link}" for link in links if ".." not in link]


@click.group()
def main() -> None:
    """Audit a repo by validating its repo metadata and packages."""
    pass


@main.command()
@recursive_option
@click.argument("url")
@click.option("--dists", help="Comma separated list of distributions.")
def apt(recursive: bool, url: str, dists: str) -> None:
    """Validate an apt repository at URL."""
    if recursive:
        urls = _get_repo_urls(url)
    else:
        urls = [url]

    if dists:
        dist_set = set(dists.split(","))
    else:
        dist_set = None

    for repo_url in urls:
        check_apt_repo(repo_url, dist_set)


@main.command()
@recursive_option
@click.argument("url")
def yum(recursive: bool, url: str) -> None:
    """Validate a yum repository at URL."""
    if recursive:
        urls = _get_repo_urls(url)
    else:
        urls = [url]

    for repo_url in urls:
        check_yum_repo(repo_url)
