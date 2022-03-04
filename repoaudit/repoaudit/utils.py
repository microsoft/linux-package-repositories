import hashlib
from typing import List, Optional

import click
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


class MultiHash:
    """A class to can handle multiple hash objs."""

    def __init__(self, algorithms: List[str]) -> None:
        """Define hashers with list of algorithms."""
        self.hashers = {}
        for alg in algorithms:
            self.hashers[alg] = hashlib.new(alg)

    def update(self, chunk: bytes) -> None:
        """Update hashers with a chunk."""
        for h in self.hashers.values():
            h.update(chunk)

    def hexdigest(self, alg: str) -> str:
        """Return the hasher hex digest for algorithm."""
        return self.hashers[alg].hexdigest()


def output_result(proc_packages: int, errors: List[str]) -> bool:
    """Output number of packages processed and errors."""
    click.echo(f"Checked {proc_packages} package(s).")
    if errors:
        click.echo(f"{len(errors)} errors found:\n" + ("\n").join(errors))
        return False
    else:
        click.echo("No errors detected.")
        return True


def urljoin(*paths: str) -> str:
    """Join together a set of url components."""
    # urllib's urljoin has a few gotchas and doesn't handle multiple paths
    return "/".join(map(lambda path: path.strip("/"), paths))


def retry_session(retries: int = 3) -> requests.Session:
    """Create a requests.Session with retries."""
    session = requests.Session()
    retry = Retry(total=retries)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def get_url(
    url: str,
    stream: bool = False,
    session: Optional[requests.Session] = None
) -> requests.Response:
    """Call requests.get() on a url and return the requests.Response."""
    if not session:
        session = retry_session()
    resp = session.get(url, stream=stream)
    resp.raise_for_status()
    return resp
