import hashlib
import re
from typing import List, Optional, Set

import click
from pgpy.errors import PGPError
from pgpy import PGPKey, PGPMessage, PGPSignature
import requests
from requests.exceptions import HTTPError
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

class ParseError(Exception):
    pass

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


class RepoErrors:
    DEFAULT = "default"
    def __init__(self) -> None:
        self.errors = dict()

    def add(self, repo : str, dist : str, error : Optional[str]) -> None:
        if repo not in self.errors:
            self.errors[repo] = dict()
        if dist not in self.errors[repo]:
            self.errors[repo][dist] = []
        if error is not None:
            self.errors[repo][dist].append(error.replace('\n', ' ').replace('\r', '').rstrip())
    def error_count(self, repo: Optional[str] = None, dist: Optional[str] = None) -> int:
        count = 0
        if repo:
            if dist:
                count += len(self.errors[repo][dist])
            else:
                for _, errors in self.errors[repo].items():
                    count += len(errors)
        else:
            for _, dists in self.errors.items():
                for _, errors in dists.items():
                    count += len(errors)

        return count

    def get_output(self) -> str:
        output = ""
        output += f"[repo_count: {len(self.errors)}]\n"
        for repo, dists in self.errors.items():
            output += f"{repo} [dist_count: {len(dists)}]\n"
            for dist, errors in dists.items():
                output += f"{dist} [error_count: {len(errors)}]\n"
                if errors:
                    output += ("\n").join(errors) + "\n"
        return output


def output_result(errors: RepoErrors, file) -> bool:
    """Output number of packages processed and errors."""
    # click.echo(f"Checked {proc_packages} package(s).")
    text_output = errors.get_output()
    if file is not None:
        file.write(text_output)
    else:
        click.echo(text_output)
    return errors.error_count() == 0

def package_output(proc_packages : int) -> None:
    click.echo(f"Checked {proc_packages} package(s).")


def check_repo_empty(url: str) -> bool:
    """Returns true if repo is empty"""
    try:
        resp = get_url(url)
        content = re.findall(r"href=[\"'](.*)[\"']", resp.text)
        content = list(filter(lambda c: ".." not in c, content))
        return len(content) == 0
    except HTTPError:
        return True

def verify_signature(pubkeys: Set[PGPKey], file_text: str, signature_text: Optional[str] = None):
    passed = False
    file = open("temp.txt", "w")
    file.write(file_text)
    file.close()

    msg = PGPMessage.new("temp.txt", file=True)

    # print(msg.message)

    if signature_text:
        sig = PGPSignature.from_blob(signature_text)
        msg |= sig
    else:
        sig = PGPSignature.from_blob(file_text)
        msg |= sig

    for pub in pubkeys:
        print("trying to verify")
        try:
            pub.verify(msg)
            passed = True
        except PGPError as e:
            print(e)
            # print(file)
            continue
    print(passed)
    return passed
    # try:
    #     file_text = get_url(file_url).text
    #     if signature_url:
    #         sig_text = get_url(file_url).text
    #     else:
    #         sig_text = None
    # except HTTPError as e:



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
