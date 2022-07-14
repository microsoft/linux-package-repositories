from collections import defaultdict
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
from uuid import uuid4
import gnupg
from typing import List, Optional

import click
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
    """A class to keep track of repository errors. Each repository has an entry
    for each distro in it. If there are no distros (i.e. yum repo) then
    YUM_DIST or APT_DIST can be used instead."""

    YUM_DIST = "yum_dist"
    APT_DIST = "apt_dist"

    def __init__(self) -> None:
        self.errors = defaultdict(lambda: {"state": "empty"})

    def add(self, repo: str, dist: Optional[str], error: Optional[str]) -> None:
        """
        - If just a repository is specified without a dist and it hasn't been added yet, it
        will have the state "empty".
        - If a dist is specified, the repository it is a part of as well as
        the dist will have the state "ok".
        - If an error is specified, a dist and repo must also be specified
        for which the error is a part of. Upon adding an error, the dist and
        repo it is a part of will change to the state "error".
        """

        # update time which also adds repo to dictionary
        self.errors[repo]["time"] = str(datetime.datetime.utcnow())

        # add dist
        if dist:
            if "dists" not in self.errors[repo]:
                self.errors[repo]["dists"] = dict()

            if dist not in self.errors[repo]["dists"]:
                if "empty" == self.errors[repo]["state"]:
                    self.errors[repo]["state"] = "ok"  # repo no longer empty
                self.errors[repo]["dists"][dist] = dict()
                self.errors[repo]["dists"][dist]["state"] = "ok"

            if error:
                error_str = error.replace('\n', ' ').replace('\r', '').rstrip()
                if "dist_errors" not in self.errors[repo]["dists"][dist]:
                    self.errors[repo]["dists"][dist]["dist_errors"] = []

                self.errors[repo]["dists"][dist]["dist_errors"].append(error_str)
                self.errors[repo]["state"] = "error"
                self.errors[repo]["dists"][dist]["state"] = "error"

    def _dist_error_count(self, repo: str, dist: str):
        return len(self.errors[repo]["dists"][dist].get("dist_errors", []))

    def _repo_error_count(self, repo: str):
        if "dists" in self.errors[repo]:
            return sum([self._dist_error_count(repo, dist)
                        for dist in self.errors[repo]["dists"].keys()])

        return 0

    def error_count(self, repo: Optional[str] = None, dist: Optional[str] = None) -> int:
        """Return the number of errors in all repositories, in a single repository, or a single
        distro in a repository."""
        if repo:
            if dist:
                return self._dist_error_count(repo, dist)
            else:
                return self._repo_error_count(repo)

        else:
            return sum([self._repo_error_count(repo_str) for repo_str in self.errors.keys()])

    def get_output(self) -> str:
        return self.get_json()

    def get_json(self) -> str:
        return json.dumps(self.errors, indent=4)


def get_repo_urls(url: str, verify: Optional[str] = None) -> List[str]:
    """Returns a list of repository url's in the folder linked by the input url"""
    try:
        resp = get_url(url, verify=verify)
    except HTTPError as e:
        raise click.ClickException(
            f"{e}\n"
            "Please check the url or explicitly use repo urls without the --recursive option."
        )
    links = re.findall(r"href=[\"'](.*)[\"']", resp.text)
    return [urljoin(url, link) for link in links if ".." not in link]


def initialize_gpg(urls: List[str], home_dir: Optional[Path] = None,
                   verify: Optional[str] = None) -> gnupg.GPG:
    """
    Initializes a GPG object using the public keys at the input urls.
    Raises HTTPError if a key url is invalid.
    """
    if home_dir is None:
        _home_dir = Path(tempfile.gettempdir()) / f"temp_{uuid4().hex}"
    else:
        _home_dir = home_dir

    _home_dir.mkdir(exist_ok=True)

    gpg = gnupg.GPG(gnupghome=str(_home_dir))

    for url in urls:
        try:
            resp = get_url(url, verify=verify)
        except Exception:
            if home_dir is None:
                destroy_gpg(gpg)
            else:
                destroy_gpg(gpg, keep_folder=True)
            raise

        gpg.import_keys(resp.text)

    return gpg


def destroy_gpg(gpg: Optional[gnupg.GPG], keep_folder: bool = False) -> None:
    """Cleans up the resources used by a GPG object"""
    if gpg and Path(gpg.gnupghome).exists():
        if keep_folder:
            home_path = Path(gpg.gnupghome)
            for filename in home_path.iterdir():
                file_path = home_path / filename
                if file_path.is_file() or file_path.is_symlink():
                    file_path.unlink()
                elif file_path.is_dir():
                    shutil.rmtree(file_path)
        else:
            shutil.rmtree(gpg.gnupghome)


def check_signature(repo: str, dist: str, file_url: str,
                    gpg: gnupg.GPG, errors: RepoErrors,
                    signature_url: Optional[str] = None,
                    verify: Optional[str] = None) -> bool:
    """
    Check the signature on a file. If the signature is detached (in a separate file)
    its url can be specified with signature_url. It is expected input gpg already has
    the public keys loaded.
    """

    try:
        file_text = get_url(file_url, verify=verify).text
        if signature_url:
            sig_text = get_url(signature_url, verify=verify).text
            sig_file_loc = Path(gpg.gnupghome) / "temp_sig_file.gpg"

            file = open(sig_file_loc, "w")
            file.write(sig_text)
            file.close()

            verified = gpg.verify_data(str(sig_file_loc), file_text.encode())
        else:
            verified = gpg.verify(file_text)

        if not verified:
            errors.add(
                repo, dist,
                f"Signature verification failed for {file_url} " +
                (f"with the signature {signature_url}" if signature_url else "")
            )
            return False
    except HTTPError as e:
        errors.add(
            repo, dist,
            f"While checking signatures, could not access file at {e.response.url}: {e}"
        )
        return False

    return True


def output_result(errors: RepoErrors, file_name: Optional[str]) -> bool:
    """Output number of packages processed and errors."""

    if file_name is not None:
        text_output = errors.get_json()
        file = open(file_name, "w")
        file.write(text_output)
        file.close()
    else:
        text_output = errors.get_output()
        click.echo(text_output)
    return errors.error_count() == 0


def package_output(proc_packages: int) -> None:
    click.echo(f"Checked {proc_packages} package(s).")


def check_repo_empty(url: str, verify: Optional[str] = None) -> bool:
    """Returns true if repo is empty, false otherwise."""
    try:
        resp = get_url(url, verify=verify)
    except HTTPError:
        return True

    content = re.findall(r"href=[\"'](.*)[\"']", resp.text)
    content = list(filter(lambda c: ".." not in c, content))
    return len(content) == 0


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
    session: Optional[requests.Session] = None,
    verify: Optional[str] = None
) -> requests.Response:
    """Call requests.get() on a url and return the requests.Response."""
    if not session:
        session = retry_session()
    resp = session.get(url, stream=stream, verify=verify)
    resp.raise_for_status()
    return resp
