import hashlib
import json
import os
import random
import re
import shutil
import string
import gnupg
from typing import List, Optional, Set

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
    DEFAULT = "default"

    def __init__(self) -> None:
        self.errors = dict()

    def add(self, repo: str, dist: str, error: Optional[str]) -> None:
        if repo not in self.errors:
            self.errors[repo] = dict()
        if dist not in self.errors[repo]:
            self.errors[repo][dist] = []
        if error is not None:
            self.errors[repo][dist].append(error.replace(
                '\n', ' ').replace('\r', '').rstrip())

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

    def get_json(self) -> str:
        return json.dumps(self.errors, indent = 4)

def generate_random_folder() -> str:
    path = "temp_"
    path += ''.join(random.choices(string.ascii_lowercase +
                        string.digits + string.ascii_uppercase, k=32))
    return path

def initialize_gpg(urls: List[str], home_dir: Optional[str] = None) -> Optional[gnupg.GPG]:
    """Raises HTTPError if key url is invalid"""
    if home_dir is None:
        home_dir = generate_random_folder()
    
    if not os.path.exists(home_dir):
        os.mkdir(home_dir)
    
    gpg = gnupg.GPG(gnupghome=home_dir)

    for url in urls:
        try:
            resp = get_url(url)
        except:
            if home_dir is None:
                destroy_gpg(gpg)
            else:
                destroy_gpg(gpg, keep_folder=True)
            raise

        gpg.import_keys(resp.text)

    return gpg


def destroy_gpg(gpg: Optional[gnupg.GPG], keep_folder: bool = False) -> None:
    if gpg and os.path.exists(gpg.gnupghome):
        if keep_folder:
            for filename in os.listdir(gpg.gnupghome):
                file_path = os.path.join(gpg.gnupghome, filename)
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
        else:
            shutil.rmtree(gpg.gnupghome)

def check_signature(repo: str, dist: str, file_url: str,
                    gpg: gnupg.GPG, errors: RepoErrors, 
                    signature_url: Optional[str] = None) -> bool:
    success = True

    try:
        file_text = get_url(file_url).text
        if signature_url:
            sig_text = get_url(signature_url).text
            sig_file_loc = os.path.join(gpg.gnupghome,"temp_sig_file.gpg")

            file = open(sig_file_loc, "w")
            file.write(sig_text)
            file.close()

            verified = gpg.verify_data(sig_file_loc, file_text.encode())
        else:
            verified = gpg.verify(file_text)
        
        if not verified:
            errors.add(repo, dist,
                f"Signature verification failed for {file_url} " +
                (f"with the signature {signature_url}" if signature_url else "")
            )
            success = False
    except HTTPError as e:
        errors.add(repo, dist,
            f"While checking signatures, could not access file at {e.response.url}: {e}"
        )
        success = False
    
    return success


def output_result(errors: RepoErrors, file_name: Optional[str]) -> bool:
    """Output number of packages processed and errors."""
    # click.echo(f"Checked {proc_packages} package(s).")
    
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


def check_repo_empty(url: str) -> bool:
    """Returns true if repo is empty"""
    try:
        resp = get_url(url)
        content = re.findall(r"href=[\"'](.*)[\"']", resp.text)
        content = list(filter(lambda c: ".." not in c, content))
        return len(content) == 0
    except HTTPError:
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
