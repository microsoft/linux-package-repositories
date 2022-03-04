import re
import zlib
from typing import Optional, Set

import click
from debian.deb822 import Packages, Release
from requests.exceptions import HTTPError

from .utils import MultiHash, get_url, output_result, urljoin

CHECKSUMS = {
    "MD5sum": "md5",
    "SHA1": "sha1",
    "SHA256": "sha256",
    "SHA512": "sha512",
}
CHUNK_SIZE = 2 * 1024 * 1024


def _find_dists(url: str) -> Set[str]:
    try:
        resp = get_url(urljoin(url, "dists"))
    except HTTPError as e:
        if e.response.status_code == 404:
            raise click.ClickException(f"Could not determine dists from {url}."
                                       "Please manually supply them with --dist.")
        raise

    links = re.findall(r"href=[\"'](.*)[\"']", resp.text)
    return {dist.strip("/") for dist in links if ".." not in dist}


def _packages_file(base_url: str) -> str:
    try:
        resp = get_url(urljoin(base_url, "Packages"))
        return resp.text
    except HTTPError as e:
        if e.response.status_code == 404:
            resp = get_url(urljoin(base_url, "Packages.gz"))
            return zlib.decompress(resp.content, 16 + zlib.MAX_WBITS).decode()
        else:
            raise e


def check_apt_repo(url: str, dists: Optional[Set[str]]) -> bool:
    """Validate an apt repo."""
    click.echo(f"Validating apt repo at {url}...")
    errors = []
    proc_packages = 0

    if not dists:
        dists = _find_dists(url)
    click.echo(f"Checking dists: {', '.join(dists)}")

    try:
        for dist in dists:
            dist_url = urljoin(url, "dists", dist)
            release = get_url(urljoin(dist_url, "Release")).text
            release_file = Release(release)

            components = release_file["Components"].split()
            architectures = release_file["Architectures"].split()

            for comp in components:
                for arch in architectures:
                    packages = _packages_file(urljoin(dist_url, comp, f"binary-{arch}"))
                    # count the paragraphs
                    package_count = len(re.findall(r"^Package: ", packages, re.MULTILINE))
                    click.echo(f"Checking {dist}/{comp}/{arch}. Found {package_count} package(s).")

                    with click.progressbar(
                        Packages.iter_paragraphs(packages, use_apt_pkg=False),
                        label="Checking packages(s)",
                        length=package_count,
                    ) as bar:
                        for package in bar:
                            checksums = set(CHECKSUMS.keys()) & set(package.keys())
                            checksum_types = {key: CHECKSUMS[key] for key in checksums}
                            multihash = MultiHash(list(checksum_types.values()))
                            file_url = urljoin(url, package["Filename"])

                            try:
                                response = get_url(f"{file_url}", stream=True)
                            except HTTPError as e:
                                errors.append(
                                    f"Could not access package at {e.response.url}: {e}"
                                )
                                continue

                            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                                multihash.update(chunk)

                            for key, alg in checksum_types.items():
                                if multihash.hexdigest(alg) != package[key]:
                                    errors.append(
                                        f"{key} checksum mismatch for '{package['Filename']}'. "
                                        f"Expected '{package[key]}' but received "
                                        f"'{multihash.hexdigest(alg)}'."
                                    )
                            proc_packages += 1
    except HTTPError as e:
        click.echo(f"Error when attempting to access {e.response.url}: {e}", err=True)
        return False
    except KeyboardInterrupt:
        output_result(proc_packages, errors)
        raise

    return output_result(proc_packages, errors)
