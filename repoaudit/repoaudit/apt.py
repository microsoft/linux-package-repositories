import re
import zlib
from typing import Optional, Set

import click
from debian.deb822 import Packages, Release
from requests.exceptions import HTTPError
import gnupg

from .utils import MultiHash, RepoErrors, check_repo_empty, check_signature, get_url, urljoin, package_output

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
        # if e.response.status_code == 404:
        #     raise click.ClickException(f"Could not determine dists from {url}. "
        #                                "Please manually supply them with --dist.")
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


def check_apt_repo_metadata(url : str, dist : str, release_file : Release, errors: RepoErrors) -> None:
    dist_url = urljoin(url, "dists", dist)
    checksum_types = {key : CHECKSUMS[key] for key in CHECKSUMS.keys() if key in release_file}
    
    success = True

    files = dict()
    for key in checksum_types:
        for file_def in release_file[key]:
            filename = file_def['name']
            if filename not in files:
                files[filename] = dict()
            files[filename][key] = file_def[key.lower()]

    if not files:
        errors.add(url, dist,
            urljoin(dist_url, "Release") + " file malformed"
        )
        success = False

    for file_name, checksums in files.items():
        multihash = MultiHash(list(checksum_types.values()))

        file_url = urljoin(dist_url, file_name)
        try:
            response = get_url(f"{file_url}", stream=True)
        except HTTPError as e:
            if f"{file_name}.gz" not in files:
                errors.add(url, dist,
                    f"Could not access file at {e.respose.url} : {e}"
                )
                success = False
            continue

        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
            multihash.update(chunk)
        
        for key, alg in checksum_types.items():
            if multihash.hexdigest(alg) != checksums[key]:
                errors.add(url, dist,
                    f"Metadata {key} checksum mismatch for '{file_name}'. "
                    f"Expected '{checksums[key]}' but received "
                    f"'{multihash.hexdigest(alg)}'."
                )
                success = False

    if success:
        click.echo("Metadata check successful")
    else:
        click.echo("Metadata check failed")

#TODO: Share a function between apt and yum signature checks
def check_apt_signatures(url : str, dist : str, gpg: Optional[gnupg.GPG], errors: RepoErrors) -> None:
    if gpg is None:
        return

    dist_url = urljoin(url, "dists", dist)
    release_url = urljoin(dist_url, "Release")
    releasesig_url = urljoin(dist_url, "Release.gpg")
    inrelease_url = urljoin(dist_url, "InRelease")

    success = (check_signature(url, dist, release_url, gpg, errors, signature_url=releasesig_url) and
               check_signature(url, dist, inrelease_url, gpg, errors))
    if success:
        click.echo("Signature check successful")
    else:
        click.echo("Signature check failed")


# returns false if interrupted by keyboard interrupt
def check_apt_repo(url: str, dists: Optional[Set[str]], gpg: Optional[gnupg.GPG], errors: RepoErrors) -> None:
    """Validate an apt repo."""
    click.echo(f"Validating apt repo at {url}...")
    proc_packages = 0

    if check_repo_empty(url):
        errors.add(url, RepoErrors.DEFAULT,
            f"Repository empty at {url}"
        )
        package_output(proc_packages)
        return

    if not dists:
        try:
            dists = _find_dists(url)
        except HTTPError as e:
            errors.add(url, RepoErrors.DEFAULT,
                f"Could not determine dists from {url}: {e}"
            )
            package_output(proc_packages)
            return

    click.echo(f"Checking dists: {', '.join(dists)}")

    for dist in dists:
        try:
            errors.add(url, dist, None) # add entry with no errors (yet)

            dist_url = urljoin(url, "dists", dist)
            release_url = urljoin(dist_url, "Release")
            try:
                release = get_url(release_url).text
            except HTTPError as e:
                errors.add(url, dist,
                    f"Could not access Release file at {e.response.url}: {e}"
                )
                continue
            
            check_apt_signatures(url, dist, gpg, errors)

            try:
                release_file = Release(release)
            except Exception as e:
                errors.add(url, dist,
                    f"{release_url} file malformed"
                )
                continue
            
            check_apt_repo_metadata(url, dist, release_file, errors)

            if "Components" not in release_file and "Architectures" not in release_file:
                errors.add(url, dist,
                    f"{release_url} file malformed"
                )
                continue

            components = release_file["Components"].split()
            architectures = release_file["Architectures"].split()

            for comp in components:
                for arch in architectures:
                    try:
                        packages = _packages_file(urljoin(dist_url, comp, f"binary-{arch}"))
                    except HTTPError as e:
                        errors.add(url, dist,
                            f"Could not access Packages file at {e.response.url}: {e}"
                        )
                        continue

                    # count the paragraphs
                    package_count = len(re.findall(r"^Package: ", packages, re.MULTILINE))
                    click.echo(f"Checking {dist}/{comp}/{arch}. Found {package_count} package(s).")

                    package_num = 0
                    with click.progressbar(
                        Packages.iter_paragraphs(packages, use_apt_pkg=False),
                        label="Checking packages(s)",
                        length=package_count,
                    ) as bar:
                        for package in bar:
                            checksums = set(CHECKSUMS.keys()) & set(package.keys())
                            checksum_types = {key: CHECKSUMS[key] for key in checksums}
                            multihash = MultiHash(list(checksum_types.values()))

                            if "Filename" not in package:
                                file_url = urljoin(dist_url, comp, f"binary-{arch}", "Packages")
                                errors.add(url, dist,
                                    f"{file_url} file has a malformed package entry for package #{package_num}"
                                )
                                continue

                            file_url = urljoin(url, package["Filename"])

                            try:
                                response = get_url(f"{file_url}", stream=True)
                            except HTTPError as e:
                                errors.add(url, dist,
                                    f"Could not access package at {e.response.url}: {e}"
                                )
                                continue

                            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                                multihash.update(chunk)

                            for key, alg in checksum_types.items():
                                if multihash.hexdigest(alg) != package[key]:
                                    errors.add(url, dist,
                                        f"Package {key} checksum mismatch for '{package['Filename']}'. "
                                        f"Expected '{package[key]}' but received "
                                        f"'{multihash.hexdigest(alg)}'."
                                    )
                            proc_packages += 1
                            package_num += 1
        except HTTPError as e:
            errors.add(url, dist,
                f"Error when attempting to access {e.response.url}: {e}", err=True
            )
        except Exception as e:
            errors.add(url, dist, f"Unknown error occured: {e}")
        except KeyboardInterrupt:
            package_output(proc_packages)
            raise

    package_output(proc_packages)
