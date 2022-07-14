from pathlib import Path
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element as XMLElement
import zlib
from typing import List, Optional

import click
import gnupg
from requests.exceptions import HTTPError

from .utils import (MultiHash, ParseError, RepoErrors, check_repo_empty,
                    check_signature, destroy_gpg, get_url, initialize_gpg,
                    package_output, urljoin)

NS = {
    "common": "http://linux.duke.edu/metadata/common",
    "repo": "http://linux.duke.edu/metadata/repo",
    "rpm": "http://linux.duke.edu/metadata/rpm",
}
CHUNK_SIZE = 2 * 1024 * 1024


def _check_yum_repo_metadata(url: str, repomd: ET,
                             errors: RepoErrors,
                             verify: Optional[str] = None) -> None:
    """Check repo metadata for checksum mismatches."""

    success = True
    repomd_url = urljoin(url, "/repodata/repomd.xml")

    try:
        for child in repomd:
            if "type" in child.attrib:
                data_type = child.attrib["type"]

                file_location_info = repomd.find(f"repo:data[@type='{data_type}']/repo:location",
                                                 namespaces=NS)
                file_checksum_info = repomd.find(f"repo:data[@type='{data_type}']/repo:checksum",
                                                 namespaces=NS)

                if file_location_info is None or file_checksum_info is None:
                    errors.add(
                        url, RepoErrors.YUM_DIST,
                        f"{repomd_url} file malformed, "
                        f"no location or checksum found for {data_type}"
                    )
                    raise ParseError

                file_loc = file_location_info.get("href")
                checksum_type = file_checksum_info.get("type")

                if file_loc is None or checksum_type is None:
                    errors.add(
                        url, RepoErrors.YUM_DIST,
                        f"{repomd_url} file malformed"
                        f"no href or type for {data_type}"
                    )
                    raise ParseError

                file_url = urljoin(url, file_loc)

                if checksum_type == "sha":
                    checksum_type = "sha1"
                multihash = MultiHash([checksum_type])

                ref_checksum = file_checksum_info.text

                try:
                    response = get_url(f"{file_url}", verify=verify, stream=True)
                except HTTPError as e:
                    errors.add(
                        url, RepoErrors.YUM_DIST,
                        f"Could not access file at {e.response.url}: {e}"
                    )
                    success = False
                    continue

                for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                    multihash.update(chunk)

                if multihash.hexdigest(checksum_type) != ref_checksum:
                    errors.add(
                        url, RepoErrors.YUM_DIST,
                        f"Metadata {checksum_type} checksum mismatch for '{file_url}'. Expected "
                        f"'{ref_checksum}' but received '{multihash.hexdigest(checksum_type)}'."
                    )
                    success = False
    except ParseError:
        success = False

    if success:
        click.echo("Metadata check successful")
    else:
        click.echo("Metadata check failed")


def _check_yum_signature(url: str, gpg: Optional[gnupg.GPG],
                         errors: RepoErrors, verify: Optional[str] = None) -> None:
    """Verify signature using provided public keys in gpg parameter."""
    if gpg is None:
        return

    repomd_url = urljoin(url, "/repodata/repomd.xml")
    repomdsig_url = urljoin(url, "/repodata/repomd.xml.asc")

    success = check_signature(url, RepoErrors.YUM_DIST, repomd_url, gpg, errors,
                              signature_url=repomdsig_url, verify=verify)

    if "suse" in url or "sles" in url:
        repomdkey_url = urljoin(url, "/repodata/repomd.xml.key")

        gpg_temp = None
        try:
            gpg_temp = initialize_gpg(
                [repomdkey_url],
                home_dir=Path(gpg.gnupghome) / "temporary_gpg_susesles",
                verify=verify
            )
        except HTTPError as e:
            errors.add(
                url, RepoErrors.YUM_DIST,
                f"While checking signatures, "
                f"key file {repomdkey_url} does not exist for SUSE repo: {e}"
            )
            success = False
        else:
            success = (
                success and
                check_signature(url, RepoErrors.YUM_DIST, repomd_url,
                                gpg_temp, errors, signature_url=repomdsig_url, verify=verify)
            )
        finally:
            destroy_gpg(gpg_temp, keep_folder=True)

    if success:
        click.echo("Signature check successful")
    else:
        click.echo("Signature check failed")


def _check_yum_packages(repo: str, packages: List[XMLElement], primary_url: str,
                        errors: RepoErrors, verify: Optional[str] = None) -> None:
    """Verifies the checksums for yum packages"""
    proc_packages = 0

    try:
        package_count = len(packages)
        click.echo(f"Found {package_count} packages.")

        with click.progressbar(
            packages,
            label="Checking package(s)",
        ) as bar:
            for package in bar:
                location = package.find("common:location", namespaces=NS).get("href")
                checksum = package.find("common:checksum", namespaces=NS)
                if location is None or checksum is None:
                    errors.add(
                        repo, RepoErrors.YUM_DIST,
                        f"{primary_url} file malformed, "
                        "location or checksum not found for a package."
                    )
                    continue

                package_url = urljoin(repo, location)
                digest = checksum.text

                checksum_type = checksum.get("type")
                if checksum_type is None:
                    errors.add(
                        repo, RepoErrors.YUM_DIST,
                        f"{primary_url} file malformed, "
                        "checksum entry has no type"
                    )
                    continue

                if checksum_type == "sha":
                    checksum_type = "sha1"
                multihash = MultiHash([checksum_type])
                try:
                    response = get_url(f"{package_url}", verify=verify, stream=True)
                except HTTPError as e:
                    errors.add(
                        repo, RepoErrors.YUM_DIST,
                        f"Could not access package at {e.response.url}: {e}"
                    )
                    continue
                for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                    multihash.update(chunk)

                if multihash.hexdigest(checksum_type) != digest:
                    errors.add(
                        repo, RepoErrors.YUM_DIST,
                        f"Package {checksum_type} checksum mismatch "
                        f"for '{package_url}'. Expected "
                        f"'{digest}' but received '{multihash.hexdigest(checksum_type)}'."
                    )
                proc_packages += 1
    except KeyboardInterrupt:
        package_output(proc_packages)
        raise

    package_output(proc_packages)


def check_yum_repo(url: str, gpg: Optional[gnupg.GPG],
                   errors: RepoErrors, verify: Optional[str] = None) -> None:
    """Validate a yum repo at url."""
    click.echo(f"Validating yum repo at {url}...")
    errors.add(url, None, None)  # add empty entry with no errors

    try:
        if check_repo_empty(url, verify=verify):
            click.echo("Repository empty")
            return

        errors.add(url, RepoErrors.YUM_DIST, None)

        _check_yum_signature(url, gpg, errors, verify=verify)

        repomd_url = urljoin(url, "/repodata/repomd.xml")
        # if this errors it's caught by the except below
        response = get_url(repomd_url, verify=verify)

        try:
            repomd = ET.fromstring(response.text)
        except Exception:
            errors.add(
                url, RepoErrors.YUM_DIST,
                f"{repomd_url} file malformed, "
                "cannot parse as an xml"
            )
            raise ParseError

        _check_yum_repo_metadata(url, repomd, errors, verify=verify)

        primary_loc = repomd.find("repo:data[@type='primary']/repo:location", namespaces=NS)
        if primary_loc is None:
            errors.add(
                url, RepoErrors.YUM_DIST,
                f"{repomd_url} file malformed"
                "primary entry does not exist"
            )
            raise ParseError

        primary_file = primary_loc.get("href")

        if primary_file is None:
            errors.add(
                url, RepoErrors.YUM_DIST,
                f"{repomd_url} file malformed, "
                "primary entry has no href"
            )
            raise ParseError

        primary_url = urljoin(url, primary_file)

        # if this errors it's caught by the except below
        response = get_url(primary_url, verify=verify)
        primary_xml = zlib.decompress(response.content, 16 + zlib.MAX_WBITS)

        try:
            primary = ET.fromstring(primary_xml)
        except Exception:
            errors.add(
                url, RepoErrors.YUM_DIST,
                f"{primary_url} file malformed, "
                "cannot parse as an xml"
            )
            raise ParseError

        packages = primary.findall("common:package", namespaces=NS)
        _check_yum_packages(url, packages, primary_url, errors, verify=verify)

    except HTTPError as e:
        errors.add(
            url, RepoErrors.YUM_DIST,
            f"Error when attempting to access {e.response.url}: {e}"
        )
    except ParseError:
        click.echo("Parsing error")
        pass
