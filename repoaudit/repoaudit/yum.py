import xml.etree.ElementTree as ET
import zlib
from typing import List

import click
from requests.exceptions import HTTPError

from .utils import MultiHash, ParseError, get_url, output_result, urljoin

NS = {
    "common": "http://linux.duke.edu/metadata/common",
    "repo": "http://linux.duke.edu/metadata/repo",
    "rpm": "http://linux.duke.edu/metadata/rpm",
}
CHUNK_SIZE = 2 * 1024 * 1024

def check_yum_repo_metadata(url: str, repomd : ET, errors : List[str]):
    repomd_url = urljoin(url, "/repodata/repomd.xml")

    for child in repomd:
        if "type" in child.attrib:
            data_type = child.attrib["type"]

            file_location_info = repomd.find(f"repo:data[@type='{data_type}']/repo:location", namespaces=NS)
            file_checksum_info = repomd.find(f"repo:data[@type='{data_type}']/repo:checksum", namespaces=NS)
            if file_location_info is None or file_checksum_info is None:
                errors.append(
                    f"{repomd_url} file malformed"
                )
                click.echo("Metadata check failed")
                raise ParseError
            
            file_loc = file_location_info.get("href")
            checksum_type = file_checksum_info.get("type")

            if file_loc is None or checksum_type is None:
                errors.append(
                    f"{repomd_url} file malformed"
                )
                click.echo("Metadata check failed")
                raise ParseError

            file_url = urljoin(url, file_loc)
            
            if checksum_type == "sha":
                    checksum_type = "sha1"
            multihash = MultiHash([checksum_type])

            ref_checksum = file_checksum_info.text

            try:
                response = get_url(f"{file_url}", stream=True)
            except HTTPError as e:
                errors.append(f"Could not access file at {e.response.url}: {e}")
                continue
            
            
            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                    multihash.update(chunk)

            if multihash.hexdigest(checksum_type) != ref_checksum:
                errors.append(
                    f"{checksum_type} checksum mismatch for '{file_url}'. Expected "
                    f"'{ref_checksum}' but received '{multihash.hexdigest(checksum_type)}'."
                )
    
    if errors:
        click.echo("Metadata check failed")
    else:
        click.echo("Metadata check successful")

def check_yum_repo(url: str) -> bool:
    """Validate a yum repo at url."""
    click.echo(f"Validating yum repo at {url}...")
    errors = []
    proc_packages = 0

    try:
        repomd_url = urljoin(url, "/repodata/repomd.xml")
        response = get_url(repomd_url)

        try:
            repomd = ET.fromstring(response.text)
        except:
            errors.append(
                f"{repomd_url} file malformed"
            )
            raise ParseError

        check_yum_repo_metadata(url, repomd, errors)

        primary_loc = repomd.find("repo:data[@type='primary']/repo:location", namespaces=NS)
        if primary_loc is None:
            errors.append(
                f"{repomd_url} file malformed"
            )
            raise ParseError

        primary_file = primary_loc.get("href")

        if primary_file is None:
            errors.append(
                f"{repomd_url} file malformed"
            )
            raise ParseError

        primary_url = urljoin(url, primary_file)

        response = get_url(primary_url)
        primary_xml = zlib.decompress(response.content, 16 + zlib.MAX_WBITS)

        try:
            primary = ET.fromstring(primary_xml)
        except:
            errors.append(
                f"{primary_url} file malformed"
            )
            raise ParseError

        packages = primary.findall("common:package", namespaces=NS)
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
                    errors.append(
                        f"{primary_url} file malformed"
                    )
                    continue

                package_url = urljoin(url, location)
                digest = checksum.text

                checksum_type = checksum.get("type")
                if checksum_type is None:
                    errors.append(
                        f"{primary_url} file malformed"
                    )
                    continue

                if checksum_type == "sha":
                    checksum_type = "sha1"
                multihash = MultiHash([checksum_type])

                try:
                    response = get_url(f"{package_url}", stream=True)
                except HTTPError as e:
                    errors.append(f"Could not access package at {e.response.url}: {e}")
                    continue

                for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                    multihash.update(chunk)

                if multihash.hexdigest(checksum_type) != digest:
                    errors.append(
                        f"{checksum_type} checksum mismatch for '{package_url}'. Expected "
                        f"'{digest}' but received '{multihash.hexdigest(checksum_type)}'."
                    )
                proc_packages += 1
    except HTTPError as e:
        click.echo(f"Error when attempting to access {e.response.url}: {e}", err=True)
        return False
    except ParseError:
        output_result(proc_packages, errors)
        return False
    except Exception:
        errors.append(
            "Unknown error in repository"
        )
        output_result(proc_packages, errors)
        return False
    except KeyboardInterrupt:
        output_result(proc_packages, errors)
        raise

    return output_result(proc_packages, errors)
