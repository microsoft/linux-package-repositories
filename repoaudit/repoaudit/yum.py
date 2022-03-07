import xml.etree.ElementTree as ET
import zlib

import click
from requests.exceptions import HTTPError

from .utils import MultiHash, get_url, output_result, urljoin

NS = {
    "common": "http://linux.duke.edu/metadata/common",
    "repo": "http://linux.duke.edu/metadata/repo",
    "rpm": "http://linux.duke.edu/metadata/rpm",
}
CHUNK_SIZE = 2 * 1024 * 1024


def check_yum_repo(url: str) -> bool:
    """Validate a yum repo at url."""
    click.echo(f"Validating yum repo at {url}...")
    errors = []
    proc_packages = 0

    try:
        response = get_url(urljoin(url, "/repodata/repomd.xml"))
        repomd = ET.fromstring(response.text)
        primary_loc = repomd.find("repo:data[@type='primary']/repo:location", namespaces=NS)
        primary_url = urljoin(url, primary_loc.get("href"))

        response = get_url(primary_url)
        primary_xml = zlib.decompress(response.content, 16 + zlib.MAX_WBITS)
        primary = ET.fromstring(primary_xml)

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
                package_url = urljoin(url, location)
                digest = checksum.text
                checksum_type = checksum.get("type")

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
    except KeyboardInterrupt:
        output_result(proc_packages, errors)
        raise

    return output_result(proc_packages, errors)
