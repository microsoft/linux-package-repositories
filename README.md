# Microsoft Linux Package Repositories

> [!IMPORTANT]
> As of October 17, 2024, packages.microsoft.com has dropped all support for mariner 1.0 packages at the request of the Azure Linux (CBL-Mariner) team.
> This entailed the deletion of all `cbl-mariner-1.0-.*` repositories along with their associated distribution endpoints.
> Any 1.0 packages were EOL over a year ago, with support from the Mariner team ending shortly after.
> If you have any issues pertaining 1.0 packages, please [report an issue](#report-an-issue) to the Azure Linux GitHub repo show below.

## Overview 

The Microsoft Linux Package Repositories are hosted on PMC ([packages.microsoft.com](https://packages.microsoft.com)) service. The PMC service is intended to support package hosting for customers with clients running a distribution of Linux. Microsoft builds and supports a variety of software products for Linux systems and makes them available via standard APT and YUM package repositories.  

## Report an issue

The package.microsoft.com team (PMC) maintains the infrastructure and metadata at
packages.microsoft.com.
Issues reported against this repo should involve problems downloading packages such as network
connection errors, unexpected http response codes, etc.
If you are having trouble installing or using a packaging due to missing dependencies, etc. we
recommend contacting the team that maintains the software.
Here is a list of some teams along with their issue trackers:

| Team | Issue tracker |
| -------- | ------- |
| Azure Linux (CBL-Mariner) | https://github.com/microsoft/azurelinux/issues |
| dotnet  | https://github.com/dotnet/sdk/issues |
| Microsoft Defender (mdtap) | https://github.com/microsoft/mdatp-xplat/issues |
| Open Management Infrastructure (omi) | https://github.com/microsoft/omi/issues |
| PowerShell | https://github.com/PowerShell/PowerShell/issues |
| Visual Studio Code | https://github.com/microsoft/vscode/issues |
| Blobfuse/azcopy | https://github.com/Azure/azure-storage-fuse/issues |
| SysmonForLinux | https://github.com/microsoft/SysmonForLinux/issues |

## Rate limiting

Requests to packages.microsoft.com are limited to 4,000 requests per 5 minutes.
Triggering our rate limiting rule will result in 429 responses being returned.
If you run into issues with rate limiting, you can report a new issue.

## Configuring the repository on your Linux system 

See how to [host/install/upgrade](https://docs.microsoft.com/en-us/windows-server/administration/linux-package-repository-for-microsoft-software) Microsoft's Linux software using your distribution's standard package management tools.  
In short you may enable Microsoft's Production repository for your distribution / version by installing the `packages-microsoft-prod.[rpm|deb]` package found at the appropriate [/config/](https://packages.microsoft.com/config/) subdirectory, and there may be additional / alternate repositories you can enable by making the `.repo|.list` files available to your package manager.

Microsoft's Linux Software Repository is comprised of multiple repositories: 

* **prod** – These Production repositories (e.g. Ubuntu, Fedora, RHEL, etc.) are designated for packages intended to be used in production.
  These packages are commercially supported by Microsoft under the terms of the applicable support agreement or program that you have with Microsoft.
  The prod repositories can be located via hierarchical folder structure (e.g. https://packages.microsoft.com/fedora/36/prod/).

* **insiders-fast/insiders-slow** – These repositories provide a way to preview upcoming features for software released into the Production repos.
  Packages generally flow from `insiders-fast` -> `insiders-slow` -> `prod`, but note that some software in the prod repos may not use these repos, and not all versions released here will be promoted to the next stage.
  _NOTE: Not intended for production use._

* **product-specific** – These repositories contain packages for specific products, for example [Microsoft SQL Server on Linux.](https://docs.microsoft.com/en-us/sql/linux/sql-server-linux-overview) 
  Consult the product's documentation for installation instructions, as there may be additional setup required.

_Note_: Packages in the Linux software repositories are subject to the license terms located in the packages. Please read the license terms prior to using the package. Your installation and use of the package constitutes your acceptance of these terms. If you do not agree with the license terms, do not use the package. 

## IP Addresses/Service Tags

The packages.microsoft.com infrastructure uses Azure Front Door to serve a majority of its packages.
Microsoft publishes a list of Azure IP Ranges with the Front Door IPs listed under the
`AzureFrontDoor.Frontend` service tag:

<https://www.microsoft.com/en-us/download/details.aspx?id=56519>

SQL packages are served from different regions so depending on your location you will receive
SQL packages from an IP address in one of the following Service Tags:

* AzureCloud.eastasia
* AzureCloud.eastus2
* AzureCloud.northeurope
* AzureCloud.southeastasia
* AzureCloud.westeurope
* AzureCloud.westus2

## Deprecated Support for Legacy Domain Names
Historically,  packages.microsoft.com content was available on a second domain name: apt-mo.trafficmanager.net.
This is a historical artifact from a time when packages.microsoft.com was not yet an official public offering.
In May of 2025, we will be deprecating support for this domain name.
Requests sent to this domain will be redirected to packages.microsoft.com to prevent impact.
But customers using apt-mo are encouraged to update their repo references to prevent any future issues.
This change will bring performance improvements, including better cache efficiency and faster cache purging operations.

## Signature Verification
In general in rpm-based distributions it is common to sign the individual rpms but not the repository metadata, and in deb-based distributions it is common to sign the repository metadata but not the individual debs.
Microsoft signs **both** the individual packages and the repository metadata for both types of distributions.
The public keys used for verifying Microsoft signatures can be found at [/keys/](https://packages.microsoft.com/keys/).
Customers are encouraged to use the configuration packages, located under https://packages.microsoft.com/config/, to ensure they acquire the correct key for a given repository.
 
Microsoft-2025.asc
- Microsoft's latest GPG public key may be downloaded here: [https://packages.microsoft.com/keys/microsoft-2025.asc](https://packages.microsoft.com/keys/microsoft-2025.asc)
- This key is associated with repositories created after April 2025, including RHEL 10, Debian 13, and Ubuntu 25.10
- Public Key ID: Microsoft (Release signing) `Microsoft Corporation - General GPG Signer <gpgsign@microsoft.com>`
- Public Key Fingerprint: `AA86 F75E 427A 19DD 3334 6403 EE4D 7792 F748 182B`
 
Microsoft.asc
- Microsoft's original public GPG key may be downloaded here: [https://packages.microsoft.com/keys/microsoft.asc](https://packages.microsoft.com/keys/microsoft.asc)
- This key is associated with repositories created before May 2025, including RHEL 9, Debian 12, and Ubuntu 25.04
- Public Key ID: Microsoft (Release signing) `gpgsecurity@microsoft.com`
- Public Key Fingerprint: `BC52 8686 B50D 79E3 39D3 721C EB3E 94AD BE12 29CF`

### Enabling Repository Metadata Signature Checking on RPM-Based Systems
Set `repo_gpgcheck=1` in your repo file.

### Verify the Signature of an Individual DEB.
`debsig-verify` can be used to manually check the signature of an individual DEB.
`dpkg-sig` is a competing individual-DEB signing standard with a different internal implementation, and it will not work for verifying Microsoft DEBs.

To use `debsig-verify` you must first create a policy file for it and provide Microsoft's public key.

1. Install `debsig-verify`.  
   ```
   $ sudo apt install debsig-verify
   ```
1. Install the binary formatted (not ascii-armored) version of Microsoft's public key.  
   ```
   $ wget https://packages.microsoft.com/keys/microsoft.asc -O /tmp/microsoft.asc
   $ sudo mkdir -p /usr/share/debsig/keyrings/EB3E94ADBE1229CF/
   $ sudo gpg -o /usr/share/debsig/keyrings/EB3E94ADBE1229CF/microsoft.gpg --dearmor /tmp/microsoft.asc
   ```
1. Create a `debsig-verify` policy file.  
   ```
   $ sudo mkdir -p /etc/debsig/policies/EB3E94ADBE1229CF/
   $ sudo tee /etc/debsig/policies/EB3E94ADBE1229CF/microsoft.pol > /dev/null <<'EOF'
   <?xml version="1.0"?>
   <!DOCTYPE Policy SYSTEM "https://www.debian.org/debsig/1.0/policy.dtd">
   <Policy xmlns="https://www.debian.org/debsig/1.0/">

     <Origin Name="Microsoft" id="EB3E94ADBE1229CF" Description="gpgsecurity@microsoft.com"/>

     <Selection>
       <Required Type="origin" File="microsoft.gpg" id="EB3E94ADBE1229CF"/>
     </Selection>

     <Verification MinOptional="0">
       <Required Type="origin" File="microsoft.gpg" id="EB3E94ADBE1229CF"/>
     </Verification>

   </Policy>
   EOF
   ```
1. You can now verify individual DEBs.
   ```
   $ wget https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
   $ debsig-verify /tmp/packages-microsoft-prod.deb
   debsig: Verified package from 'gpgsecurity@microsoft.com' (Microsoft)
   ```
## Snapshot support [Preview]

Preview support for [repository snapshots](https://packages.microsoft.com/snapshot) is now available on PMC (packages.microsoft.com). With PMC Snapshots, you can explore historical versions of specific Ubuntu repositories. The snapshot feature allows users to view and install packages as they existed at specific points in time, enabling reproducible deployments and helping to identify changes in package behavior over time. By using snapshots, you can recreate environments from any given date and time, which is particularly useful for tracking down when changes or regressions were introduced. Snapshots ensure that a validated environment can be consistently replicated across different stages of development and production, supporting a structured update workflow. This feature is similar to [snapshot.debian.org](https://snapshot.debian.org/) and [snapshot.ubuntu.com](https://snapshot.ubuntu.com/).

### How to create snapshots

Snapshots are created automatically when a repository is updated, provided the previous snapshot is at least 7 days old. Repository administrators can also manually create snapshots as needed.

To access repository snapshots, go to the repository's snapshot path (like `https://packages.microsoft.com/snapshot/ubuntu/24.04/prod/`). Snapshots are identified by a UTC timestamp in their URL, representing the time it was created, such as `https://packages.microsoft.com/snapshot/ubuntu/24.04/prod/20250501T193230Z/` for the 2025-05-01T19:32:30Z UTC state. Snapshots can be accessed using an arbitrary timestamp. When requesting a snapshot with a specific timestamp, if an exact match isn't found, you'll be redirected to the latest snapshot created before that time. Requesting a future or pre-first-snapshot timestamp will return a 404 error.

This feature is **currently in preview and is not recommended for production workloads**. Currently, there is no ETA for moving beyond preview status or for expanding support to additional repositories. For more information, check [Pulp's checkpoint documentation](https://pulpproject.org/pulpcore/docs/user/guides/checkpoint/) and blog [post](https://pulpproject.org/blog/2025/03/11/checkpoint-support---a-journey-towards-predictable-and-consistent-deployments/) which is the basis of the snapshot support in PMC.


## How can we make PMC service work for you? 

[Report an issue](https://github.com/microsoft/linux-package-repositories/issues/new?assignees=&labels=&template=report-an-issue.md&title=Report+an+issue): Help us improve our service by reporting issues you are experiencing 

[Request a feature](https://github.com/microsoft/linux-package-repositories/issues/new?assignees=&labels=enhancement&template=request-a-feature.md): Request a new feature or enhancement 

[Report a security vulnerability](https://github.com/microsoft/linux-package-repositories/security/policy): Please review our security policy for more details 

## Contributing  

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks 

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
