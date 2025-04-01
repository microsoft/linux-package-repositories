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

## Signature Verification
In general in rpm-based distributions it is common to sign the individual rpms but not the repository metadata, and in deb-based distributions it is common to sign the repository metadata but not the individual debs.
Microsoft signs **both** the individual packages and the repository metadata for both types of distributions.
The public keys used for verifying Microsoft signatures can be found at [/keys/](https://packages.microsoft.com/keys/).

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
