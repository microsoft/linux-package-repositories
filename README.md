# Microsoft Linux Package Repositories

## Overview 

The Microsoft Linux Package Repositories are hosted on PMC ([packages.microsoft.com](https://packages.microsoft.com)) service. The PMC service is intended to support package hosting for customers with clients running a distribution of Linux. Microsoft builds and supports a variety of software products for Linux systems and makes them available via standard APT and YUM package repositories.  

## Configuring the repository on your Linux system 

See how to [host/install/upgrade](https://docs.microsoft.com/en-us/windows-server/administration/linux-package-repository-for-microsoft-software) Microsoft's Linux software using your distribution's standard package management tools.  

Microsoft's Linux Software Repository is comprised of multiple repositories: 

**prods** – These Production repositories (e.g. Ubuntu, Fedora, RHEL, etc.) are designated for packages intended to be used in production. These packages are commercially supported by Microsoft under the terms of the applicable support agreement or program that you have with Microsoft. The prod repositories can be located via hierarchical folder structure (e.g. https://packages.microsoft.com/fedora/36/prod/).

**mssql-server** – These repositories contain packages for Microsoft SQL Server on Linux - See also: [SQL Server on Linux.](https://docs.microsoft.com/en-us/sql/linux/sql-server-linux-overview) 

*Note*: Packages in the Linux software repositories are subject to the license terms located in the packages. Please read the license terms prior to using the package. Your installation and use of the package constitutes your acceptance of these terms. If you do not agree with the license terms, do not use the package. 

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
