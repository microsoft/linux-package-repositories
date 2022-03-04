# repoaudit

A tool for validating apt and yum repositories.

## Installation

TBD

### Development

```
cd repoaudit
pip install -e .
```

## Usage

To get a list of commands and options:

```
repoaudit --help
```

### Examples

```
# validate all distros of azure-cli apt repo
repoaudit apt https://packages.microsoft.com/repos/azure-cli/

# validate only focal and bionic distros of azure-cli apt repo
repoaudit apt --dist focal --dist bionic https://packages.microsoft.com/repos/azure-cli/

# validate azurecore repo
repoaudit yum https://packages.microsoft.com/yumrepos/azurecore/

# validate all nested yumrepos
repoaudit yum -r https://packages.microsoft.com/yumrepos/
```
