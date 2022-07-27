# repoaudit

A tool for validating apt and yum repositories.

## Installation and Usage

To install repoaudit from PyPI:

```
pip install repoaudit
```

Then run:

```
repoaudit --help
```

## Examples

```
# validate all distros of azure-cli apt repo
repoaudit apt https://packages.microsoft.com/repos/azure-cli/

# validate only focal and bionic distros of azure-cli apt repo
repoaudit apt --dists focal,bionic https://packages.microsoft.com/repos/azure-cli/

# validate azurecore repo
repoaudit yum https://packages.microsoft.com/yumrepos/azurecore/

# validate all nested yumrepos
repoaudit yum -r https://packages.microsoft.com/yumrepos/

# validate all nested aptrepos
repoaudit yum -r https://packages.microsoft.com/repos/

# output json results to a file
repoaudit yum -r https://packages.microsoft.com/yumrepos/ -o example_file.json

# check metadata signatures by providing public keys
repoaudit apt https://packages.microsoft.com/repos/cbl-d -p https://packages.microsoft.com/keys/microsoft.asc,https://packages.microsoft.com/keys/msopentech.asc
```

## Development

### Setup

First install poetry per the [installation docs](https://python-poetry.org/docs/#installation).

Then clone the repo, cd into the repoaudit directory, and run `poetry install`.

### Usage

To load the poetry shell and run repoaudit:

```
poetry shell
repoaudit
```

Alternatively you can run:

```
poetry run repoaudit
```

## Releasing

First bump the version in pyproject.toml. Then commit it:

```
git commit -am "0.2.0 Release"
```

Open a PR and get it merged. Then go to
[the Github new release page](https://github.com/microsoft/linux-package-repositories/releases/new)
and create a new release 

Once that's done, pull the tag and use poetry to build it:

```
git pull --tags
git checkout 0.2.0
poetry publish --build
```
