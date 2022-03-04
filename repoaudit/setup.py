from pathlib import Path
from setuptools import setup

long_description = (Path(__file__).parent / "README.md").read_text()

setup(
    name="repoaudit",
    python_requires=">=3.8",
    description="CLI to validate yum/apt repositories",
    url="https://github.com/microsoft/linux-package-repositories",
    version="0.0.1",
    license="MIT",
    long_description=long_description,
    long_description_content_type='text/markdown',
    install_requires=[
        "click",
        "python-debian",
    ],
    py_modules=['repoaudit'],
    entry_points={
        'console_scripts': [
            'repoaudit = repoaudit:main',
        ]
    },
)
