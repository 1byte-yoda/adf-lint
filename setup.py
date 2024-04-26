import os

from setuptools import setup, find_packages
from datetime import datetime


def get_requirements() -> list[str]:
    with open("requirements.txt", "r") as f:
        return f.readlines()


def get_calendar_version() -> str:
    now = datetime.now()
    build_id = os.getenv("BUILD_BUILDID", "1")
    return f"{now.year}.{now.month:02d}.{now.day:02d}.{build_id}"


setup(
    name="adf-lint",
    version=get_calendar_version(),
    packages=find_packages(),
    include_package_data=True,
    install_requires=get_requirements(),
    description="This project was developed to scan ADF (Azure Data Factory) for any lints that are useful to maintain a Secured, Performant, and Maintainable Pipelines",
    entry_points="""
        [console_scripts]
        adf_checker=adf_lint.main:cli
    """,
)