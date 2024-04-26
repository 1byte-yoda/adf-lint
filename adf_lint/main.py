from pathlib import Path

import click

from adf_lint.adf_linter import ADFLintChecker


@click.group()
def cli():
    pass


@cli.command(name="lint")
@click.option("--arm_template", type=click.Path(exists=True), help="The ARM Template JSON File Path of Azure Data Factory")
@click.option("--verbose", type=click.INT, help="Verbose (1) or Non-Verbose (0)", default=1)
@click.option("--assertion", type=click.STRING, help="Assertion (y) or Ignore (n)", default="y")
def lint(arm_template: str, verbose: bool, assertion: str):
    ignore_assertion = assertion == "n"
    lint_checker = ADFLintChecker(verbose=verbose, ignore_assertion=ignore_assertion)
    lint_checker.main(path=arm_template)


@cli.command(name="list_check_names")
def list_check_names():
    for check_name in ADFLintChecker.get_check_names():
        print(check_name)


if __name__ == '__main__':
    cli()
