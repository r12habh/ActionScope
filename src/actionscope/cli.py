import click

from actionscope.review import review


@click.group()
@click.version_option(package_name="actionscope")
def main():
    """Ask a local AI model about changes to your coding agent's access."""


main.add_command(review)
