import os
from configparser import ConfigParser

from aws.logger import get_logger

LOGGER = get_logger(name=__name__)


class AWSConfigurationError(Exception):
    pass


def verify_existing_config_in_env_vars_or_file(vars_list, file_path, section):
    """
    Verify vars are either set as environment variables or in a config file.

    Args:
        vars_list (list): A list of variable names
        file_path (str): Absolute path to config file
        section (str): Section name in config file

    Returns:

    """
    missing_vars = []
    parser = ConfigParser()
    parser.read(file_path)
    for var in vars_list:
        if not os.getenv(var.upper()):
            LOGGER.info(f"Variable {var} is not set as environment variables, checking in config file.")
            if section not in parser.sections():
                LOGGER.error(f"Could not find section {section} in {file_path}")
                raise ValueError
            if not parser[section].get(var.lower()):
                missing_vars.append(var)
    if missing_vars:
        LOGGER.error(
            f"Missing configuration: {','.join(missing_vars)}. "
            f"Values should be set in environment variables or in {file_path}"
        )
        raise AWSConfigurationError()


def verify_aws_configuration():
    verify_existing_config_in_env_vars_or_file(
        vars_list=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
        file_path=os.path.expanduser("~/.aws/credentials"),
        section="default",
    )


def verify_aws_config():
    verify_existing_config_in_env_vars_or_file(
            vars_list=["AWS_REGION"],
            file_path=os.path.expanduser("~/.aws/config"),
            section="default",
    )
