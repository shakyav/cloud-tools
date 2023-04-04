import os
from configparser import ConfigParser, NoOptionError, NoSectionError

from simple_logger.logger import get_logger

LOGGER = get_logger(name=__name__)


class AWSConfigurationError(Exception):
    pass


def verify_existing_config_in_env_vars_or_file(vars_list, file_path, section="default"):
    """
    Verify vars are either set as environment variables or in a config file.

    Args:
        vars_list (list): A list of variable names
        file_path (str): Absolute path to config file
        section (str): Section name in config file

    Raises:
        AWSConfigurationError: raises on missing configuration
    """
    missing_vars = []
    parser = ConfigParser()
    parser.read(file_path)
    aws_region_str = "region"
    for var in vars_list:
        if os.getenv(var.upper()):
            continue
        LOGGER.info(
            f"Variable {var} is not set as environment variables, checking in config file."
        )
        try:
            var = var.lower()
            # `AWS_REGION` environment variable is set as `region` in the config file
            if aws_region_str in var:
                var = aws_region_str
            parser.get(section, var)
        except (NoSectionError, NoOptionError):
            missing_vars.append(var)
    if missing_vars:
        LOGGER.error(
            f"Missing configuration: {','.join(missing_vars)}. "
            f"Values should be set in environment variables or in {file_path}"
        )
        raise AWSConfigurationError()


def verify_aws_credentials():
    verify_existing_config_in_env_vars_or_file(
        vars_list=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
        file_path=os.path.expanduser("~/.aws/credentials"),
    )


def verify_aws_config():
    verify_existing_config_in_env_vars_or_file(
        vars_list=["AWS_REGION"],
        file_path=os.path.expanduser("~/.aws/config"),
    )
