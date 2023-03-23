import os
import sys

from ocp_utilities.logger import get_logger

LOGGER = get_logger(__name__)


def verify_aws_env_requirements_met() -> None:

    """
    Verify that the AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_REGION are set.
    The script exits if neither is set.

    Returns: None
    """
    require_env = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"]
    env_not_found = []
    for env_var in require_env:
        if not os.getenv(env_var):
            env_not_found.append(env_var)

    if env_not_found:
        LOGGER.error(
            f"Environment Variables {env_not_found} Not Set!!! :\n"
            "Below are the required environment variables:\n\t"
            f" {require_env}",
        )
        sys.exit(1)
