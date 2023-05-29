import json
import os
from configparser import ConfigParser, NoOptionError, NoSectionError
from http import HTTPStatus

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


def delete_all_objects_from_s3_folder(bucket_name: str, boto_client) -> None:
    """
    Deletes all files in a folder of an S3 bucket

    Args:
        bucket_name: The bucket name
        boto_client: AWS S3 client
    """
    try:
        objects = boto_client.list_objects_v2(Bucket=bucket_name)
    except boto_client.exceptions.NoSuchBucket:
        LOGGER.warning(f"{bucket_name} not found")
        return

    #  Sometimes there maybe no contents -- no objects
    files_in_folder = objects.get("Contents")
    if not files_in_folder:
        LOGGER.info(f"No objects to be deleted for {bucket_name}")
        return

    files_to_delete = [{"Key": file["Key"]} for file in files_in_folder]
    delete_response = boto_client.delete_objects(
        Bucket=bucket_name,
        Delete={"Objects": files_to_delete, "Quiet": True},
    )

    delete_response_http_status_code = delete_response["ResponseMetadata"][
        "HTTPStatusCode"
    ]
    if delete_response_http_status_code == HTTPStatus.OK:
        LOGGER.info("Objects deleted successfully")
        return
    else:
        LOGGER.error(
            "Objects not deleted:\n:"
            f"{json.dumps(delete_response, default=str, indent=4)}",
        )


def delete_bucket(bucket_name: str, boto_client) -> None:
    """
    Delete velero bucket

    Args:
        bucket_name: the bucket name
        boto_client: AWS client
    """
    LOGGER.info(f"Delete bucket {bucket_name}")
    try:
        response = boto_client.delete_bucket(Bucket=bucket_name)
    except boto_client.exceptions.NoSuchBucket:
        LOGGER.warning(f"{bucket_name} not found")
        return

    response_http_status_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if response_http_status_code == HTTPStatus.NO_CONTENT:
        LOGGER.info(f"Cluster bucket '{bucket_name}' deleted successfully")
        return

    elif response_http_status_code == HTTPStatus.NOT_FOUND:
        LOGGER.info(f"Bucket '{bucket_name}' not found")
        return

    LOGGER.error(
        f"Bucket {bucket_name} not deleted",
        json.dumps(response, defualt=str, indent=4),
    )
