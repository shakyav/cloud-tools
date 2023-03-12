"""
The main purpose of this script is to delete a bucket associated with a cluster
after the cluster is uninstalled:
-   The script will delete the velero bucket that is mapped to a cluster.

Required (environment Variable):
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY

Usage:
1. The module can be imported and used like below :

    import delete_s3_velero_bucket

    delete_s3_bucket.delete_velero_cluster_buckets(cluster)
    -   cluster: the name of the cluster

2.  python delete_s3_velero_bucket.py -c|--cluster <cluster_name>

    example:
    1. python delete_s3_velero_bucket.py -c mts-rhods-c1
    2. python delete_s3_velero_bucket.py --cluster mts-rhoam-c2

"""
import argparse
import json
import os
import re
import sys
import logging

from http import HTTPStatus
from typing import Union

import boto3

LOGGER = logging.getLogger(__name__)
S3_CLIENT = boto3.client("s3")
REQUIRE_ENV = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]


class DeleteBucketError(Exception):
    """Raise when a bucket is not deleted"""


class DeleteFolderObjectError(Exception):
    """Raise when a bucket folder is not deleted"""


def delete_velero_cluster_buckets(cluster) -> None:
    """
    Delete the velero bucket associated with a cluster

    Args:
        cluster: The cluster name

    """

    LOGGER.info(f"Delete velero buckets for '{cluster}' cluster")

    velero_bucket_list = get_velero_buckets()
    if not velero_bucket_list:
        LOGGER.info("No velero buckets found")
        return

    for bucket in velero_bucket_list:
        if verify_cluster_matches_velero_infrastructure_name(
                cluster_name=cluster,
                bucket_name=bucket["Name"],
        ):
            delete_all_objects_from_s3_folder(
                bucket_name=bucket["Name"],
            )

            delete_bucket(bucket_name=bucket["Name"])
            # A cluster is mapped to only one bucket, so don't check any remaining buckets
            return

    LOGGER.info("No buckets deleted")


def delete_bucket(bucket_name: str) -> None:
    """
    Delete velero bucket

    Args:
        bucket_name: the bucket name

    Raises:
        DeleteBucketError: if delete response status code is not HTTPStatus.NO_CONTENT or HTTPStatus.NOT_FOUND
    """
    LOGGER.info(f"Delete cluster bucket {bucket_name}")
    response = S3_CLIENT.delete_bucket(Bucket=bucket_name)

    response_http_status_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if response_http_status_code == HTTPStatus.NO_CONTENT:
        LOGGER.info(f"Cluster bucket '{bucket_name}' deleted successfully")
        return

    elif response_http_status_code == HTTPStatus.NOT_FOUND:
        LOGGER.info(f"Bucket '{bucket_name}' not found\n")
        return

    LOGGER.error(
        f"Bucket {bucket_name} not deleted",
        json.dumps(response, defualt=str, indent=4),
    )

    raise DeleteBucketError(
        f'Bucket Deletion Error: Expecting {HTTPStatus.NO_CONTENT} or {HTTPStatus.NOT_FOUND} Status code:"'
        f"but got {response_http_status_code}",
    )


def get_velero_buckets() -> list:
    """
    Get a list of velero buckets

    Returns:
        list of velero buckets
    """
    LOGGER.info("Get a list of velero buckets")

    buckets = S3_CLIENT.list_buckets()["Buckets"]
    return [
        bucket
        for bucket in buckets
        if re.search("managed-velero-backups-", bucket["Name"])
    ]


def get_velero_infrastructure_name(bucket_name: str) -> Union[str, None]:
    """
    Get the velero bucket infrastructure name

    Args:
        bucket_name: The name of the cluster bucket to delete

    Returns:
        velero infrastructure name or None
    """

    LOGGER.info(f"Get tags for bucket: {bucket_name}")
    bucket_tags = S3_CLIENT.get_bucket_tagging(Bucket=bucket_name)["TagSet"]

    for tag in bucket_tags:
        if tag["Key"] == "velero.io/infrastructureName":
            return tag["Value"]


def verify_cluster_matches_velero_infrastructure_name(
        cluster_name: str,
        bucket_name: str,
) -> bool:
    """
    Get the velero bucket infrastructure name and compare it with the cluster

    Args:
        cluster_name: The cluster name
        bucket_name: The bucket name

    Returns:
        True if the cluster matches a velero infrastructure name, False otherwise
    """

    LOGGER.info(
        f"Verify cluster matches a velero infrastructure name via its bucket tag: {bucket_name}",
    )

    velero_infrastructure_name = get_velero_infrastructure_name(bucket_name=bucket_name)

    # Verify if the bucket is associated with the cluster
    if velero_infrastructure_name and re.search(
            rf"{cluster_name}(-\w+)?$",
            velero_infrastructure_name,
    ):
        LOGGER.info(
            f"Verified cluster '{cluster_name}' is associated with velero infrastructure name {velero_infrastructure_name}",
        )
        return True

    return False


def delete_all_objects_from_s3_folder(bucket_name: str) -> None:
    """
    Deletes all files in a folder of an S3 bucket

    Args:
        bucket_name: The bucket name


    Raises:
        DeleteFolderObjectError: if respone status code is not HTTPStatus.OK
    """

    list_obj_response = S3_CLIENT.list_objects_v2(Bucket=bucket_name)

    #  Sometimes there maybe no contents -- no objects
    files_in_folder = list_obj_response.get("Contents")
    if not files_in_folder:
        LOGGER.info(f"No objects to be deleted for {bucket_name}")
        return

    files_to_delete = [{"Key": file["Key"]} for file in files_in_folder]
    delete_response = S3_CLIENT.delete_objects(
        Bucket=bucket_name,
        Delete={"Objects": files_to_delete, "Quiet": True},
    )

    delete_response_http_status_code = delete_response["ResponseMetadata"][
        "HTTPStatusCode"
    ]
    if delete_response_http_status_code == HTTPStatus.OK:
        LOGGER.info(f"Objects deleted successfully")
        return
    else:
        LOGGER.error(
            "Objects not deleted:\n:"
            f"{json.dumps(delete_response, default=str, indent=4)}",
        )

        raise DeleteFolderObjectError(
            f'Folder Object Deletion Error: Expecting a {HTTPStatus.OK} Status code:"'
            f"but got {delete_response_http_status_code}",
        )


def get_cluster_name() -> str:
    """
    Get the cluster name passed to the script

    The cluster name can be passed as a command line argument or an environment variable.
    The script exits if the cluster name is not provided

    Returns:
        The name of the cluster
    """
    parser = argparse.ArgumentParser(description="Delete an s3 velero cluster bucket")
    parser.add_argument(
        "-c",
        "--cluster_name",
        help=""" Either set the S3_CLUSTER environment variable or
            Pass the cluster value at the command line when the script is invoked with the -c|--cluster
        """,
    )

    cluster_name = parser.parse_args().cluster_name
    if cluster_name:
        return cluster_name

    LOGGER.error("Required cluster value was not set! Run script with --help for specifics")
    sys.exit(1)


def verify_env_variables_and_parameters():
    """
    Verify that the AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY are cluster name are set.
    The script exits if neither is set.

    Returns:
         cluster name
    """
    found_env = []
    for env_var in REQUIRE_ENV:
        if os.getenv(env_var):
            found_env.append(env_var)
    parser = argparse.ArgumentParser(description="Delete an s3 velero cluster bucket")
    parser.add_argument(
        "-c",
        "--cluster_name",
        help=""" Either set the S3_CLUSTER environment variable or
                Pass the cluster value at the command line when the script is invoked with the -c|--cluster
            """,
    )
    cluster_name = parser.parse_args().cluster_name
    if len(found_env) < len(REQUIRE_ENV):
        LOGGER.error(f"Missing environment variable found: {found_env}, require:{REQUIRE_ENV}")
        sys.exit(1)
    if not cluster_name:
        LOGGER.error("Missing cluster name")
        sys.exit(1)
    return cluster_name


def main():
    delete_velero_cluster_buckets(cluster=verify_env_variables_and_parameters())


if __name__ == "__main__":
    main()
