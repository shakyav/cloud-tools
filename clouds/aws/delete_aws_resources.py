import re

import boto3
from simple_logger.logger import get_logger

from clouds.aws.aws_utils import verify_aws_credentials

LOGGER = get_logger(name=__name__)


def aws_region_names():
    regions = boto3.client(service_name="ec2").describe_regions()["Regions"]
    return [region["RegionName"] for region in regions]


def delete_rds_instances(region):
    rds_client = boto3.client(service_name="rds", region_name=region)
    db_instances = rds_client.describe_db_instances()["DBInstances"]
    for db_instance_identifier in db_instances:
        LOGGER.warning(f"DB instance identifier: {db_instance_identifier}")
        # TODO: once we have the contents of db_instance_identifier, update code to delete it
        # aws rds modify-db-instance --no-deletion-protection --db-instance-identifier "${rds}"


def delete_vpc_peering_connections(region):
    ec2_client = boto3.client(service_name="ec2", region_name=region)
    for conn in ec2_client.describe_vpc_peering_connections()["VpcPeeringConnections"]:
        LOGGER.warning(f"VPC peering connection: {conn}")
        # TODO: once we have the contents of conn, update code to delete it
        # aws ec2 delete-vpc-peering-connection --vpc-peering-connection-id "${pc}"


def delete_open_id_connect_provider(iam_client):
    for conn in iam_client.list_open_id_connect_providers()[
        "OpenIDConnectProviderList"
    ]:
        conn_name = conn["Arn"]
        LOGGER.info(f"Delete open id connection provider {conn_name}")
        # iam_client.delete_open_id_connect_provider(OpenIDConnectProviderArn=conn_name)


def delete_instance_profiles(iam_client):
    for profile in iam_client.list_instance_profiles()["InstanceProfiles"]:
        profile_name = profile["InstanceProfileName"]
        for role in iam_client.get_instance_profile(InstanceProfileName=profile_name)[
            "InstanceProfile"
        ]["Roles"]:
            role_name = role["RoleName"]
            LOGGER.info(f"Remove role {role_name} from instance profile {profile_name}")
            # iam_client.remove_role_from_instance_profile(RoleName=role_name)
        LOGGER.info(f"Delete Profile {profile_name}")
        # iam_client.delete_instance_profile(InstanceProfileName=profile_name)


def delete_roles(iam_client):
    for role in iam_client.list_roles()["Roles"]:
        role_name = role["RoleName"]
        if not re.search(r"ManagedOpenShift|AWSServiceRole|AWS-QuickSetup", role_name):
            for policy in iam_client.list_attached_role_policies(RoleName=role_name)[
                "AttachedPolicies"
            ]:
                policy_name = policy["PolicyName"]
                LOGGER.info(f"Detach policy {policy_name} for role {role_name}")
                # iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy["PolicyArn"])
            LOGGER.info(f"Delete role {role_name}")
            # iam_client.delete_role(RoleName=role_name)


def delete_buckets(region):
    s3_client = boto3.client(service_name="s3", region_name=region)
    for bucket in s3_client.list_buckets()["Buckets"]:
        pass
        # delete_all_objects_from_s3_folder(bucket_name=bucket["Name"], boto_client=s3_client)
        # delete_bucket(bucket_name=bucket["Name"], boto_client=s3_client)


def main():
    verify_aws_credentials()

    for region in aws_region_names():
        iam_client = boto3.client(service_name="iam", region_name=region)
        LOGGER.info(f"Deleting resources in region {region}")
        delete_rds_instances(region=region)
        delete_vpc_peering_connections(region=region)
        delete_open_id_connect_provider(iam_client=iam_client)
        delete_instance_profiles(iam_client=iam_client)
        delete_roles(iam_client=iam_client)
        # run_command(
        #     command=shlex.split(
        #         f"cloud-nuke aws --region {region} --force"
        #     )
        # )
        delete_buckets(region=region)


if __name__ == "__main__":
    main()
