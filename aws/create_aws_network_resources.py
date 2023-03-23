"""
This script can be used for creating custom VPC and other resources on AWS,
to create security group with specified Inbound and Outbound Rules

Pre-requisites:
Set the following environment Variables
    AWS_ACCESS_KEY_ID: Specifies an AWS access key
    AWS_SECRET_ACCESS_KEY: Specifies the secret key associated with the access key
    AWS_REGION: Specifies the AWS Region to send the request to

Usage:
Import this module to create AWS network resources and Security Group with Inbound and Outbound rules

    from create_aws_network_resources import create_network_resources, create_security_group, ec2_add_security_rules

    resources = create_aws_network_resources(cidr_block="10,0,0,0/16", site_name="demo", subnet_count=3)
    security_grp_id = create_security_group(vpc_id=resources['vpc_id'], sec_grp_name="security-demo")
    ec2_add_security_rules(security_grp_id=security_grp_id, rules_json_file="security_rules_example.json")


"""
import json
import os
import sys
import time
from ipaddress import AddressValueError, IPv4Network

import boto3
import click
from aws_utils import verify_aws_env_requirements_met
from botocore.exceptions import ClientError
from ocp_utilities.logger import get_logger

LOGGER = get_logger(__name__)
ec2_client = boto3.client("ec2")


def ec2_assign_name_tag(res_id, tag_name) -> None:
    """
    Assign 'Name' tag value to EC2 resource

    Args:
        res_id (str): The ID of resource(which can be of 'vpc', 'subnet', etc)
        tag_name (str): The value of 'Name' tag

    Returns: None
    """
    try:

        ec2_client.create_tags(
            Resources=[
                res_id,
            ],
            Tags=[
                {
                    "Key": "Name",
                    "Value": tag_name,
                },
            ],
        )
    except ClientError as client_err:
        LOGGER.error(client_err)
        raise


def get_subnets_cidr(cidr_block, subnet_count) -> list:
    """
    Calculates Subnet CIDR address blocks within given VPC CIDR block

    Args:
        cidr_block (str): The IPv4 network of VPC
        subnet_count (str): The number of additional bits with which to extend the prefix

    Returns:
        list: The list of subnet CIDR address blocks

    Raises:
        AddressValueError: If cidr_block provided in invalid for IPv4 address
    """
    subnet_range = []
    try:
        net = IPv4Network(cidr_block)
        LOGGER.info(f"cidr block net  get subnets function: {net}")
        LOGGER.info(f"type : {net}")

        prefix = net.prefixlen + (subnet_count * 2)
        for subnet in net.subnets(new_prefix=prefix):
            subnet_range.append(str(subnet))
        return subnet_range
    except AddressValueError:
        LOGGER.error(f"Address is invalid for IPv4: {cidr_block}")
        raise


def get_availability_zones() -> list:
    """
    Provides a list of zone IDs in availability zone of current AWS Region

    Returns:
        list: The list of Zone IDs

    Raises:
        ClientError: If error response is provided by an AWS service to Boto3 client’s request.
    """
    zones = []
    try:
        av_zones = ec2_client.describe_availability_zones()
        for zone in av_zones.get("AvailabilityZones"):
            zones.append(zone.get("ZoneId"))
        LOGGER.info(f" az : {zones}")
        return zones
    except ClientError as client_err:
        LOGGER.error(client_err)
        raise


def create_network_resources(cidr_block, site_name, subnet_count) -> dict:
    """
    Creates VPC and other resources(VPC Endpoint, Public and Private Subnets, Route Tables,
    Route, Nat gateways, Internet Gateways)

    Args:
        cidr_block (str): The IPv4 network for creating VPC
        site_name (str): The value for 'Name' tag used for all resource
        subnet_count (str): The number of public and private subnet pairs to create

    Returns:
        dict: The dictionary contains VPC ID, public and private subnet IDs

    """

    verify_aws_env_requirements_met()

    # vpc_output = {}
    subnet_cidr_blocks = get_subnets_cidr(cidr_block, subnet_count)
    LOGGER.info(f" subnet cidr blocks: {subnet_cidr_blocks}")
    availability_zones = get_availability_zones()

    # Check the provided number of public and private subnet pairs should not be more than 3
    # for creating one public and private subnet per AZ
    if subnet_count > 3:
        LOGGER.error(
            f"Number of private and public subnet pairs should be less than 3! \n{subnet_count} is not acceptable!!!",
        )
        sys.exit(1)

    try:

        vpc_output = create_vpc_and_vpc_endpoint(cidr_block, site_name)
        vpc_id = vpc_output["vpc_id"]

        LOGGER.info(f"Creating {subnet_count} Public Subnets...")
        vpc_output["public_subnet_ids"] = create_public_subnets_for_vpc(
            subnet_count, vpc_id, subnet_cidr_blocks, availability_zones, site_name
        )

        LOGGER.info(f"Creating {subnet_count} Private Subnets...")
        vpc_output["private_subnet_ids"] = create_private_subnets_for_vpc(
            subnet_count, vpc_id, subnet_cidr_blocks, availability_zones, site_name
        )

        LOGGER.info("Creating Internet Gateway...")
        internet_gateway_id = create_and_attach_igw(site_name, vpc_id)

        LOGGER.info(f"Allocating Public IPs for VPC {vpc_id}")
        alloc_ids = allocate_elastic_ips(subnet_count, site_name)

        LOGGER.info("Creating Nat Gateway (1 per AZ) for each public subnet")
        nat_gateway_ids = create_nat_gateway(
            subnet_count, site_name, vpc_output, alloc_ids, "public"
        )

        LOGGER.info("Creating  Public Route Tables")

        rt_public_id = create_public_route_table(site_name, vpc_id)
        LOGGER.info("Creating  Private Route Tables")
        rt_private_ids = create_private_route_table(
            subnet_count,
            vpc_id,
            site_name,
        )

        LOGGER.info("Creating Routes for  Route Tables")
        associate_route_ipv4(rt_public_id, internet_gateway_id)

        associate_route_ipv6(rt_public_id, internet_gateway_id)

        associate_route_to_private_nat(subnet_count, rt_private_ids, nat_gateway_ids)

        associate_vpc_endpoint_private_route(vpc_output["vpc_endpoint"], rt_private_ids)

        public_route_table_association(
            subnet_count,
            route_table_id=rt_public_id,
            subnet_id=vpc_output["public_subnet_ids"],
        )

        private_route_table_association(
            subnet_count,
            route_table_id=rt_private_ids,
            subnet_id=vpc_output["private_subnet_ids"],
        )
        return vpc_output

    except ClientError as ec2_client_err:
        LOGGER.error(ec2_client_err)
        raise


def associate_route_to_private_nat(subnet_count, rt_private_ids, nat_gateway_ids):
    """
    Args:
        subnet_count(int):
        rt_private_ids(list): list containing id for private route table
        nat_gateway_ids(list): list consisting nat gateway id's
    """
    for count in range(subnet_count):
        ec2_client.create_route(
            RouteTableId=rt_private_ids[count],
            DestinationCidrBlock="0.0.0.0/0",
            NatGatewayId=nat_gateway_ids[count],
        )


def create_security_group(vpc_id, sec_grp_name) -> str:
    """
    Creates Security Group for specified VPC ID

    Args:
        vpc_id (str): The ID of VPC in which to create the security group.
        sec_grp_name (str): The name of security group to create

    Returns:
        str: The ID of security group created

    Raises:
        ClientError: If error response is provided by an AWS service to Boto3 client’s request.
    """

    verify_aws_env_requirements_met()

    try:
        security_grp = ec2_client.create_security_group(
            Description=sec_grp_name,
            GroupName=sec_grp_name,
            VpcId=vpc_id,
        )
        ec2_assign_name_tag(res_id=security_grp["GroupId"], tag_name=sec_grp_name)
        return security_grp["GroupId"]

    except ClientError as ec2_client_err:
        LOGGER.error(ec2_client_err)
        raise


def ec2_add_inbound_security_rule(security_grp_id, sg_rule) -> None:
    """
    Adds Inbound Rule to security group

    Args:
        security_grp_id (str): The ID of Security Group to add inbound rule with
        sg_rule (dict): The dictionary containing of security inbound rule

    Returns: None
    """
    try:
        ec2_client.authorize_security_group_ingress(
            GroupId=security_grp_id,
            CidrIp=sg_rule["CidrIp"],
            IpProtocol=sg_rule["IpProtocol"],
            FromPort=sg_rule["FromPort"],
            ToPort=sg_rule["ToPort"],
        )
    except ClientError as ec2_client_err:
        LOGGER.error(ec2_client_err)
        raise


def ec2_add_outbound_security_rule(security_grp_id, sg_rule) -> None:
    """
    Adds Outbound Rule to security group

    Args:
        security_grp_id (str): The ID of Security Group to add outbound rule with
        sg_rule (dict): The dictionary containing of security outbound rule

    Returns: None
    """
    try:
        ec2_client.authorize_security_group_egress(
            GroupId=security_grp_id,
            CidrIp=sg_rule["CidrIp"],
            IpProtocol=sg_rule["IpProtocol"],
            FromPort=sg_rule["FromPort"],
            ToPort=sg_rule["ToPort"],
        )
    except ClientError as ec2_client_err:
        LOGGER.error(ec2_client_err)
        raise


def ec2_add_security_rules(security_grp_id, rules_json_file) -> None:
    """
    Adds Inbound and Outbound Rules to security group

    Args:
        security_grp_id (str): The ID of Security Group to add inbound/outbound rule with
        rules_json_file (str): The file name of security inbound and outbound rules in json

    Returns: None

    Raises:
        ClientError: If error response is provided by an AWS service to Boto3 client’s request.
    """
    with open(rules_json_file) as rules_file:
        rules_object = json.load(rules_file)

    try:
        if "inbound_rules" in rules_object.keys():
            for rule in rules_object["inbound_rules"]:
                ec2_add_inbound_security_rule(security_grp_id, rule)

        if "outbound_rules" in rules_object.keys():
            for rule in rules_object["outbound_rules"]:
                ec2_add_outbound_security_rule(security_grp_id, rule)

    except ClientError as ec2_client_err:
        LOGGER.error(ec2_client_err)
        raise


def create_public_subnets_for_vpc(
    subnet_count, vpc_id, subnet_cidr_blocks, availability_zones, site_name
):
    public_subnet_ids_list = []
    for count in range(subnet_count):
        subnet = ec2_client.create_subnet(
            CidrBlock=subnet_cidr_blocks[count],
            VpcId=vpc_id,
            AvailabilityZoneId=availability_zones[count],
        )
        time.sleep(5)
        ec2_assign_name_tag(
            res_id=subnet["Subnet"]["SubnetId"],
            tag_name=f"{site_name}-subnet-public-{count+1}",
        )
        public_subnet_ids_list.append(subnet["Subnet"]["SubnetId"])
    return public_subnet_ids_list


def create_private_subnets_for_vpc(
    subnet_count, vpc_id, subnet_cidr_blocks, availability_zones, site_name
):
    private_subnet_ids_list = []
    for count in range(subnet_count):
        subnet = ec2_client.create_subnet(
            CidrBlock=subnet_cidr_blocks[count + subnet_count],
            VpcId=vpc_id,
            AvailabilityZoneId=availability_zones[count],
        )
        time.sleep(5)
        ec2_assign_name_tag(
            res_id=subnet["Subnet"]["SubnetId"],
            tag_name=f"{site_name}-subnet-private-{count+1}",
        )
        private_subnet_ids_list.append(subnet["Subnet"]["SubnetId"])
    return private_subnet_ids_list


def create_and_attach_igw(site_name, vpc_id):
    internet_gateway = ec2_client.create_internet_gateway()
    internet_gateway_id = internet_gateway["InternetGateway"]["InternetGatewayId"]
    ec2_assign_name_tag(
        res_id=internet_gateway_id,
        tag_name=f"{site_name}-igw",
    )

    ec2_client.attach_internet_gateway(
        InternetGatewayId=internet_gateway_id,
        VpcId=vpc_id,
    )
    return internet_gateway_id


def allocate_elastic_ips(subnet_count, site_name):
    """ """
    eip_list = []
    for count in range(subnet_count):
        eip = ec2_client.allocate_address(Domain="vpc")
        ec2_assign_name_tag(
            res_id=eip["AllocationId"],
            tag_name=f"{site_name}-eip{count+1}",
        )
        eip_list.append(eip["AllocationId"])
    return eip_list


def create_nat_gateway(subnet_count, site_name, vpc_output, alloc_ids, subnet_type):
    """ """
    nat_gateway_id_list = []
    for count in range(subnet_count):
        nat_gateway = ec2_client.create_nat_gateway(
            AllocationId=alloc_ids[count],
            SubnetId=vpc_output["public_subnet_ids"][count],
        )
        ec2_assign_name_tag(
            res_id=nat_gateway["NatGateway"]["NatGatewayId"],
            tag_name=f"{site_name}-nat-{subnet_type}{count+1}",
        )
        nat_gateway_id_list.append(nat_gateway["NatGateway"]["NatGatewayId"])
    ec2_client.get_waiter("nat_gateway_available").wait(
        NatGatewayIds=nat_gateway_id_list,
    )
    return nat_gateway_id_list


def create_public_route_table(site_name, vpc_id):
    """
    Create route table for public routes

    Args:
        site_name(str): vpc name
        vpc_id(str): vpc Id of the associated vpc
    Return:
        str: route table id

    Raises:
        ClientError: raises ec2 client error
    """
    try:

        rt_public = ec2_client.create_route_table(VpcId=vpc_id)
        rt_public_id = rt_public["RouteTable"]["RouteTableId"]
        time.sleep(3)
        ec2_assign_name_tag(
            res_id=rt_public_id,
            tag_name=f"{site_name}-rtb-public",
        )
        return rt_public_id

    except ClientError as ec2_client_err:
        LOGGER.error(ec2_client_err)
        raise


def create_private_route_table(subnet_count, vpc_id, site_name):
    """
    Create route table for private routes

    Args:
        subent_count(int): no. of subnets
        vpc_id(str): vpc Id of the associated vpc
        site_name(str): vpc name

    Return:
        list: list containing subnet Ids

    Raises:
        ClientError: raises ec2 client error
    """
    try:

        rt_private_ids_list = []
        for count in range(subnet_count):
            rt_private = ec2_client.create_route_table(VpcId=vpc_id)
            time.sleep(3)
            ec2_assign_name_tag(
                res_id=rt_private["RouteTable"]["RouteTableId"],
                tag_name=f"{site_name}-rtb-private{count+1}",
            )
            rt_private_ids_list.append(rt_private["RouteTable"]["RouteTableId"])
        return rt_private_ids_list

    except ClientError as ec2_client_err:
        LOGGER.error(ec2_client_err)
        raise


def associate_route_ipv4(route_table_id, internet_gateway_id):
    """ """
    try:

        LOGGER.info("Creating Routes for  Route Tables")
        ec2_client.create_route(
            RouteTableId=route_table_id,
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=internet_gateway_id,
        )
        return
    except ClientError as ec2_client_err:
        LOGGER.error(ec2_client_err)
        raise


def associate_route_ipv6(route_table_id, internet_gateway_id):
    """ """
    try:

        ec2_client.create_route(
            RouteTableId=route_table_id,
            DestinationIpv6CidrBlock="::/0",
            GatewayId=internet_gateway_id,
        )
    except ClientError as ec2_client_err:
        LOGGER.error(ec2_client_err)
        raise


def public_route_table_association(subnet_count, route_table_id, subnet_id):
    """
    args:
       route_table_type(str): public or private
       subnet_count(int): max value is 3
       route_table_id:
       subnet_id()
    """
    try:

        for count in range(subnet_count):
            ec2_client.associate_route_table(
                RouteTableId=route_table_id,
                SubnetId=subnet_id[count],
            )
    except ClientError as ec2_client_err:
        LOGGER.error(ec2_client_err)
        raise


def private_route_table_association(subnet_count, route_table_id, subnet_id):
    """
    args:
       route_table_type(str): public or private
       subnet_count(int): max value is 3
       route_table_id:
       subnet_id()
    """
    try:

        for count in range(subnet_count):
            ec2_client.associate_route_table(
                RouteTableId=route_table_id[count],
                SubnetId=subnet_id[count],
            )
    except ClientError as ec2_client_err:
        LOGGER.error(ec2_client_err)
        raise


def associate_vpc_endpoint_private_route(vpc_endpoint, rt_private_ids):

    ec2_client.modify_vpc_endpoint(
        VpcEndpointId=vpc_endpoint,
        AddRouteTableIds=rt_private_ids,
    )


def create_vpc_and_vpc_endpoint(cidr_block, site_name):
    vpc_output = {}
    LOGGER.info("Creating VPC...")
    vpc = ec2_client.create_vpc(
        CidrBlock=cidr_block,
        AmazonProvidedIpv6CidrBlock=False,
    )

    vpc_id = vpc["Vpc"]["VpcId"]
    vpc_output["vpc_id"] = vpc_id
    ec2_client.get_waiter("vpc_available").wait(VpcIds=[vpc_id])

    ec2_assign_name_tag(res_id=vpc_id, tag_name=site_name)

    ec2_client.modify_vpc_attribute(
        EnableDnsSupport={
            "Value": True,
        },
        VpcId=vpc_id,
    )

    ec2_client.modify_vpc_attribute(
        EnableDnsHostnames={
            "Value": True,
        },
        VpcId=vpc_id,
    )

    aws_region = os.getenv("AWS_REGION")
    vpc_endpoint = ec2_client.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{aws_region}.s3",
    )

    while True:
        state = vpc_endpoint["VpcEndpoint"]["State"]
        if state == "available":
            break
        time.sleep(5)
    ec2_assign_name_tag(
        res_id=vpc_endpoint["VpcEndpoint"]["VpcEndpointId"],
        tag_name=f"{site_name}-endpoint-s3",
    )
    vpc_output["vpc_endpoint"] = vpc_endpoint["VpcEndpoint"]["VpcEndpointId"]

    return vpc_output


@click.command()
@click.option(
    "--aws-access-key-id",
    help="Set AWS access key id, default if taken from environment variable: AWS_ACCESS_KEY_ID",
    required=True,
    default=os.getenv("AWS_ACCESS_KEY_ID"),
)
@click.option(
    "--aws-secret-access-key",
    help="Set AWS secret access key id,default if taken from environment variable: AWS_SECRET_ACCESS_KEY",
    required=True,
    default=os.getenv("AWS_SECRET_ACCESS_KEY"),
)
@click.option(
    "-c",
    "--cluster-name",
    help="",
    required=True,
    default=os.getenv("AWS_SECRET_ACCESS_KEY"),
)
@click.option(
    "--region",
    help="Set aws region, where you want to create resources",
    required=True,
    default=os.getenv("AWS_REGION"),
)
def main():
    print(get_availability_zones())

    res = create_network_resources(
        cidr_block="10.0.0.0/16", site_name="odf-ci", subnet_count=3
    )
    LOGGER.info(f"\nResources ID: {res}")

    security_grp_id = create_security_group(
        vpc_id=res["vpc_id"], sec_grp_name="odf-sec-group"
    )
    LOGGER.info(f"\nSecurity Grp: {security_grp_id}")

    ec2_add_security_rules(
        security_grp_id=security_grp_id, rules_json_file="rules.json"
    )


if __name__ == "__main__":
    main()
