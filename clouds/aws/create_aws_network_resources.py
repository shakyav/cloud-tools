import json
import os
from ipaddress import IPv4Network

import click
from aws_utils import verify_aws_config, verify_aws_credentials
from ocp_resources.utils import TimeoutSampler
from simple_logger.logger import get_logger

from clouds.aws.exceptions import (
    InvalidNumberOfSubnets,
    InvalidSubnetRange,
    NoAvailabilityZones,
)
from clouds.aws.session_clients import ec2_client

LOGGER = get_logger(name=__name__)


def ec2_assign_name_tag(ec2_client, resource_id, tag_name) -> None:
    """
    Assign 'Name' tag value to EC2 resource

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         resource_id (str): The ID of resource(which can be of 'vpc', 'subnet', etc)
         tag_name (str): The value of 'Name' tag
    """
    ec2_client.create_tags(
        Resources=[
            resource_id,
        ],
        Tags=[
            {
                "Key": "Name",
                "Value": tag_name,
            },
        ],
    )


def get_subnets_cidr(cidr_block, subnet_count) -> list:
    """
    Calculates Subnet CIDR address blocks within given VPC CIDR block

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         cidr_block (str): The IPv4 network of VPC
         subnet_count (str): The number of additional bits with which to extend the prefix

    Returns:
         list: The list of subnet CIDR address blocks

    """
    subnet_range = []
    net = IPv4Network(address=cidr_block)
    prefix = net.prefixlen + (subnet_count)
    for subnet in net.subnets(new_prefix=prefix):
        subnet_range.append(str(subnet))
    if not subnet_range:
        LOGGER.error(
            f"Subnet Range is empty, no new subnet address added"
            f"Subnet Range: {subnet_range}"
        )
        raise InvalidSubnetRange()
    return subnet_range


def get_availability_zones(ec2_client) -> list:
    """
    Provides a list of zone IDs in availability zone of current AWS Region

    Args:
         ec2_client (botocore.client.EC2): aws botocore client

    Returns:
         list: The list of Zone IDs
    """
    zones = []
    av_zones = ec2_client.describe_availability_zones()
    for zone in av_zones["AvailabilityZones"]:
        zones.append(zone["ZoneId"])
    if not zones:
        LOGGER.error(f"Availabitlity zones not found,Availability zones : { zones }")
        raise NoAvailabilityZones()
    return zones


def create_network_resources(
    ec2_client, cidr_block, site_name, subnet_count, region_name
) -> dict:
    """
    Creates VPC and other resources such as VPC Endpoint, Public and Private Subnets, Route Tables,
    Route, Nat gateways, Internet Gateways

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         cidr_block (str): The IPv4 network for creating VPC
         site_name (str): The value for 'Name' tag used for all resource
         subnet_count (str): The number of public and private subnet pairs to create

    Returns:
         dict: The dictionary contains VPC ID, public and private subnet IDs
    """
    verify_aws_credentials()
    verify_aws_config()

    subnet_cidr_blocks = get_subnets_cidr(
        cidr_block=cidr_block, subnet_count=subnet_count
    )
    availability_zones = get_availability_zones(ec2_client=ec2_client)

    # Check the provided number of public and private subnet pairs should not be more than 3
    # for creating one public and private subnet per AZ
    if subnet_count > 3:
        LOGGER.error(
            f"Subnet Count: {subnet_count}"
            f"Number of subnets must be not be greater than 3"
        )
        raise InvalidNumberOfSubnets()

    vpc_output = create_vpc_and_vpc_endpoint(
        ec2_client=ec2_client,
        cidr_block=cidr_block,
        site_name=site_name,
        region_name=region_name,
    )
    vpc_id = vpc_output["vpc_id"]
    vpc_output["public_subnet_ids"] = create_public_subnets_for_vpc(
        ec2_client=ec2_client,
        subnet_count=subnet_count,
        vpc_id=vpc_id,
        subnet_cidr_blocks=subnet_cidr_blocks,
        availability_zones=availability_zones,
        site_name=site_name,
    )
    vpc_output["private_subnet_ids"] = create_private_subnets_for_vpc(
        ec2_client=ec2_client,
        subnet_count=subnet_count,
        vpc_id=vpc_id,
        subnet_cidr_blocks=subnet_cidr_blocks,
        availability_zones=availability_zones,
        site_name=site_name,
    )
    internet_gateway_id = create_and_attach_internet_gateway(
        ec2_client=ec2_client, site_name=site_name, vpc_id=vpc_id
    )
    alloc_ids = allocate_elastic_ips(
        ec2_client=ec2_client, subnet_count=subnet_count, site_name=site_name
    )
    nat_gateway_ids = create_nat_gateway(
        ec2_client=ec2_client,
        site_name=site_name,
        subnet_count=subnet_count,
        vpc_output=vpc_output,
        alloc_ids=alloc_ids,
        subnet_type="public",
    )
    rt_public_id = create_public_route_table(
        ec2_client=ec2_client, site_name=site_name, vpc_id=vpc_id
    )
    rt_private_ids = create_private_route_table(
        ec2_client=ec2_client,
        subnet_count=subnet_count,
        vpc_id=vpc_id,
        site_name=site_name,
    )
    associate_route_ipv4(
        ec2_client=ec2_client,
        route_table_id=rt_public_id,
        internet_gateway_id=internet_gateway_id,
    )
    associate_route_ipv6(
        ec2_client=ec2_client,
        route_table_id=rt_public_id,
        internet_gateway_id=internet_gateway_id,
    )
    create_route_for_private_nat(
        ec2_client=ec2_client,
        subnet_count=subnet_count,
        rt_private_ids=rt_private_ids,
        nat_gateway_ids=nat_gateway_ids,
    )
    ec2_client.modify_vpc_endpoint(
        VpcEndpointId=vpc_output["vpc_endpoint"],
        AddRouteTableIds=rt_private_ids,
    )
    route_table_association(
        ec2_client=ec2_client,
        subnet_count=subnet_count,
        public_route_table_id=rt_public_id,
        private_route_table_id=rt_private_ids,
        public_subnets=vpc_output["public_subnet_ids"],
        private_subnets=vpc_output["private_subnet_ids"],
    )

    return vpc_output


def create_route_for_private_nat(
    ec2_client, subnet_count, rt_private_ids, nat_gateway_ids
) -> None:
    """
    Creates route to private NAT

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         subnet_count (int): number of subnets required
         rt_private_ids (list): list containing id for private route table
         nat_gateway_ids (list): list consisting nat gateway id's
    """
    for count in range(subnet_count):
        ec2_client.create_route(
            RouteTableId=rt_private_ids[count],
            DestinationCidrBlock="0.0.0.0/0",
            NatGatewayId=nat_gateway_ids[count],
        )


def create_security_group(ec2_client, vpc_id, security_group_name) -> str:
    """
    Creates Security Group for specified VPC ID

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         vpc_id (str): The ID of VPC in which to create the security group.
         security_group_name (str): The name of security group to create

    Returns:
         str: The ID of security group created
    """

    security_group = ec2_client.create_security_group(
        Description=security_group_name,
        GroupName=security_group_name,
        VpcId=vpc_id,
    )
    ec2_assign_name_tag(
        ec2_client=ec2_client,
        resource_id=security_group["GroupId"],
        tag_name=security_group_name,
    )
    return security_group["GroupId"]


def ec2_add_inbound_security_rule(
    ec2_client, security_group_id, security_group_rule
) -> None:
    """
    Adds Inbound Rule to security group

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         security_group_id (str): The ID of Security Group to add inbound rule with
         security_group_rule (dict): The dictionary containing of security inbound rule
    """
    ec2_client.authorize_security_group_ingress(
        GroupId=security_group_id,
        CidrIp=security_group_rule["CidrIp"],
        IpProtocol=security_group_rule["IpProtocol"],
        FromPort=security_group_rule["FromPort"],
        ToPort=security_group_rule["ToPort"],
    )


def ec2_add_outbound_security_rule(
    ec2_client, security_group_id, security_group_rule
) -> None:
    """
    Adds Outbound Rule to security group

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         security_group_id (str): The ID of Security Group to add outbound rule with
         security_group_rule (dict): The dictionary containing of security outbound rule
    """
    ec2_client.authorize_security_group_egress(
        GroupId=security_group_id,
        CidrIp=security_group_rule["CidrIp"],
        IpProtocol=security_group_rule["IpProtocol"],
        FromPort=security_group_rule["FromPort"],
        ToPort=security_group_rule["ToPort"],
    )


def ec2_add_security_rules(ec2_client, security_group_id, rules_json_file) -> None:
    """
    Adds Inbound and Outbound Rules to security group

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         security_group_id (str): The ID of Security Group to add inbound/outbound rule with
         rules_json_file (str): The file name of security inbound and outbound rules in json
    """
    with open(rules_json_file) as rules_file:
        rules_object = json.load(rules_file)

    if "inbound_rules" in rules_object.keys():
        for rule in rules_object["inbound_rules"]:
            ec2_add_inbound_security_rule(
                ec2_client=ec2_client,
                security_group_id=security_group_id,
                security_group_rule=rule,
            )

    if "outbound_rules" in rules_object.keys():
        for rule in rules_object["outbound_rules"]:
            ec2_add_outbound_security_rule(
                ec2_client=ec2_client,
                security_group_id=security_group_id,
                security_group_rule=rule,
            )


def create_public_subnets_for_vpc(
    ec2_client, subnet_count, vpc_id, subnet_cidr_blocks, availability_zones, site_name
) -> list:
    """
    Creates public subnets in a given vpc

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         subnet_count (int): The number of additional bits with which to extend the prefix
         vpc_id (str): Id for the VPC where subnets need to be created
         subnet_cidr_blocks (list): list of subnets CIDRs available
         availability_zones (list): list of available zones
         site_name (str): The value for 'Name' tag used for all resource

    Returns:
         list: list of ID's for the subnets created
    """
    LOGGER.info(f"Creating {subnet_count} Public Subnets.")
    public_subnet_ids_list = []
    for count in range(subnet_count):
        subnet = ec2_client.create_subnet(
            CidrBlock=subnet_cidr_blocks[count],
            VpcId=vpc_id,
            AvailabilityZoneId=availability_zones[count],
        )
        subnet_details = ec2_client.describe_subnets(
            SubnetIds=[subnet["Subnet"]["SubnetId"]]
        )
        for sample in TimeoutSampler(
            wait_timeout=300,
            sleep=5,
            func=is_resource_available,
            aws_resource={"Resource": subnet_details["Subnets"][0]},
        ):
            if sample is True:
                break

        ec2_assign_name_tag(
            ec2_client=ec2_client,
            resource_id=subnet["Subnet"]["SubnetId"],
            tag_name=f"{site_name}-subnet-public-{count+1}",
        )
        public_subnet_ids_list.append(subnet["Subnet"]["SubnetId"])
    return public_subnet_ids_list


def create_private_subnets_for_vpc(
    ec2_client, subnet_count, vpc_id, subnet_cidr_blocks, availability_zones, site_name
) -> list:
    """
    Creates public subnets in a given vpc

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         subnet_count (int): The number of additional bits with which to extend the prefix
         vpc_id (str): Id for the VPC where subnets need to be created
         subnet_cidr_blocks (list): list of subnets CIDRs available
         availability_zones (list): list of available zones
         site_name (str): The value for 'Name' tag used for all resource

    Returns:
         list: list of ID's for the subnets created
    """
    LOGGER.info(f"Creating {subnet_count} Private Subnets.")
    private_subnet_ids_list = []
    for count in range(subnet_count):
        subnet = ec2_client.create_subnet(
            CidrBlock=subnet_cidr_blocks[count + subnet_count],
            VpcId=vpc_id,
            AvailabilityZoneId=availability_zones[count],
        )
        subnet_details = ec2_client.describe_subnets(
            SubnetIds=[subnet["Subnet"]["SubnetId"]]
        )
        for sample in TimeoutSampler(
            wait_timeout=300,
            sleep=5,
            func=is_resource_available,
            aws_resource={"Resource": subnet_details["Subnets"][0]},
        ):
            if sample is True:
                break

        ec2_assign_name_tag(
            ec2_client=ec2_client,
            resource_id=subnet["Subnet"]["SubnetId"],
            tag_name=f"{site_name}-subnet-private-{count+1}",
        )
        private_subnet_ids_list.append(subnet["Subnet"]["SubnetId"])
    return private_subnet_ids_list


def create_and_attach_internet_gateway(ec2_client, site_name, vpc_id) -> str:
    """
    Creates internet gateway for public access

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         site_name (str): The value for 'Name' tag used for all resource
         vpc_id (str): vpc Id to associate gateway to vpc

    Retruns:
         str : internet gateway id
    """
    LOGGER.info("Creating Internet Gateway.")
    internet_gateway = ec2_client.create_internet_gateway()
    internet_gateway_id = internet_gateway["InternetGateway"]["InternetGatewayId"]
    ec2_assign_name_tag(
        ec2_client=ec2_client,
        resource_id=internet_gateway_id,
        tag_name=f"{site_name}-internet_gateway",
    )

    ec2_client.attach_internet_gateway(
        InternetGatewayId=internet_gateway_id,
        VpcId=vpc_id,
    )
    return internet_gateway_id


def allocate_elastic_ips(ec2_client, subnet_count, site_name) -> list:
    """
    Allocate public elastic IPs for NAT

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         subnet_count (int): subnet to alloacte elastic ip per subnet
         site_name (str): vpc name to associate elastic ips

    Returns:
         list: list of elastic ips allocated
    """

    elastic_ip_list = []
    for count in range(subnet_count):
        eip = ec2_client.allocate_address(Domain="vpc")
        ec2_assign_name_tag(
            ec2_client=ec2_client,
            resource_id=eip["AllocationId"],
            tag_name=f"{site_name}-eip{count+1}",
        )
        elastic_ip_list.append(eip["AllocationId"])
    return elastic_ip_list


def create_nat_gateway(
    ec2_client, site_name, subnet_count, vpc_output, alloc_ids, subnet_type
) -> list:
    """
    Creates NAT gateway to map private network to single public ip

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         subnet_count (int): subnet count to create nat gateway per subnet
         site_name (str): vpc name to associate nat gateway

    Returns:
         list (nat_gateway_id_list): list containing nat gateway id
    """
    LOGGER.info("Creating Nat Gateway (1 per AZ) for each public subnet")

    nat_gateway_id_list = []
    for count in range(subnet_count):
        nat_gateway = ec2_client.create_nat_gateway(
            AllocationId=alloc_ids[count],
            SubnetId=vpc_output["public_subnet_ids"][count],
        )
        ec2_assign_name_tag(
            ec2_client=ec2_client,
            resource_id=nat_gateway["NatGateway"]["NatGatewayId"],
            tag_name=f"{site_name}-nat-{subnet_type}{count+1}",
        )
        nat_gateway_id_list.append(nat_gateway["NatGateway"]["NatGatewayId"])
    ec2_client.get_waiter("nat_gateway_available").wait(
        NatGatewayIds=nat_gateway_id_list,
    )
    return nat_gateway_id_list


def create_public_route_table(ec2_client, site_name, vpc_id) -> list:
    """
    Creates route table for public routes

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         site_name (str): vpc name
         vpc_id (str): vpc Id of the associated vpc

    Returns:
         str : route table id
    """
    LOGGER.info("Creating  Public Route Tables")

    rt_public = ec2_client.create_route_table(VpcId=vpc_id)
    rt_public_id = rt_public["RouteTable"]["RouteTableId"]
    rt_details = ec2_client.describe_route_tables(RouteTableIds=[rt_public_id])
    for sample in TimeoutSampler(
        wait_timeout=300,
        sleep=5,
        func=is_resource_available,
        aws_resource={"Resource": (rt_details["RouteTables"][0])["Routes"][0]},
    ):
        if sample is True:
            break

    ec2_assign_name_tag(
        ec2_client=ec2_client,
        resource_id=rt_public_id,
        tag_name=f"{site_name}-route-table-public",
    )
    return rt_public_id


def create_private_route_table(ec2_client, subnet_count, vpc_id, site_name) -> list:
    """
    Creates route table for private routes

    Args:
         ec2_client (botocore.client.EC2): aws botocore client
         subent_count (int): number of subnets
         vpc_id (str): vpc Id of the associated vpc
         site_name (str): vpc name

    Returns:
         list: list containing subnet Ids
    """
    LOGGER.info("Creating Private Route Tables")
    private_route_table_id_list = []
    for count in range(subnet_count):
        rt_private = ec2_client.create_route_table(VpcId=vpc_id)
        rt_private_id = rt_private["RouteTable"]["RouteTableId"]

        rt_details = ec2_client.describe_route_tables(RouteTableIds=[rt_private_id])
        for sample in TimeoutSampler(
            wait_timeout=300,
            sleep=5,
            func=is_resource_available,
            aws_resource={"Resource": (rt_details["RouteTables"][0])["Routes"][0]},
        ):
            if sample is True:
                break

        ec2_assign_name_tag(
            ec2_client=ec2_client,
            resource_id=rt_private["RouteTable"]["RouteTableId"],
            tag_name=f"{site_name}-route-table-private{count+1}",
        )
        private_route_table_id_list.append(rt_private["RouteTable"]["RouteTableId"])
    return private_route_table_id_list


def associate_route_ipv4(ec2_client, route_table_id, internet_gateway_id) -> None:
    """
    Send all IPv4 traffic to the internet gateway
    """
    LOGGER.info("Creating Routes for  Route Tables")
    ec2_client.create_route(
        RouteTableId=route_table_id,
        DestinationCidrBlock="0.0.0.0/0",
        GatewayId=internet_gateway_id,
    )


def associate_route_ipv6(ec2_client, route_table_id, internet_gateway_id) -> None:
    """
    Send all IPv6 traffic to the internet gateway

    Args:
         ec2_client (botocore.client.EC2): aws boto client
         route_table_id (str): route table id string
         internet_gateway_id (str): internet gateway id to associate
    """
    LOGGER.info("Creating IPV6 Routes for  Route Tables")
    ec2_client.create_route(
        RouteTableId=route_table_id,
        DestinationIpv6CidrBlock="::/0",
        GatewayId=internet_gateway_id,
    )


def route_table_association(
    ec2_client,
    subnet_count,
    public_route_table_id,
    private_route_table_id,
    public_subnets,
    private_subnets,
):
    """
    Add public routes to the route table

    Args:
         ec2_client (botocore.client.EC2): aws boto client
         subnet_count (int): The number of public subnets to attach
         public_route_table_id: route table id string
         private_route_table_id (list): list contaiing private route table id
         public_subnets (list): list containing public subnet id's
         private_subnets (list): list containing private subnet id's
    """

    LOGGER.info("Associtate public route tables")
    for count in range(subnet_count):
        ec2_client.associate_route_table(
            RouteTableId=public_route_table_id,
            SubnetId=public_subnets[count],
        )

    LOGGER.info("Associtate private route tables")
    for count in range(subnet_count):
        ec2_client.associate_route_table(
            RouteTableId=private_route_table_id[count],
            SubnetId=private_subnets[count],
        )


def create_vpc_and_vpc_endpoint(ec2_client, cidr_block, site_name, region_name) -> dict:
    """
    Create vpc and assign the name tag

    Args:
         ec2_client (botocore.client.EC2): aws boto client
         cidr_block (str): The IPv4 network for creating VPC
         site_name (str): The value for 'Name' tag used for all resource
         region_name (str): aws region

    Returns:
         dict: dictinary conatining key value pairs for vpc_id, vpc_endpoint
    """
    vpc_output = {}
    LOGGER.info("Creating VPC")
    vpc = ec2_client.create_vpc(
        CidrBlock=cidr_block,
        AmazonProvidedIpv6CidrBlock=False,
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    vpc_output["vpc_id"] = vpc_id
    vpc_details = ec2_client.describe_vpcs(VpcIds=[vpc["Vpc"]["VpcId"]])
    for sample in TimeoutSampler(
        wait_timeout=300,
        sleep=5,
        func=is_resource_available,
        aws_resource={"Resource": vpc_details["Vpcs"][0]},
    ):
        if sample is True:
            break

    ec2_assign_name_tag(ec2_client=ec2_client, resource_id=vpc_id, tag_name=site_name)

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

    vpc_endpoint = ec2_client.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{region_name}.s3",
    )

    vpc_endpoint_details = ec2_client.describe_vpc_endpoints(
        VpcEndpointIds=[vpc_endpoint["VpcEndpoint"]["VpcEndpointId"]]
    )
    for sample in TimeoutSampler(
        wait_timeout=300,
        sleep=5,
        func=is_resource_available,
        aws_resource={"Resource": vpc_endpoint_details["VpcEndpoints"][0]},
    ):
        if sample is True:
            break

    ec2_assign_name_tag(
        ec2_client=ec2_client,
        resource_id=vpc_endpoint["VpcEndpoint"]["VpcEndpointId"],
        tag_name=f"{site_name}-endpoint-s3",
    )
    vpc_output["vpc_endpoint"] = vpc_endpoint["VpcEndpoint"]["VpcEndpointId"]

    return vpc_output


def is_resource_available(aws_resource):
    state = aws_resource["Resource"]["State"]
    return state == "available" or state == "active"


@click.command()
@click.option(
    "--aws-access-key-id",
    help="""Set AWS access key id, default if taken from environment variable: AWS_ACCESS_KEY_ID,
            if not set can be read from config""",
    default=os.getenv("AWS_ACCESS_KEY_ID"),
)
@click.option(
    "--aws-secret-access-key",
    help="""Set AWS secret access key id,default if taken from environment variable: AWS_SECRET_ACCESS_KEY,
            if not set can be read from config""",
    default=os.getenv("AWS_SECRET_ACCESS_KEY"),
)
@click.option(
    "--region",
    help="""Set aws region, where you want to create resources default is take from environment,
            if not set can be read from config""",
    default=os.getenv("AWS_REGION"),
)
@click.option(
    "--cidr-block",
    help="Set vpc cidr block",
    required=True,
)
@click.option(
    "--site-name",
    help="Set vpc name",
    required=True,
)
@click.option(
    "--subnet-count",
    help="Set subnet, for ODF vpc it should be <= 3",
    required=True,
    default="3",
)
@click.option(
    "--security-group-name",
    help="Set name for the security group",
    required=True,
)
@click.option(
    "security-group-rules-file",
    help="path to file containing security group rules",
    required=True,
)
def main(
    aws_access_key_id,
    aws_secret_access_key,
    region,
    cidr_block,
    site_name,
    subnet_count,
    security_group_name,
    security_group_rules_file,
):
    boto_client = ec2_client(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region,
    )
    resources = create_network_resources(
        ec2_client=boto_client,
        cidr_block=cidr_block,
        site_name=site_name,
        subnet_count=int(subnet_count),
        region_name=region,
    )
    LOGGER.info(f" Resources ID: {resources}")

    security_group_id = create_security_group(
        ec2_client=boto_client,
        vpc_id=resources["vpc_id"],
        security_group_name=security_group_name,
    )
    LOGGER.info(f" Security Grp: {security_group_id}")

    ec2_add_security_rules(
        ec2_client=boto_client,
        security_group_id=security_group_id,
        rules_json_file=security_group_rules_file,
    )


if __name__ == "__main__":
    main()
