# AWS tools

## Prerequisites
The following arguments variables are required as environment variables or in [AWS config files](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html):
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION`

```bash
export AWS_SECRET_ACCESS_KEY=<value>
export AWS_ACCESS_KEY_ID=< value>
export AWS_REGION=<value>
```

## Delete S3 velero bucket
This script deletes a bucket associated with a cluster after the cluster is uninstalled.
- The script will delete the velero bucket that is mapped to a cluster.

Use `poetry run python aws/delete_s3_velero_bucket.py` to execute the code.

```
poetry run python aws/delete_s3_velero_bucket.py --help
poetry run python aws/delete_s3_velero_bucket.py  --cluster-name <cluster_name>
```
## Create AWS network resources
"""
This script can be used for creating custom VPC and other resources on AWS,
to create security group with specified Inbound and Outbound Rules

Pre-requisites:
Set the following as environment Variables or input argument, can also be read from
aws configuration file:
    AWS_ACCESS_KEY_ID: Specifies an AWS access key
    AWS_SECRET_ACCESS_KEY: Specifies the secret key associated with the access key
    AWS_REGION: Specifies the AWS Region to send the request to


Usage:
1. Import this module to create AWS network resources and Security Group with Inbound and Outbound rules :

    from create_aws_network_resources import create_network_resources, create_security_group, ec2_add_security_rules

    resources = create_aws_network_resources(cidr_block="10,0,0,0/16", site_name="demo", subnet_count=3)
    security_grp_id = create_security_group(vpc_id=resources['vpc_id'], sec_grp_name="security-demo")
    ec2_add_security_rules(security_grp_id=security_grp_id, rules_json_file="security_rules_example.json")

2.  poetry run python aws/create_aws_network_resources.py
        --aws_access_key_id=<access-key> --aws_secret_access_key=<secret> --region <aws_region> --cidr-block=<vpc-cidr> --site-name=<vpc-name> --subnet-count=<number-of-subnets> --security-group-name=<secuiryt-group> --security-group-rules-file=<path-to-rules-file>
"""
