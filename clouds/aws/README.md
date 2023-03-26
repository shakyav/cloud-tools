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
