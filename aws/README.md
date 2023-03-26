# AWS tools

## Delete S3 velero bucket
This script deletes a bucket associated with a cluster after the cluster is uninstalled.
- The script will delete the velero bucket that is mapped to a cluster.
- The following arguments variables are required: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`

```bash
exxport AWS_SECRET_ACCESS_KEY=<AWS_SECRET_ACCESS_KEY value>
exxport AWS_ACCESS_KEY_ID=<AWS_ACCESS_KEY_ID value>
```

Use `poery run python aws/delete_s3_velero_bucket.py` to execute the code.

```
poery run python aws/delete_s3_velero_bucket.py --help
poery run python aws/delete_s3_velero_bucket.py  --cluster-name <cluster_name>
```
