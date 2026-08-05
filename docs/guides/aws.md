# AWS connection guide

MultiCloudShield v0.1.0 uses the official boto3 credential provider chain and makes control-plane
read calls only. Credentials are resolved in the worker at call time; access keys and session tokens
must never be entered into MultiCloudShield or stored in a connection record.

## Recommended permission policy

The following policy is the narrow baseline generated from the v0.1.0 collectors. Attach it to the
audit role or identity used by the worker. Scope resource ARNs further where AWS supports it and your
estate boundaries permit it; many list and account posture APIs require `Resource: "*"`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "MultiCloudShieldInventory",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetTrailStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroupRules",
        "ec2:DescribeSecurityGroups",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetCredentialReport",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:ListUsers",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:ListKeys",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketEncryption",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketVersioning",
        "s3:GetPublicAccessBlock",
        "s3:ListAllMyBuckets"
      ],
      "Resource": "*"
    }
  ]
}
```

`sts:GetCallerIdentity` is also used to bind the resolved credentials to the registered account. AWS
does not require an identity-based permission for that operation. When using an audit role, the
source identity additionally needs `sts:AssumeRole` for that role and the role trust policy must
allow the source identity.

As a convenient alternative, AWS managed policy
`arn:aws:iam::aws:policy/SecurityAudit` covers the posture calls. It is broader than the generated
policy but deliberately safer than the other common choices:

- `job-function/ViewOnlyAccess` is insufficient: it omits configuration reads used by the S3, KMS,
  and CloudTrail collectors.
- `ReadOnlyAccess` is over-privileged for this product: `s3:Get*` includes customer object reads and
  it grants unrelated data-plane operations.

## Credential mechanisms

Prefer short-lived credentials. Supported mechanisms are:

1. The default boto3 chain, including environment credentials, container credentials, EC2 instance
   roles, and IRSA.
2. An IAM Identity Center profile. Store only the local profile name in the connection.
3. Role assumption. Store only the role ARN, session name, and (when required) the name of an
   environment variable containing the external ID. The external ID value is read by the worker and
   is never placed in the connection record.

The registered AWS scope must be the account ID returned by `sts:GetCallerIdentity`. A mismatch is
treated as an authentication failure, preventing a worker identity from scanning a different account
by mistake. Optional region allowlists are intersected with the enabled regions returned by
`ec2:DescribeRegions`; regions are not hard-coded.

Do not configure `AWS_ENDPOINT_URL` or service-specific `AWS_ENDPOINT_URL_*` variables for the
worker. MultiCloudShield rejects endpoint overrides so connection configuration cannot become a
signed-request SSRF path. Use the AWS partition and normal regional endpoints selected by boto3.

## Credential-report limitation

The IAM collector calls `iam:GetCredentialReport` when a report already exists and is fresh. It
never calls `iam:GenerateCredentialReport`: despite its name, generation starts a server-side job and
creates account state. When no fresh report exists, password-enabled facts are `unknown`; user access
key age and MFA posture still come from `ListAccessKeys` and `ListMFADevices`.

The AWS `SecurityAudit` managed policy happens to include `iam:GenerateCredentialReport`, but the
MultiCloudShield operation allowlist excludes it and tests enforce that exclusion.

## Safe verification

Run the connection verification before a scan. It calls the identity probe and one inexpensive read
per collector. A partially permitted identity returns a degraded capability report naming the
missing permission. Missing boto3, missing credentials, expired sessions, account mismatches, and
provider errors fail with normalized errors; SDK exceptions and credential values are not returned.

For production deployments, put cloud credentials only in the worker process, keep boto3 debug
logging disabled, and restrict worker egress to the AWS control-plane endpoints for the selected
partition.
