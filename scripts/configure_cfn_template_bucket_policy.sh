#!/usr/bin/env bash
set -euo pipefail

bucket="${AWS_CFN_TEMPLATE_BUCKET:-}"
region="${AWS_REGION:-us-east-1}"

if [ -z "${bucket}" ]; then
  echo "AWS_CFN_TEMPLATE_BUCKET is required." >&2
  exit 1
fi
if ! [[ "${bucket}" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]]; then
  echo "AWS_CFN_TEMPLATE_BUCKET must be a valid S3 bucket name." >&2
  exit 1
fi
if ! [[ "${region}" =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$ ]]; then
  echo "AWS_REGION must be an AWS region such as us-east-1." >&2
  exit 1
fi

case "${region}" in
  cn-*) partition="aws-cn" ;;
  us-gov-*) partition="aws-us-gov" ;;
  *) partition="aws" ;;
esac

template_resource="arn:${partition}:s3:::${bucket}/connectors/aws/sha256/*"
statement_sid="IdentrailCloudFormationTemplatePublicRead"
temp_dir="$(mktemp -d)"
trap 'rm -rf -- "${temp_dir}"' EXIT

policy_error="${temp_dir}/get-policy.err"
if ! policy_json="$(
  aws s3api get-bucket-policy \
    --bucket "${bucket}" \
    --region "${region}" \
    --query Policy \
    --output text 2>"${policy_error}"
)"; then
  if grep -qi "NoSuchBucketPolicy\|PolicyNotFound\|404" "${policy_error}"; then
    policy_json='{"Version":"2012-10-17","Statement":[]}'
  else
    cat "${policy_error}" >&2
    exit 1
  fi
fi

if ! jq -e 'type == "object"' >/dev/null <<<"${policy_json}"; then
  echo "The existing bucket policy is not a JSON object; refusing to replace it." >&2
  exit 1
fi

merged_policy="${temp_dir}/bucket-policy.json"
jq \
  --arg statement_sid "${statement_sid}" \
  --arg template_resource "${template_resource}" \
  '
    .Version = (.Version // "2012-10-17")
    | .Statement = (
        if .Statement == null then []
        elif (.Statement | type) == "array" then .Statement
        elif (.Statement | type) == "object" then [.Statement]
        else error("Statement must be an object or array")
        end
        | map(select((.Sid // "") != $statement_sid))
        + [{
            "Sid": $statement_sid,
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": $template_resource
          }]
      )
  ' <<<"${policy_json}" >"${merged_policy}"

aws s3api put-bucket-policy \
  --bucket "${bucket}" \
  --region "${region}" \
  --policy "file://${merged_policy}"

echo "Configured public read for ${template_resource}."
echo "Existing bucket policy statements were preserved; ACLs were not changed."
