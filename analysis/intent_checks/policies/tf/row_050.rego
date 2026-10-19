package intent.tf.row_050

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "contains",
     "value": "sts:AssumeRole"
    }
   ]
  },
  "aps_policy": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "policy"
     ],
     "op": "regex",
     "value": "(?i)aps:(QueryMetrics|\\*)"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "role_exists",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "creates an IAM role",
   "justify": "an IAM role trust policy (\"assumption of the role\") implies sts:AssumeRole; substring match only"
  },
  {
   "id": "trust_restricted_to_accounts",
   "kind": "any_of",
   "tier": "core",
   "quote": "restricting assumption of the role to specified monitoring AWS accounts",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)\"Principal\":\\{\"AWS\":\\[?\"(arn:aws:iam::)?[0-9]{12}"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)aws:(SourceAccount|PrincipalAccount)"
     }
    }
   ],
   "justify": "an IAM role trust policy (\"assumption of the role\") implies sts:AssumeRole; substring match only"
  },
  {
   "id": "prometheus_query_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "custom policy allowing an AWS Managed Grafana workspace named \"Grafana\" to query Amazon Managed Service for Prometheus",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "to": "aps_policy"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)aps:(QueryMetrics|\\*)"
       }
      ]
     },
     "to": "role"
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)aps:(QueryMetrics|\\*)"
     }
    }
   ],
   "justify": "an IAM role trust policy (\"assumption of the role\") implies sts:AssumeRole; substring match only"
  },
  {
   "id": "policy_attached_to_role",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an IAM role and custom policy",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": []
     },
     "to": "role"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "to": "role"
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "present"
     }
    }
   ],
   "justify": "an IAM role trust policy (\"assumption of the role\") implies sts:AssumeRole; substring match only"
  },
  {
   "id": "cloudwatch_metrics_access",
   "kind": "any_of",
   "tier": "core",
   "quote": "query Amazon Managed Service for Prometheus and CloudWatch metrics",
   "checks": [
    {
     "kind": "ref",
     "to": "role",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "cloudwatch"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "cloudwatch:"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "contains",
      "value": "cloudwatch:"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "contains",
      "value": "cloudwatch"
     }
    }
   ],
   "justify": "an IAM role trust policy (\"assumption of the role\") implies sts:AssumeRole; substring match only"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
