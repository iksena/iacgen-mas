package intent.cfn.row_071

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "iam_any": {
   "types": [
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  },
  "doc": {
   "types": [
    "AWS::SSM::Document"
   ],
   "where": [
    {
     "path": [
      "DocumentType"
     ],
     "op": "eq",
     "value": "Automation"
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
   "quote": "creates a prerequisite IAM role"
  },
  {
   "id": "role_name_prefix_region",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "RoleName"
    ],
    "op": "regex",
    "value": "(?i)^pciautomationassumerole.*us-east-1$"
   },
   "tier": "core",
   "quote": "the role must be named with a prefix of pciautomationassumerole followed by the region",
   "justify": "\"followed by the region\" = AWS::Region, which resolves to us-east-1"
  },
  {
   "id": "role_trust_services",
   "kind": "all_of",
   "tier": "detail",
   "quote": "trust SSM, EC2, and Events services",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "AssumeRolePolicyDocument"
      ],
      "op": "contains",
      "value": "ssm.amazonaws.com"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "AssumeRolePolicyDocument"
      ],
      "op": "contains",
      "value": "ec2.amazonaws.com"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "AssumeRolePolicyDocument"
      ],
      "op": "contains",
      "value": "events.amazonaws.com"
     }
    }
   ]
  },
  {
   "id": "policy_ec2_actions",
   "kind": "all_of",
   "tier": "detail",
   "quote": "include a policy granting only the specific ec2 actions needed by these scripts (releasing addresses, describing and deleting security groups, and revoking security group ingress and egress rules)",
   "checks": [
    {
     "kind": "attr",
     "select": "iam_any",
     "cond": {
      "path": [
       "*"
      ],
      "op": "contains",
      "value": "ec2:ReleaseAddress"
     }
    },
    {
     "kind": "attr",
     "select": "iam_any",
     "cond": {
      "path": [
       "*"
      ],
      "op": "contains",
      "value": "ec2:DescribeSecurityGroups"
     }
    },
    {
     "kind": "attr",
     "select": "iam_any",
     "cond": {
      "path": [
       "*"
      ],
      "op": "contains",
      "value": "ec2:DeleteSecurityGroup"
     }
    },
    {
     "kind": "attr",
     "select": "iam_any",
     "cond": {
      "path": [
       "*"
      ],
      "op": "contains",
      "value": "ec2:RevokeSecurityGroupIngress"
     }
    },
    {
     "kind": "attr",
     "select": "iam_any",
     "cond": {
      "path": [
       "*"
      ],
      "op": "contains",
      "value": "ec2:RevokeSecurityGroupEgress"
     }
    }
   ]
  },
  {
   "id": "automation_documents",
   "kind": "exists",
   "select": "doc",
   "min": 4,
   "tier": "core",
   "quote": "a set of custom AWS Systems Manager Automation documents",
   "justify": "the prompt enumerates four separate documents (restrict default SG, delete unused SGs, release EIPs, ASG health check)"
  },
  {
   "id": "doc_restrict_default_sg",
   "kind": "all_of",
   "tier": "core",
   "quote": "a document to restrict VPC default security group traffic by revoking all ingress and egress rules",
   "checks": [
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)revoke_?(security_?group_?)?ingress"
     }
    },
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "Content"
      ],
      "op": "regex",
      "value": "(?i)revoke_?(security_?group_?)?egress"
     }
    }
   ]
  },
  {
   "id": "doc_delete_sg",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)delete_?security_?group"
   },
   "tier": "core",
   "quote": "a document to delete unused security groups"
  },
  {
   "id": "doc_release_eip",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)release_?address"
   },
   "tier": "core",
   "quote": "a document to release unassociated Elastic IP addresses"
  },
  {
   "id": "doc_release_eip_allocation_id",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)release_?address(?s:.)*allocation_?id|allocation_?id(?s:.)*release_?address"
   },
   "tier": "detail",
   "quote": "using their allocation IDs"
  },
  {
   "id": "doc_asg_health_check_elb",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)HealthCheckType\\\\?['\"]?\\s*[=:]\\s*\\\\?['\"]?ELB"
   },
   "tier": "core",
   "quote": "a document to update an auto scaling group's health check type to ELB"
  },
  {
   "id": "doc_asg_grace_period_300",
   "kind": "attr",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)HealthCheckGracePeriod\\\\?['\"]?\\s*[=:]\\s*\\\\?['\"]?300\\b"
   },
   "tier": "detail",
   "quote": "with a grace period of 300 seconds"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
