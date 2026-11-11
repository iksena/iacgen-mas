package intent.cfn.row_089

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "rule": {
   "types": [
    "AWS::SecurityHub::AutomationRule"
   ],
   "where": []
  },
  "iam_rule": {
   "types": [
    "AWS::SecurityHub::AutomationRule"
   ],
   "where": [
    {
     "path": [
      "Criteria",
      "AwsAccountId"
     ],
     "op": "absent"
    },
    {
     "path": [
      "Criteria"
     ],
     "op": "regex",
     "value": "(?i)(\\biam\\b|awsiam)"
    }
   ]
  },
  "broad": {
   "types": [
    "AWS::SecurityHub::AutomationRule"
   ],
   "where": [
    {
     "path": [
      "Criteria",
      "AwsAccountId"
     ],
     "op": "absent"
    },
    {
     "path": [
      "Criteria",
      "ResourceId",
      "*"
     ],
     "op": "absent"
    },
    {
     "path": [
      "Criteria"
     ],
     "op": "regex",
     "value": "(?i)(cis|foundational|\\b(ec2|s3|iam|config)\\.\\d)"
    },
    {
     "path": [
      "Criteria",
      "ProductName",
      "*",
      "Value"
     ],
     "op": "none_eq",
     "value": "GuardDuty"
    }
   ]
  },
  "bucket_rule": {
   "types": [
    "AWS::SecurityHub::AutomationRule"
   ],
   "where": [
    {
     "path": [
      "Criteria",
      "ResourceId"
     ],
     "op": "len_gte",
     "value": 2
    },
    {
     "path": [
      "Criteria"
     ],
     "op": "regex",
     "value": "(?i)s3"
    }
   ]
  },
  "gd_rule": {
   "types": [
    "AWS::SecurityHub::AutomationRule"
   ],
   "where": [
    {
     "path": [],
     "op": "regex",
     "value": "(?i)guard.?duty"
    }
   ]
  },
  "two_acct": {
   "types": [
    "AWS::SecurityHub::AutomationRule"
   ],
   "where": [
    {
     "path": [
      "Criteria",
      "AwsAccountId"
     ],
     "op": "len_gte",
     "value": 2
    }
   ]
  }
 },
 "checks": [
  {
   "id": "seven_rules",
   "kind": "exists",
   "tier": "core",
   "quote": "a set of automation rules on an already-enabled AWS Security Hub",
   "select": "rule",
   "min": 7,
   "justify": "the prompt lists seven distinct suppression rules"
  },
  {
   "id": "no_security_hub_created",
   "kind": "all_of",
   "tier": "core",
   "quote": "rather than creating or enabling Security Hub itself",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "type"
      ],
      "op": "none_eq",
      "value": "AWS::SecurityHub::Hub"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "type"
      ],
      "op": "none_eq",
      "value": "AWS::SecurityHub::HubV2"
     }
    }
   ],
   "justify": "creating Security Hub would need one of its hub resource types"
  },
  {
   "id": "rules_suppress",
   "kind": "attr",
   "tier": "core",
   "quote": "Each rule should update the workflow status of matching findings to suppressed",
   "select": "rule",
   "quantifier": "all",
   "cond": {
    "path": [
     "Actions",
     "*",
     "FindingFieldsUpdate",
     "Workflow",
     "Status"
    ],
    "op": "eq",
    "value": "SUPPRESSED"
   }
  },
  {
   "id": "rules_note",
   "kind": "attr",
   "tier": "detail",
   "quote": "attach an explanatory note",
   "select": "rule",
   "quantifier": "all",
   "cond": {
    "path": [
     "Actions",
     "*",
     "FindingFieldsUpdate",
     "Note",
     "Text"
    ],
    "op": "present"
   }
  },
  {
   "id": "iam_findings_rule",
   "kind": "exists",
   "tier": "core",
   "quote": "suppresses certain IAM-related findings across the organization",
   "select": "iam_rule"
  },
  {
   "id": "cis_subaccount_rule",
   "kind": "exists",
   "tier": "core",
   "quote": "a handful of CIS benchmark findings scoped to one particular designated sub-account",
   "select": {
    "types": [
     "AWS::SecurityHub::AutomationRule"
    ],
    "where": [
     {
      "path": [
       "Criteria",
       "AwsAccountId"
      ],
      "op": "len_eq",
      "value": 1
     },
     {
      "path": [],
      "op": "regex",
      "value": "(CIS|\\bcis\\b)"
     }
    ]
   },
   "justify": "one sub-account means one account id; consolidated control IDs carry no CIS token, so the rule's name or description may state it"
  },
  {
   "id": "broad_cis_fsbp_rule",
   "kind": "exists",
   "tier": "core",
   "quote": "a set of CIS and AWS Foundational Security Best Practices findings organization-wide",
   "select": "broad"
  },
  {
   "id": "broad_admin_ports",
   "kind": "attr",
   "tier": "detail",
   "quote": "findings about security groups permitting administrative ports needed for bastion hosts and testing",
   "select": "broad",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)(\\b[45]\\.[123]\\b|\\bec2\\.(2|13|14|18|19|21|53|54)\\b|security.?group|bastion|\\bssh\\b|\\brdp\\b|admin\\w*.?ports?)"
   },
   "justify": "CIS 4.x and 5.x, FSBP EC2.2/13/14/18/19/21/53/54 are the security-group port checks, or the rule says so in words"
  },
  {
   "id": "broad_s3",
   "kind": "attr",
   "tier": "detail",
   "quote": "S3 bucket public-access and HTTP-access settings",
   "select": "broad",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)(\\b2\\.1\\.[1-5]\\b|\\bs3\\b)"
   },
   "justify": "CIS 2.1.x and FSBP S3.x are the S3 checks"
  },
  {
   "id": "broad_config_regions",
   "kind": "attr",
   "tier": "detail",
   "quote": "AWS Config regional coverage",
   "select": "broad",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)(\\bconfig\\b|\\b3\\.5\\b|\\b2\\.5\\b)"
   },
   "justify": "CIS 2.5 and 3.5 and Config.1 are the AWS Config checks; the word config must stand alone, since Type values contain 'Configuration'"
  },
  {
   "id": "public_buckets_rule",
   "kind": "exists",
   "tier": "core",
   "quote": "suppresses public-access findings for a known list of buckets that are intentionally public",
   "select": "bucket_rule",
   "justify": "a list means more than one bucket"
  },
  {
   "id": "ebs_encryption_rule",
   "kind": "exists",
   "tier": "core",
   "quote": "suppresses an EBS default-encryption finding for one specific account",
   "select": {
    "types": [
     "AWS::SecurityHub::AutomationRule"
    ],
    "where": [
     {
      "path": [
       "Criteria",
       "AwsAccountId"
      ],
      "op": "len_eq",
      "value": 1
     },
     {
      "path": [],
      "op": "regex",
      "value": "(EBS|Ebs|\\bebs\\b|2\\.2\\.1|\\b[eE][cC]2\\.(3|7)\\b)"
     }
    ]
   },
   "justify": "one account means one account id; the finding is named in words or by CIS 2.2.1 or FSBP EC2.3 or EC2.7"
  },
  {
   "id": "unused_credentials_two_accounts",
   "kind": "exists",
   "tier": "core",
   "quote": "suppresses unused-credential and access-key-rotation findings for two specific accounts",
   "select": {
    "types": [
     "AWS::SecurityHub::AutomationRule"
    ],
    "where": [
     {
      "path": [
       "Criteria",
       "AwsAccountId"
      ],
      "op": "len_gte",
      "value": 2
     },
     {
      "path": [
       "Criteria"
      ],
      "op": "regex",
      "value": "(?i)(1\\.1[2-4]|iam|credential|unused|rotat)"
     }
    ]
   },
   "justify": "two accounts means at least two account ids"
  },
  {
   "id": "guardduty_rule",
   "kind": "exists",
   "tier": "core",
   "quote": "suppresses one specific GuardDuty finding type",
   "select": "gd_rule"
  },
  {
   "id": "guardduty_finding_type",
   "kind": "attr",
   "tier": "detail",
   "quote": "one specific GuardDuty finding type related to expected cross-account Bedrock API activity",
   "select": "gd_rule",
   "cond": {
    "path": [
     "Criteria",
     "Type"
    ],
    "op": "present"
   }
  },
  {
   "id": "guardduty_bedrock",
   "kind": "attr",
   "tier": "detail",
   "quote": "related to expected cross-account Bedrock API activity",
   "select": "gd_rule",
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)bedrock"
   }
  },
  {
   "id": "x_rules_enabled",
   "kind": "attr",
   "tier": "extra",
   "select": "rule",
   "quantifier": "all",
   "cond": {
    "path": [
     "RuleStatus"
    ],
    "op": "eq",
    "value": "ENABLED"
   }
  },
  {
   "id": "x_rules_active_only",
   "kind": "attr",
   "tier": "extra",
   "select": "rule",
   "quantifier": "all",
   "cond": {
    "path": [
     "Criteria",
     "RecordState",
     "*",
     "Value"
    ],
    "op": "eq",
    "value": "ACTIVE"
   }
  },
  {
   "id": "x_rules_action_type",
   "kind": "attr",
   "tier": "extra",
   "select": "rule",
   "quantifier": "all",
   "cond": {
    "path": [
     "Actions",
     "*",
     "Type"
    ],
    "op": "eq",
    "value": "FINDING_FIELDS_UPDATE"
   }
  },
  {
   "id": "x_rules_only_new_findings",
   "kind": "attr",
   "tier": "extra",
   "select": "rule",
   "quantifier": "all",
   "cond": {
    "path": [
     "Criteria",
     "WorkflowStatus",
     "*",
     "Value"
    ],
    "op": "eq",
    "value": "NEW"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
