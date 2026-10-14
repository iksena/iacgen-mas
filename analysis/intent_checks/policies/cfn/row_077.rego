# GENERATED from specs/cfn/row_077.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_077

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "svc": {
   "types": [
    "AWS::AppRunner::Service"
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
  "build_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "eq",
     "value": "build.apprunner.amazonaws.com"
    }
   ]
  },
  "task_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "eq",
     "value": "tasks.apprunner.amazonaws.com"
    }
   ]
  },
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "apprunner_service",
   "kind": "exists",
   "select": "svc",
   "tier": "core",
   "quote": "creates an AWS App Runner service"
  },
  {
   "id": "build_role",
   "kind": "exists",
   "select": "build_role",
   "tier": "core",
   "quote": "a build role with permissions to access ECR",
   "justify": "App Runner's ECR access (build) role is assumed by build.apprunner.amazonaws.com"
  },
  {
   "id": "build_role_ecr_auth_and_pull",
   "kind": "all_of",
   "tier": "core",
   "quote": "including GetAuthorizationToken and image pull operations",
   "checks": [
    {
     "kind": "attr",
     "select": "iam_any",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ecr:(GetAuthorizationToken|\\*)|AWSAppRunnerServicePolicyForECRAccess"
     }
    },
    {
     "kind": "attr",
     "select": "iam_any",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)ecr:(BatchGetImage|GetDownloadUrlForLayer|BatchGet\\*|Get\\*|\\*)|AWSAppRunnerServicePolicyForECRAccess"
     }
    }
   ]
  },
  {
   "id": "task_role",
   "kind": "exists",
   "select": "task_role",
   "tier": "core",
   "quote": "a task role with permissions to call Directory Service and QuickSight APIs",
   "justify": "an App Runner task/instance role is assumed by tasks.apprunner.amazonaws.com"
  },
  {
   "id": "task_role_ds_quicksight_actions",
   "kind": "all_of",
   "tier": "core",
   "quote": "permissions to call Directory Service and QuickSight APIs (such as CreateNamespace, CreateDataSet, RegisterUser, and related actions)",
   "checks": [
    {
     "kind": "attr",
     "select": "iam_any",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)\\bds:[A-Za-z*]"
     }
    },
    {
     "kind": "attr",
     "select": "iam_any",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)quicksight:(CreateNamespace|Create\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "iam_any",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)quicksight:(CreateDataSet|Create\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "iam_any",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)quicksight:(RegisterUser|Register\\*|\\*)"
     }
    }
   ]
  },
  {
   "id": "service_uses_task_role",
   "kind": "ref",
   "from": "svc",
   "to": "task_role",
   "tier": "detail",
   "quote": "a task role with permissions to call Directory Service and QuickSight APIs"
  },
  {
   "id": "env_allow_ip_range",
   "kind": "attr",
   "select": "svc",
   "cond": {
    "path": [
     "SourceConfiguration"
    ],
    "op": "regex",
    "value": "(?is)ALLOW_IP_RANGE.{0,60}?0\\.0\\.0\\.0/0"
   },
   "tier": "core",
   "quote": "ALLOW_IP_RANGE set to 0.0.0.0/0"
  },
  {
   "id": "env_region_and_account",
   "kind": "all_of",
   "tier": "detail",
   "quote": "the AWS region and account ID",
   "justify": "the stack's own region/account pseudo-parameters resolve to us-east-1 / 123456789012",
   "checks": [
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "SourceConfiguration"
      ],
      "op": "contains",
      "value": "us-east-1"
     }
    },
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "SourceConfiguration"
      ],
      "op": "contains",
      "value": "123456789012"
     }
    }
   ]
  },
  {
   "id": "env_email_and_admin",
   "kind": "all_of",
   "tier": "detail",
   "quote": "a dummy email placeholder, an admin user name",
   "checks": [
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "SourceConfiguration"
      ],
      "op": "regex",
      "value": "(?i)e-?mail"
     }
    },
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "SourceConfiguration"
      ],
      "op": "regex",
      "value": "(?i)admin"
     }
    }
   ]
  },
  {
   "id": "env_quicksight_identifiers",
   "kind": "all_of",
   "tier": "detail",
   "quote": "template, dataset, datasource, database, table, and filter column identifiers",
   "checks": [
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "SourceConfiguration"
      ],
      "op": "regex",
      "value": "(?i)template"
     }
    },
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "SourceConfiguration"
      ],
      "op": "regex",
      "value": "(?i)data_?set"
     }
    },
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "SourceConfiguration"
      ],
      "op": "regex",
      "value": "(?i)data_?source"
     }
    },
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "SourceConfiguration"
      ],
      "op": "regex",
      "value": "(?i)database"
     }
    },
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "SourceConfiguration"
      ],
      "op": "regex",
      "value": "(?i)table"
     }
    },
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "SourceConfiguration"
      ],
      "op": "regex",
      "value": "(?i)filter"
     }
    }
   ]
  },
  {
   "id": "output_service_url",
   "kind": "ref",
   "from": "out",
   "to": "svc",
   "tier": "detail",
   "quote": "the App Runner service URL"
  },
  {
   "id": "output_image_uri",
   "kind": "any_of",
   "tier": "detail",
   "quote": "outputting the generated image URI",
   "checks": [
    {
     "kind": "attr",
     "select": "out",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)image"
     }
    },
    {
     "kind": "attr",
     "select": "out",
     "cond": {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "(?i)ecr|RepositoryUri"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
