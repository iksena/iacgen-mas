package intent.cfn.row_027

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "db": {
   "types": [
    "AWS::Glue::Database"
   ],
   "where": []
  },
  "cr": {
   "types": [
    "AWS::Glue::Crawler"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "db",
   "kind": "exists",
   "select": "db",
   "tier": "core",
   "quote": "a Glue database"
  },
  {
   "id": "crawler",
   "kind": "exists",
   "select": "cr",
   "tier": "core",
   "quote": "a Glue crawler"
  },
  {
   "id": "db_suffix",
   "kind": "attr",
   "select": "db",
   "cond": {
    "path": [
     "DatabaseInput",
     "Name"
    ],
    "op": "regex",
    "value": "-kk-admin-db$"
   },
   "tier": "core",
   "quote": "The database name should end with the suffix -kk-admin-db"
  },
  {
   "id": "table_prefix",
   "kind": "attr",
   "select": "cr",
   "cond": {
    "path": [
     "TablePrefix"
    ],
    "op": "eq",
    "value": "cloudtrail_"
   },
   "tier": "core",
   "quote": "the crawler's table names should be prefixed with cloudtrail_"
  },
  {
   "id": "crawl_path",
   "kind": "attr",
   "select": "cr",
   "cond": {
    "path": [
     "Targets",
     "S3Targets",
     "*",
     "Path"
    ],
    "op": "contains",
    "value": "cloud-trail/AWSLogs/"
   },
   "tier": "core",
   "quote": "CloudTrail logs stored under the prefix cloud-trail/AWSLogs/ in that bucket"
  },
  {
   "id": "role",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "a newly provisioned IAM role"
  },
  {
   "id": "crawler_role",
   "kind": "ref",
   "from": "cr",
   "to": "role",
   "tier": "core",
   "quote": "the crawler should use a newly provisioned IAM role"
  },
  {
   "id": "glue_managed",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "contains",
    "value": "AWSGlueServiceRole"
   },
   "tier": "core",
   "quote": "the AWSGlueServiceRole managed policy"
  },
  {
   "id": "role_s3_access",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "s3:GetObject"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:GetObject"
       }
      ]
     },
     "to": "role"
    }
   ],
   "quote": "plus permissions to access that S3 bucket",
   "justify": "access to the bucket for a crawler means at least reading its objects"
  },
  {
   "id": "crawler_db",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": "cr",
     "to": "db"
    },
    {
     "kind": "join",
     "from": "cr",
     "from_path": [
      "DatabaseName"
     ],
     "to": "db",
     "to_path": [
      "DatabaseInput",
      "Name"
     ]
    }
   ],
   "quote": "a Glue database, and a Glue crawler to catalog AWS CloudTrail logs"
  },
  {
   "id": "x_trust_glue",
   "kind": "attr",
   "select": "role",
   "tier": "extra",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "regex",
    "value": "glue\\.amazonaws\\.com"
   }
  },
  {
   "id": "x_s3_list",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "s3:ListBucket"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:ListBucket"
       }
      ]
     },
     "to": "role"
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
