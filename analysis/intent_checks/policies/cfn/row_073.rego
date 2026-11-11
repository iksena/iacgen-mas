package intent.cfn.row_073

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "buckets": {
   "types": [
    "AWS::S3::Bucket"
   ],
   "where": []
  },
  "primary": {
   "types": [
    "AWS::S3::Bucket"
   ],
   "where": [
    {
     "path": [
      "ReplicationConfiguration"
     ],
     "op": "present"
    }
   ]
  },
  "bpol": {
   "types": [
    "AWS::S3::BucketPolicy"
   ],
   "where": []
  },
  "repl_role": {
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
     "value": "s3.amazonaws.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "three_buckets",
   "kind": "exists",
   "tier": "core",
   "quote": "along with a separate access log bucket and a same-region replica bucket",
   "select": "buckets",
   "min": 3,
   "justify": "primary + log + replica = three buckets"
  },
  {
   "id": "sse",
   "kind": "any_of",
   "tier": "core",
   "quote": "server-side encryption using AES256",
   "checks": [
    {
     "kind": "attr",
     "select": "primary",
     "cond": {
      "path": [
       "BucketEncryption",
       "ServerSideEncryptionConfiguration",
       "*",
       "ServerSideEncryptionByDefault",
       "SSEAlgorithm"
      ],
      "op": "eq",
      "value": "AES256"
     }
    },
    {
     "kind": "attr",
     "select": "buckets",
     "quantifier": "all",
     "cond": {
      "path": [
       "BucketEncryption",
       "ServerSideEncryptionConfiguration",
       "*",
       "ServerSideEncryptionByDefault",
       "SSEAlgorithm"
      ],
      "op": "eq",
      "value": "AES256"
     }
    }
   ]
  },
  {
   "id": "versioning",
   "kind": "any_of",
   "tier": "core",
   "quote": "versioning enabled",
   "checks": [
    {
     "kind": "attr",
     "select": "primary",
     "cond": {
      "path": [
       "VersioningConfiguration",
       "Status"
      ],
      "op": "eq",
      "value": "Enabled"
     }
    },
    {
     "kind": "attr",
     "select": "buckets",
     "quantifier": "all",
     "cond": {
      "path": [
       "VersioningConfiguration",
       "Status"
      ],
      "op": "eq",
      "value": "Enabled"
     }
    }
   ]
  },
  {
   "id": "pab",
   "kind": "any_of",
   "tier": "core",
   "quote": "public access blocked",
   "justify": "blocked public access implies all four settings",
   "checks": [
    {
     "kind": "attr",
     "select": "primary",
     "cond": {
      "path": [
       "PublicAccessBlockConfiguration"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "BlockPublicAcls"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "BlockPublicPolicy"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "IgnorePublicAcls"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "RestrictPublicBuckets"
        ],
        "op": "eq",
        "value": true
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "buckets",
     "quantifier": "all",
     "cond": {
      "path": [
       "PublicAccessBlockConfiguration"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "BlockPublicAcls"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "BlockPublicPolicy"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "IgnorePublicAcls"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "RestrictPublicBuckets"
        ],
        "op": "eq",
        "value": true
       }
      ]
     }
    }
   ]
  },
  {
   "id": "secure_transport",
   "kind": "any_of",
   "tier": "core",
   "quote": "a bucket policy that denies requests without secure transport",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::S3::BucketPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Effect"
          ],
          "op": "eq",
          "value": "Deny"
         },
         {
          "path": [
           "Condition"
          ],
          "op": "regex",
          "value": "(?i)SecureTransport\\W+false"
         }
        ]
       }
      ]
     },
     "to": "primary"
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::S3::BucketPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Effect"
          ],
          "op": "eq",
          "value": "Deny"
         },
         {
          "path": [
           "Condition"
          ],
          "op": "regex",
          "value": "(?i)SecureTransport\\W+false"
         }
        ]
       }
      ]
     },
     "from_path": [
      "Bucket"
     ],
     "to": "primary",
     "to_path": [
      "BucketName"
     ]
    },
    {
     "kind": "attr",
     "select": "bpol",
     "quantifier": "all",
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Effect"
        ],
        "op": "eq",
        "value": "Deny"
       },
       {
        "path": [
         "Condition"
        ],
        "op": "regex",
        "value": "(?i)SecureTransport\\W+false"
       }
      ]
     }
    }
   ],
   "justify": "denying requests without secure transport means Effect Deny on aws:SecureTransport false"
  },
  {
   "id": "logging_policies",
   "kind": "exists",
   "tier": "core",
   "quote": "include bucket policies on all three buckets that allow the S3 logging service to deliver access logs",
   "justify": "one policy per each of three buckets",
   "select": {
    "types": [
     "AWS::S3::BucketPolicy"
    ],
    "where": [
     {
      "path": [
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Effect"
        ],
        "op": "eq",
        "value": "Allow"
       },
       {
        "path": [
         "Principal",
         "Service",
         "*"
        ],
        "op": "eq",
        "value": "logging.s3.amazonaws.com"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:PutObject"
       }
      ]
     }
    ]
   },
   "min": 3
  },
  {
   "id": "logging_ref",
   "kind": "attr",
   "tier": "core",
   "quote": "a separate access log bucket",
   "select": "primary",
   "cond": {
    "path": [
     "LoggingConfiguration",
     "DestinationBucketName"
    ],
    "op": "present"
   }
  },
  {
   "id": "replication_cfg",
   "kind": "attr",
   "tier": "core",
   "quote": "a same-region replica bucket",
   "select": "primary",
   "cond": {
    "path": [
     "ReplicationConfiguration",
     "Rules",
     "*",
     "Destination",
     "Bucket"
    ],
    "op": "present"
   }
  },
  {
   "id": "app_param",
   "kind": "attr",
   "tier": "core",
   "quote": "a parameter for the application name with a default of \"testanu\"",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "testanu"
   }
  },
  {
   "id": "repl_role",
   "kind": "exists",
   "tier": "core",
   "quote": "provision an IAM role with an attached policy granting the necessary S3 replication permissions",
   "select": "repl_role"
  },
  {
   "id": "repl_perm",
   "kind": "any_of",
   "tier": "core",
   "quote": "granting the necessary S3 replication permissions",
   "justify": "replication permissions imply s3:ReplicateObject",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "repl_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "s3:ReplicateObject"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "repl_role",
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
      "value": "s3:ReplicateObject"
     }
    }
   ]
  },
  {
   "id": "repl_role_ref",
   "kind": "ref",
   "tier": "detail",
   "quote": "IAM role with an attached policy granting the necessary S3 replication permissions",
   "from": "primary",
   "to": "repl_role"
  },
  {
   "id": "repl_get",
   "kind": "any_of",
   "tier": "detail",
   "quote": "necessary S3 replication permissions",
   "justify": "source-read permissions are part of replication",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "repl_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "s3:GetObjectVersionForReplication"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "repl_role",
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
      "value": "s3:GetObjectVersionForReplication"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "repl_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "s3:GetReplicationConfiguration"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "repl_role",
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
      "value": "s3:GetReplicationConfiguration"
     }
    }
   ]
  },
  {
   "id": "x_replica_versioning",
   "kind": "attr",
   "tier": "extra",
   "select": "buckets",
   "quantifier": "all",
   "cond": {
    "path": [
     "VersioningConfiguration",
     "Status"
    ],
    "op": "eq",
    "value": "Enabled"
   }
  },
  {
   "id": "x_pab_all",
   "kind": "attr",
   "tier": "extra",
   "select": "buckets",
   "quantifier": "all",
   "cond": {
    "path": [
     "PublicAccessBlockConfiguration",
     "BlockPublicAcls"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "x_sse_all",
   "kind": "attr",
   "tier": "extra",
   "select": "buckets",
   "quantifier": "all",
   "cond": {
    "path": [
     "BucketEncryption",
     "ServerSideEncryptionConfiguration",
     "*",
     "ServerSideEncryptionByDefault",
     "SSEAlgorithm"
    ],
    "op": "eq",
    "value": "AES256"
   }
  },
  {
   "id": "x_rule_enabled",
   "kind": "attr",
   "tier": "extra",
   "select": "primary",
   "cond": {
    "path": [
     "ReplicationConfiguration",
     "Rules",
     "*",
     "Status"
    ],
    "op": "eq",
    "value": "Enabled"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
