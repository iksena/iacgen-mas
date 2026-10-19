package intent.tf.row_084

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "standard_cmk_created",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "quote": "a standard customer-managed KMS key with AWS-provided key material"
  },
  {
   "id": "default_root_policy",
   "kind": "any_of",
   "tier": "detail",
   "quote": "supporting a default root policy",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)arn:aws:iam::[0-9]{12}:root"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_kms_key",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i):root"
       }
      ]
     }
    }
   ],
   "justify": "the key policy may be built in a policy document/local, so the declared text is read"
  },
  {
   "id": "external_key_supported",
   "kind": "exists",
   "tier": "core",
   "quote": "an external KMS key with base64 key material",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_kms_external_key"
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "key_material_base64"
     }
    ]
   }
  },
  {
   "id": "replica_key_supported",
   "kind": "exists",
   "tier": "core",
   "quote": "a standard multi-region replica key referencing a primary key ARN",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_kms_replica_key"
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "primary_key_arn"
     }
    ]
   }
  },
  {
   "id": "replica_external_key_supported",
   "kind": "exists",
   "tier": "core",
   "quote": "a replica external key with custom key material and primary external key ARN",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_kms_replica_external_key"
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "key_material_base64"
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "primary_key_arn"
     }
    ]
   }
  },
  {
   "id": "aliases_supported",
   "kind": "all_of",
   "tier": "detail",
   "quote": "the module should provision KMS aliases using exact names or name prefixes",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_kms_alias"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "\"name\":"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_kms_alias"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "name_prefix"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "grants_supported",
   "kind": "exists",
   "tier": "detail",
   "quote": "KMS grants with grantee principals, allowed operations, retiring principals",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_kms_grant"
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "grantee_principal"
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "operations"
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "retiring_principal"
     }
    ]
   }
  },
  {
   "id": "grant_encryption_context_subset",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_kms_grant"
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "encryption_context_subset"
     }
    ]
   },
   "quote": "optional encryption context constraint subsets"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
