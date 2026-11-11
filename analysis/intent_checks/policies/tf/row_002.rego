package intent.tf.row_002

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "kms_key",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "quote": "creates a symmetric AWS KMS key"
  },
  {
   "id": "kms_symmetric",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "customer_master_key_spec"
    ],
    "op": "eq",
    "value": "SYMMETRIC_DEFAULT"
   },
   "quote": "a symmetric AWS KMS key",
   "justify": "symmetric key spec is SYMMETRIC_DEFAULT"
  },
  {
   "id": "kms_usage",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "key_usage"
    ],
    "op": "eq",
    "value": "ENCRYPT_DECRYPT"
   },
   "quote": "for general encryption and decryption tasks",
   "justify": "encryption and decryption usage is ENCRYPT_DECRYPT"
  },
  {
   "id": "kms_deletion_window",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "deletion_window_in_days"
    ],
    "op": "eq",
    "value": 10
   },
   "quote": "a 10-day deletion window"
  },
  {
   "id": "kms_rotation_off",
   "kind": "all_of",
   "tier": "core",
   "quote": "explicitly disabled key rotation",
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
       "enable_key_rotation"
      ],
      "op": "eq",
      "value": false
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_kms_key"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "enable_key_rotation"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "policy_all_actions",
   "kind": "any_of",
   "tier": "core",
   "quote": "allows all actions from any AWS principal",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_kms_key",
       "aws_kms_key_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?s)\"Action\":\\[?\"(kms:)?\\*\"\\]?,\"Effect\":\"Allow\",\"Principal\":(\\{\"AWS\":\\[?)?\"\\*\""
     }
    },
    {
     "kind": "attr",
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
         "aws_kms_key_policy"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)'action':\\s*\\[?\\s*'(kms:)?\\*'[^{}]{0,40}?\\}?(?:[^{}]|\\{[^{}]*\\}){0,300}'principal':\\s*(\\{\\s*'aws':\\s*)?\\[?\\s*'\\*'|'principal':\\s*(\\{\\s*'aws':\\s*)?\\[?\\s*'\\*'[^{}]{0,40}?\\}?(?:[^{}]|\\{[^{}]*\\}){0,300}'action':\\s*\\[?\\s*'(kms:)?\\*'"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_key",
       "aws_kms_key_policy"
      ],
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "actions",
           "*"
          ],
          "op": "in",
          "value": [
           "*",
           "kms:*"
          ]
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "eq",
          "value": "*"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_any_principal",
   "kind": "any_of",
   "tier": "core",
   "quote": "allows all actions from any AWS principal",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_kms_key",
       "aws_kms_key_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?s)\"Effect\":\"Allow\",(?:\"NotAction\"[^]]*\\],)?\"Principal\":(\\{\"AWS\":\\[?)?\"\\*\""
     }
    },
    {
     "kind": "attr",
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
         "aws_kms_key_policy"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)'principal':\\s*(\\{\\s*'aws':\\s*)?\\[?\\s*'\\*'"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_key",
       "aws_kms_key_policy"
      ],
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "eq",
          "value": "*"
         }
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "alias_exists",
   "kind": "ref",
   "tier": "core",
   "quote": "assign the key an alias of \"alias/bar\"",
   "from": {
    "types": [
     "aws_kms_alias"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "alias/bar"
     }
    ]
   },
   "to": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
