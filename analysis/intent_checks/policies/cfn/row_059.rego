package intent.cfn.row_059

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "bk": {
   "types": [
    "AWS::S3::Bucket"
   ],
   "where": []
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
   "id": "buckets",
   "kind": "exists",
   "tier": "core",
   "quote": "a source bucket, a target bucket",
   "select": "bk",
   "min": 2,
   "justify": "source and target buckets are always created; the EMR one is optional"
  },
  {
   "id": "optional_emr_bucket",
   "kind": "exists",
   "tier": "core",
   "quote": "an optional EMR log bucket that is only created when a parameter is set to true",
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
      "value": "AWS::S3::Bucket"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "bool_param",
   "kind": "any_of",
   "tier": "detail",
   "quote": "only created when a parameter is set to true",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "default"
        ],
        "op": "in",
        "value": [
         "true",
         "false"
        ]
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "allowed_values",
         "*"
        ],
        "op": "eq",
        "value": "true"
       }
      ]
     }
    }
   ],
   "justify": "a parameter that can be set to true holds true/false"
  },
  {
   "id": "private",
   "kind": "any_of",
   "tier": "core",
   "quote": "private S3 buckets",
   "justify": "private means AccessControl Private or public access blocked",
   "checks": [
    {
     "kind": "attr",
     "select": "bk",
     "quantifier": "all",
     "cond": {
      "path": [
       "AccessControl"
      ],
      "op": "eq",
      "value": "Private"
     }
    },
    {
     "kind": "attr",
     "select": "bk",
     "quantifier": "all",
     "cond": {
      "path": [
       "PublicAccessBlockConfiguration",
       "BlockPublicAcls"
      ],
      "op": "truthy"
     }
    }
   ]
  },
  {
   "id": "lifecycle_expire",
   "kind": "attr",
   "tier": "core",
   "quote": "expire objects after 2555 days",
   "select": "bk",
   "quantifier": "all",
   "cond": {
    "path": [
     "LifecycleConfiguration",
     "Rules",
     "*",
     "ExpirationInDays"
    ],
    "op": "eq",
    "value": 2555
   }
  },
  {
   "id": "lifecycle_transition_days",
   "kind": "any_of",
   "tier": "core",
   "quote": "transition objects to either STANDARD_IA or GLACIER storage class after 90 days",
   "checks": [
    {
     "kind": "attr",
     "select": "bk",
     "quantifier": "all",
     "cond": {
      "path": [
       "LifecycleConfiguration",
       "Rules",
       "*",
       "Transition",
       "TransitionInDays"
      ],
      "op": "eq",
      "value": 90
     }
    },
    {
     "kind": "attr",
     "select": "bk",
     "quantifier": "all",
     "cond": {
      "path": [
       "LifecycleConfiguration",
       "Rules",
       "*",
       "Transitions",
       "*",
       "TransitionInDays"
      ],
      "op": "eq",
      "value": 90
     }
    }
   ]
  },
  {
   "id": "lifecycle_transition_class",
   "kind": "any_of",
   "tier": "core",
   "quote": "transition objects to either STANDARD_IA or GLACIER storage class",
   "checks": [
    {
     "kind": "attr",
     "select": "bk",
     "quantifier": "all",
     "cond": {
      "path": [
       "LifecycleConfiguration",
       "Rules",
       "*",
       "Transition",
       "StorageClass"
      ],
      "op": "in",
      "value": [
       "STANDARD_IA",
       "GLACIER"
      ]
     }
    },
    {
     "kind": "attr",
     "select": "bk",
     "quantifier": "all",
     "cond": {
      "path": [
       "LifecycleConfiguration",
       "Rules",
       "*",
       "Transitions",
       "*",
       "StorageClass"
      ],
      "op": "in",
      "value": [
       "STANDARD_IA",
       "GLACIER"
      ]
     }
    }
   ]
  },
  {
   "id": "lifecycle_enabled_emr_only",
   "kind": "attr",
   "tier": "core",
   "quote": "the lifecycle rule should be enabled only on the EMR log bucket",
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
      "value": "AWS::S3::Bucket"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "LifecycleConfiguration",
     "Rules",
     "*",
     "Status"
    ],
    "op": "eq",
    "value": "Enabled"
   }
  },
  {
   "id": "lifecycle_disabled_others",
   "kind": "attr",
   "tier": "core",
   "quote": "the lifecycle rule should be enabled only on the EMR log bucket",
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
      "value": "AWS::S3::Bucket"
     },
     {
      "path": [
       "gated"
      ],
      "op": "falsy"
     }
    ]
   },
   "quantifier": "all",
   "cond": {
    "path": [
     "properties",
     "LifecycleConfiguration",
     "Rules",
     "*",
     "Status"
    ],
    "op": "eq",
    "value": "Disabled"
   },
   "justify": "'enabled only on the EMR log bucket' means disabled on the others"
  },
  {
   "id": "exports",
   "kind": "exists",
   "tier": "detail",
   "quote": "the template must export the bucket names",
   "justify": "source and target bucket names are always created; the EMR bucket is optional",
   "select": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "export"
      ],
      "op": "present"
     }
    ]
   },
   "min": 2
  },
  {
   "id": "outputs_ref_buckets",
   "kind": "ref",
   "tier": "detail",
   "quote": "export the bucket names",
   "from": "out",
   "to": "bk"
  },
  {
   "id": "x_encryption",
   "kind": "attr",
   "tier": "extra",
   "select": "bk",
   "quantifier": "all",
   "cond": {
    "path": [
     "BucketEncryption"
    ],
    "op": "present"
   }
  },
  {
   "id": "x_public_block",
   "kind": "attr",
   "tier": "extra",
   "select": "bk",
   "quantifier": "all",
   "cond": {
    "path": [
     "PublicAccessBlockConfiguration",
     "BlockPublicAcls"
    ],
    "op": "truthy"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
