package intent.tf.row_333

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "role_exists",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "quote": "creates an IAM service role"
  },
  {
   "id": "role_name",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "eks-cluster-sadcloud-example"
   },
   "quote": "named \"eks-cluster-sadcloud-example\""
  },
  {
   "id": "trust_eks",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "eks.amazonaws.com"
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
        "value": "aws_iam_role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "eks.amazonaws.com"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
         "statement"
        ],
        "op": "contains",
        "value": "eks.amazonaws.com"
       }
      ]
     }
    }
   ],
   "quote": "that the Amazon EKS service can assume",
   "justify": "EKS service assumes via the eks.amazonaws.com principal"
  },
  {
   "id": "cluster_policy",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "eks-cluster-sadcloud-example"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "(?i)(^|/)AmazonEKSClusterPolicy$"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "(?i)(^|/)AmazonEKSClusterPolicy$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)(^|/)AmazonEKSClusterPolicy$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "eks-cluster-sadcloud-example"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "(?i)(^|/)AmazonEKSClusterPolicy$"
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
        "value": "aws_iam_role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "managed_policy_arns"
      ],
      "op": "regex",
      "value": "(?i)/AmazonEKSClusterPolicy\\b"
     }
    }
   ],
   "quote": "AmazonEKSClusterPolicy"
  },
  {
   "id": "service_policy",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "eks-cluster-sadcloud-example"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "(?i)(^|/)AmazonEKSServicePolicy$"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "(?i)(^|/)AmazonEKSServicePolicy$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)(^|/)AmazonEKSServicePolicy$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "eks-cluster-sadcloud-example"
       }
      ]
     },
     "cond": {
      "path": [
       "policy_arn"
      ],
      "op": "regex",
      "value": "(?i)(^|/)AmazonEKSServicePolicy$"
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
        "value": "aws_iam_role"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "managed_policy_arns"
      ],
      "op": "regex",
      "value": "(?i)/AmazonEKSServicePolicy\\b"
     }
    }
   ],
   "quote": "AmazonEKSServicePolicy"
  },
  {
   "id": "extra_type_aws_eks_cluster",
   "kind": "exists",
   "tier": "extra",
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
      "value": "aws_eks_cluster"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
