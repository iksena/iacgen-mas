package intent.tf.row_322

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "role_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "creates an IAM role",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   }
  },
  {
   "id": "ec2_trust",
   "kind": "any_of",
   "tier": "core",
   "quote": "an IAM role that can be assumed by EC2",
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
      "value": "ec2.amazonaws.com"
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
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "assume_role_policy"
        ],
        "op": "contains",
        "value": "ec2.amazonaws.com"
       }
      ]
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
         "properties"
        ],
        "op": "contains",
        "value": "ec2.amazonaws.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "allow_specific_cluster",
   "kind": "any_of",
   "tier": "core",
   "quote": "one allowing \"rds:AddRoleToDBCluster\" on a single specific RDS cluster named \"foo_cluster\"",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?is)([\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*foo_cluster|[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*foo_cluster[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*foo_cluster|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*foo_cluster[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"']|foo_cluster[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|foo_cluster[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'])"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "inline_policy",
         "*",
         "policy"
        ],
        "op": "regex",
        "value": "(?is)([\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*foo_cluster|[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*foo_cluster[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*foo_cluster|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*foo_cluster[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"']|foo_cluster[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|foo_cluster[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'])"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?is)([\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*foo_cluster|[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*foo_cluster[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*foo_cluster|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*foo_cluster[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"']|foo_cluster[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|foo_cluster[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'])"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy",
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
         "properties"
        ],
        "op": "regex",
        "value": "(?is)([\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*foo_cluster|[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*foo_cluster[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*foo_cluster|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*foo_cluster[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"']|foo_cluster[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|foo_cluster[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:AddRoleToDBCluster[\"'])"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "allow_wildcard",
   "kind": "any_of",
   "tier": "core",
   "quote": "one allowing \"rds:Add*\" on all RDS clusters in any region and account",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?is)([\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'])"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "inline_policy",
         "*",
         "policy"
        ],
        "op": "regex",
        "value": "(?is)([\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'])"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?is)([\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'])"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy",
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
         "properties"
        ],
        "op": "regex",
        "value": "(?is)([\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Allow[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'])"
       }
      ]
     }
    }
   ],
   "justify": "'all RDS clusters in any region and account' is the cluster ARN with region and account wildcards (rds:*:*:cluster:*)"
  },
  {
   "id": "deny_wildcard",
   "kind": "any_of",
   "tier": "core",
   "quote": "one denying \"rds:Add*\" on all RDS clusters in any region and account",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?is)([\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"']|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'])"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "inline_policy",
         "*",
         "policy"
        ],
        "op": "regex",
        "value": "(?is)([\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"']|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'])"
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
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "(?is)([\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"']|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'])"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy",
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
         "properties"
        ],
        "op": "regex",
        "value": "(?is)([\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"']|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*rds:\\*:\\*:cluster:\\*|[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'][^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"']|rds:\\*:\\*:cluster:\\*[^{}]*[\"']?effect[\"']?\\s*[:=]\\s*[\"']Deny[\"'][^{}]*[\"']?actions?[\"']?\\s*[:=]\\s*\\[?\\s*(?:[\"'][^\"'\\]]*[\"']\\s*,\\s*)*[\"']rds:Add\\*[\"'])"
       }
      ]
     }
    }
   ],
   "justify": "'all RDS clusters in any region and account' is the cluster ARN with region and account wildcards (rds:*:*:cluster:*)"
  },
  {
   "id": "three_inline_policies",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with three inline policies attached",
   "justify": "the prompt states three inline policies",
   "checks": [
    {
     "kind": "exists",
     "min": 3,
     "select": {
      "types": [
       "aws_iam_role_policy"
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
       "inline_policy"
      ],
      "op": "len_gte",
      "value": 3
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
