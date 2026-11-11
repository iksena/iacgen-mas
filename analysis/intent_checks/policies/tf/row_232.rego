package intent.tf.row_232

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "role",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "quote": "a dedicated third-party IAM integration role"
  },
  {
   "id": "role_name",
   "kind": "any_of",
   "tier": "core",
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
       "name"
      ],
      "op": "eq",
      "value": "CloudForecast-ZeroWaste"
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
         "default"
        ],
        "op": "eq",
        "value": "CloudForecast-ZeroWaste"
       }
      ]
     }
    }
   ],
   "quote": "the role name controlled by a variable defaulting to \"CloudForecast-ZeroWaste\""
  },
  {
   "id": "trust_principal",
   "kind": "any_of",
   "tier": "core",
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
      "value": "arn:aws:iam::656227328603:root"
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
         "properties"
        ],
        "op": "contains",
        "value": "656227328603"
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "656227328603"
       }
      ]
     }
    }
   ],
   "quote": "cross-account access from the external principal \"arn:aws:iam::656227328603:root\""
  },
  {
   "id": "trust_external_id",
   "kind": "any_of",
   "tier": "core",
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
      "value": "sts:ExternalId"
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
         "properties"
        ],
        "op": "contains",
        "value": "sts:ExternalId"
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "sts:ExternalId"
       }
      ]
     }
    }
   ],
   "quote": "conditioned strictly on matching a customizable external ID variable"
  },
  {
   "id": "external_id_default",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "benchmark-external-id"
     }
    ]
   },
   "quote": "defaulting to \"benchmark-external-id\""
  },
  {
   "id": "inline_policies",
   "kind": "any_of",
   "tier": "core",
   "quote": "fifteen discrete inline IAM policies",
   "justify": "fifteen is 15",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
     },
     "min": 15
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
      "value": 15
     }
    }
   ]
  },
  {
   "id": "inline_policies_on_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "Attached directly to this role",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": []
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
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "act_cw_metrics",
   "kind": "any_of",
   "tier": "core",
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
        "value": "(?i)cloudwatch:(?:GetMetricStatistics|G\\*|Ge\\*|Get\\*|GetM\\*|GetMe\\*|GetMet\\*|GetMetr\\*|GetMetri\\*|GetMetric\\*|GetMetricS\\*|GetMetricSt\\*|GetMetricSta\\*|GetMetricStat\\*|GetMetricStati\\*|GetMetricStatis\\*|GetMetricStatist\\*|GetMetricStatisti\\*|GetMetricStatistic\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)cloudwatch:(?:GetMetricStatistics|G\\*|Ge\\*|Get\\*|GetM\\*|GetMe\\*|GetMet\\*|GetMetr\\*|GetMetri\\*|GetMetric\\*|GetMetricS\\*|GetMetricSt\\*|GetMetricSta\\*|GetMetricStat\\*|GetMetricStati\\*|GetMetricStatis\\*|GetMetricStatist\\*|GetMetricStatisti\\*|GetMetricStatistic\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)cloudwatch:(?:GetMetricStatistics|G\\*|Ge\\*|Get\\*|GetM\\*|GetMe\\*|GetMet\\*|GetMetr\\*|GetMetri\\*|GetMetric\\*|GetMetricS\\*|GetMetricSt\\*|GetMetricSta\\*|GetMetricStat\\*|GetMetricStati\\*|GetMetricStatis\\*|GetMetricStatist\\*|GetMetricStatisti\\*|GetMetricStatistic\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "\"cloudwatch:GetMetricStatistics\""
  },
  {
   "id": "act_tag",
   "kind": "any_of",
   "tier": "core",
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
        "value": "(?i)tag:(?:GetResources|G\\*|Ge\\*|Get\\*|GetR\\*|GetRe\\*|GetRes\\*|GetReso\\*|GetResou\\*|GetResour\\*|GetResourc\\*|GetResource\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)tag:(?:GetResources|G\\*|Ge\\*|Get\\*|GetR\\*|GetRe\\*|GetRes\\*|GetReso\\*|GetResou\\*|GetResour\\*|GetResourc\\*|GetResource\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)tag:(?:GetResources|G\\*|Ge\\*|Get\\*|GetR\\*|GetRe\\*|GetRes\\*|GetReso\\*|GetResou\\*|GetResour\\*|GetResourc\\*|GetResource\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "\"tag:GetResources\""
  },
  {
   "id": "act_org",
   "kind": "any_of",
   "tier": "core",
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
        "value": "(?i)organizations:(?:ListAccounts|L\\*|Li\\*|Lis\\*|List\\*|ListA\\*|ListAc\\*|ListAcc\\*|ListAcco\\*|ListAccou\\*|ListAccoun\\*|ListAccount\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)organizations:(?:ListAccounts|L\\*|Li\\*|Lis\\*|List\\*|ListA\\*|ListAc\\*|ListAcc\\*|ListAcco\\*|ListAccou\\*|ListAccoun\\*|ListAccount\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)organizations:(?:ListAccounts|L\\*|Li\\*|Lis\\*|List\\*|ListA\\*|ListAc\\*|ListAcc\\*|ListAcco\\*|ListAccou\\*|ListAccoun\\*|ListAccount\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "\"organizations:ListAccounts\""
  },
  {
   "id": "act_elb",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "(?i)elasticloadbalancing:(?:Describe\\w*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)elasticloadbalancing:(?:Describe\\w*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)elasticloadbalancing:(?:Describe\\w*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "ALB/ELB load balancers and tags",
   "justify": "read-only describe permissions for load balancers"
  },
  {
   "id": "act_ebs_snapshots",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "(?i)ec2:(?:DescribeSnapshots|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeS\\*|DescribeSn\\*|DescribeSna\\*|DescribeSnap\\*|DescribeSnaps\\*|DescribeSnapsh\\*|DescribeSnapsho\\*|DescribeSnapshot\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)ec2:(?:DescribeSnapshots|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeS\\*|DescribeSn\\*|DescribeSna\\*|DescribeSnap\\*|DescribeSnaps\\*|DescribeSnapsh\\*|DescribeSnapsho\\*|DescribeSnapshot\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(?:DescribeSnapshots|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeS\\*|DescribeSn\\*|DescribeSna\\*|DescribeSnap\\*|DescribeSnaps\\*|DescribeSnapsh\\*|DescribeSnapsho\\*|DescribeSnapshot\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "EBS snapshots and volumes",
   "justify": "read-only describe of snapshots"
  },
  {
   "id": "act_ebs_volumes",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "(?i)ec2:(?:DescribeVolumes|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeV\\*|DescribeVo\\*|DescribeVol\\*|DescribeVolu\\*|DescribeVolum\\*|DescribeVolume\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)ec2:(?:DescribeVolumes|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeV\\*|DescribeVo\\*|DescribeVol\\*|DescribeVolu\\*|DescribeVolum\\*|DescribeVolume\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(?:DescribeVolumes|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeV\\*|DescribeVo\\*|DescribeVol\\*|DescribeVolu\\*|DescribeVolum\\*|DescribeVolume\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "EBS snapshots and volumes",
   "justify": "read-only describe of volumes"
  },
  {
   "id": "act_ec2_instances",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "(?i)ec2:(?:DescribeInstances|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeI\\*|DescribeIn\\*|DescribeIns\\*|DescribeInst\\*|DescribeInsta\\*|DescribeInstan\\*|DescribeInstanc\\*|DescribeInstance\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)ec2:(?:DescribeInstances|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeI\\*|DescribeIn\\*|DescribeIns\\*|DescribeInst\\*|DescribeInsta\\*|DescribeInstan\\*|DescribeInstanc\\*|DescribeInstance\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:(?:DescribeInstances|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeI\\*|DescribeIn\\*|DescribeIns\\*|DescribeInst\\*|DescribeInsta\\*|DescribeInstan\\*|DescribeInstanc\\*|DescribeInstance\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "EC2 instances",
   "justify": "read-only describe of instances"
  },
  {
   "id": "act_rds_instances",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "(?i)rds:(?:DescribeDBInstances|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeD\\*|DescribeDB\\*|DescribeDBI\\*|DescribeDBIn\\*|DescribeDBIns\\*|DescribeDBInst\\*|DescribeDBInsta\\*|DescribeDBInstan\\*|DescribeDBInstanc\\*|DescribeDBInstance\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)rds:(?:DescribeDBInstances|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeD\\*|DescribeDB\\*|DescribeDBI\\*|DescribeDBIn\\*|DescribeDBIns\\*|DescribeDBInst\\*|DescribeDBInsta\\*|DescribeDBInstan\\*|DescribeDBInstanc\\*|DescribeDBInstance\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)rds:(?:DescribeDBInstances|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeD\\*|DescribeDB\\*|DescribeDBI\\*|DescribeDBIn\\*|DescribeDBIns\\*|DescribeDBInst\\*|DescribeDBInsta\\*|DescribeDBInstan\\*|DescribeDBInstanc\\*|DescribeDBInstance\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "RDS instances and snapshots",
   "justify": "read-only describe of DB instances"
  },
  {
   "id": "act_rds_snapshots",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "(?i)rds:(?:DescribeDBSnapshots|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeD\\*|DescribeDB\\*|DescribeDBS\\*|DescribeDBSn\\*|DescribeDBSna\\*|DescribeDBSnap\\*|DescribeDBSnaps\\*|DescribeDBSnapsh\\*|DescribeDBSnapsho\\*|DescribeDBSnapshot\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)rds:(?:DescribeDBSnapshots|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeD\\*|DescribeDB\\*|DescribeDBS\\*|DescribeDBSn\\*|DescribeDBSna\\*|DescribeDBSnap\\*|DescribeDBSnaps\\*|DescribeDBSnapsh\\*|DescribeDBSnapsho\\*|DescribeDBSnapshot\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)rds:(?:DescribeDBSnapshots|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeD\\*|DescribeDB\\*|DescribeDBS\\*|DescribeDBSn\\*|DescribeDBSna\\*|DescribeDBSnap\\*|DescribeDBSnaps\\*|DescribeDBSnapsh\\*|DescribeDBSnapsho\\*|DescribeDBSnapshot\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "RDS instances and snapshots",
   "justify": "read-only describe of DB snapshots"
  },
  {
   "id": "act_s3_list_all",
   "kind": "any_of",
   "tier": "core",
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
        "value": "(?i)s3:(?:ListAllMyBuckets|L\\*|Li\\*|Lis\\*|List\\*|ListA\\*|ListAl\\*|ListAll\\*|ListAllM\\*|ListAllMy\\*|ListAllMyB\\*|ListAllMyBu\\*|ListAllMyBuc\\*|ListAllMyBuck\\*|ListAllMyBucke\\*|ListAllMyBucket\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)s3:(?:ListAllMyBuckets|L\\*|Li\\*|Lis\\*|List\\*|ListA\\*|ListAl\\*|ListAll\\*|ListAllM\\*|ListAllMy\\*|ListAllMyB\\*|ListAllMyBu\\*|ListAllMyBuc\\*|ListAllMyBuck\\*|ListAllMyBucke\\*|ListAllMyBucket\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:(?:ListAllMyBuckets|L\\*|Li\\*|Lis\\*|List\\*|ListA\\*|ListAl\\*|ListAll\\*|ListAllM\\*|ListAllMy\\*|ListAllMyB\\*|ListAllMyBu\\*|ListAllMyBuc\\*|ListAllMyBuck\\*|ListAllMyBucke\\*|ListAllMyBucket\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "\"s3:ListAllMyBuckets\""
  },
  {
   "id": "act_s3_list",
   "kind": "any_of",
   "tier": "core",
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
        "value": "(?i)s3:(?:ListBucket|L\\*|Li\\*|Lis\\*|List\\*|ListB\\*|ListBu\\*|ListBuc\\*|ListBuck\\*|ListBucke\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)s3:(?:ListBucket|L\\*|Li\\*|Lis\\*|List\\*|ListB\\*|ListBu\\*|ListBuc\\*|ListBuck\\*|ListBucke\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:(?:ListBucket|L\\*|Li\\*|Lis\\*|List\\*|ListB\\*|ListBu\\*|ListBuc\\*|ListBuck\\*|ListBucke\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "\"s3:ListBucket\""
  },
  {
   "id": "act_s3_location",
   "kind": "any_of",
   "tier": "core",
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
        "value": "(?i)s3:(?:GetBucketLocation|G\\*|Ge\\*|Get\\*|GetB\\*|GetBu\\*|GetBuc\\*|GetBuck\\*|GetBucke\\*|GetBucket\\*|GetBucketL\\*|GetBucketLo\\*|GetBucketLoc\\*|GetBucketLoca\\*|GetBucketLocat\\*|GetBucketLocati\\*|GetBucketLocatio\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)s3:(?:GetBucketLocation|G\\*|Ge\\*|Get\\*|GetB\\*|GetBu\\*|GetBuc\\*|GetBuck\\*|GetBucke\\*|GetBucket\\*|GetBucketL\\*|GetBucketLo\\*|GetBucketLoc\\*|GetBucketLoca\\*|GetBucketLocat\\*|GetBucketLocati\\*|GetBucketLocatio\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:(?:GetBucketLocation|G\\*|Ge\\*|Get\\*|GetB\\*|GetBu\\*|GetBuc\\*|GetBuck\\*|GetBucke\\*|GetBucket\\*|GetBucketL\\*|GetBucketLo\\*|GetBucketLoc\\*|GetBucketLoca\\*|GetBucketLocat\\*|GetBucketLocati\\*|GetBucketLocatio\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "\"s3:GetBucketLocation\""
  },
  {
   "id": "act_s3_tagging",
   "kind": "any_of",
   "tier": "core",
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
        "value": "(?i)s3:(?:GetBucketTagging|G\\*|Ge\\*|Get\\*|GetB\\*|GetBu\\*|GetBuc\\*|GetBuck\\*|GetBucke\\*|GetBucket\\*|GetBucketT\\*|GetBucketTa\\*|GetBucketTag\\*|GetBucketTagg\\*|GetBucketTaggi\\*|GetBucketTaggin\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)s3:(?:GetBucketTagging|G\\*|Ge\\*|Get\\*|GetB\\*|GetBu\\*|GetBuc\\*|GetBuck\\*|GetBucke\\*|GetBucket\\*|GetBucketT\\*|GetBucketTa\\*|GetBucketTag\\*|GetBucketTagg\\*|GetBucketTaggi\\*|GetBucketTaggin\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:(?:GetBucketTagging|G\\*|Ge\\*|Get\\*|GetB\\*|GetBu\\*|GetBuc\\*|GetBuck\\*|GetBucke\\*|GetBucket\\*|GetBucketT\\*|GetBucketTa\\*|GetBucketTag\\*|GetBucketTagg\\*|GetBucketTaggi\\*|GetBucketTaggin\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "\"s3:GetBucketTagging\""
  },
  {
   "id": "act_s3_lifecycle",
   "kind": "any_of",
   "tier": "core",
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
        "value": "(?i)s3:(?:GetLifecycleConfiguration|G\\*|Ge\\*|Get\\*|GetL\\*|GetLi\\*|GetLif\\*|GetLife\\*|GetLifec\\*|GetLifecy\\*|GetLifecyc\\*|GetLifecycl\\*|GetLifecycle\\*|GetLifecycleC\\*|GetLifecycleCo\\*|GetLifecycleCon\\*|GetLifecycleConf\\*|GetLifecycleConfi\\*|GetLifecycleConfig\\*|GetLifecycleConfigu\\*|GetLifecycleConfigur\\*|GetLifecycleConfigura\\*|GetLifecycleConfigurat\\*|GetLifecycleConfigurati\\*|GetLifecycleConfiguratio\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)s3:(?:GetLifecycleConfiguration|G\\*|Ge\\*|Get\\*|GetL\\*|GetLi\\*|GetLif\\*|GetLife\\*|GetLifec\\*|GetLifecy\\*|GetLifecyc\\*|GetLifecycl\\*|GetLifecycle\\*|GetLifecycleC\\*|GetLifecycleCo\\*|GetLifecycleCon\\*|GetLifecycleConf\\*|GetLifecycleConfi\\*|GetLifecycleConfig\\*|GetLifecycleConfigu\\*|GetLifecycleConfigur\\*|GetLifecycleConfigura\\*|GetLifecycleConfigurat\\*|GetLifecycleConfigurati\\*|GetLifecycleConfiguratio\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)s3:(?:GetLifecycleConfiguration|G\\*|Ge\\*|Get\\*|GetL\\*|GetLi\\*|GetLif\\*|GetLife\\*|GetLifec\\*|GetLifecy\\*|GetLifecyc\\*|GetLifecycl\\*|GetLifecycle\\*|GetLifecycleC\\*|GetLifecycleCo\\*|GetLifecycleCon\\*|GetLifecycleConf\\*|GetLifecycleConfi\\*|GetLifecycleConfig\\*|GetLifecycleConfigu\\*|GetLifecycleConfigur\\*|GetLifecycleConfigura\\*|GetLifecycleConfigurat\\*|GetLifecycleConfigurati\\*|GetLifecycleConfiguratio\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "\"s3:GetLifecycleConfiguration\""
  },
  {
   "id": "act_logs",
   "kind": "any_of",
   "tier": "core",
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
        "value": "(?i)logs:(?:DescribeLogGroups|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeL\\*|DescribeLo\\*|DescribeLog\\*|DescribeLogG\\*|DescribeLogGr\\*|DescribeLogGro\\*|DescribeLogGrou\\*|DescribeLogGroup\\*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)logs:(?:DescribeLogGroups|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeL\\*|DescribeLo\\*|DescribeLog\\*|DescribeLogG\\*|DescribeLogGr\\*|DescribeLogGro\\*|DescribeLogGrou\\*|DescribeLogGroup\\*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)logs:(?:DescribeLogGroups|D\\*|De\\*|Des\\*|Desc\\*|Descr\\*|Descri\\*|Describ\\*|Describe\\*|DescribeL\\*|DescribeLo\\*|DescribeLog\\*|DescribeLogG\\*|DescribeLogGr\\*|DescribeLogGro\\*|DescribeLogGrou\\*|DescribeLogGroup\\*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "\"logs:DescribeLogGroups\""
  },
  {
   "id": "act_support",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "(?i)(?:support|trustedadvisor):(?:Describe\\w*|\\*)(?:[\"'\\],\\s]|$)"
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
         "inline_policy"
        ],
        "op": "regex",
        "value": "(?i)(?:support|trustedadvisor):(?:Describe\\w*|\\*)(?:[\"'\\],\\s]|$)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(?:support|trustedadvisor):(?:Describe\\w*|\\*)(?:[\"'\\],\\s]|$)"
       }
      ]
     }
    }
   ],
   "quote": "Support/Trusted Advisor checks",
   "justify": "Trusted Advisor checks are read via support Describe actions"
  },
  {
   "id": "x_max_session",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "max_session_duration"
    ],
    "op": "eq",
    "value": 3600
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
