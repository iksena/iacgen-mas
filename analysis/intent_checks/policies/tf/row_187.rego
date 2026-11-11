package intent.tf.row_187

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "aws_vpc"
   ],
   "where": []
  },
  "cluster": {
   "types": [
    "aws_eks_cluster"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "md-k8s"
    }
   ]
  },
  "pubsub": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "in",
     "value": [
      "192.168.0.0/19",
      "192.168.32.0/19",
      "192.168.64.0/19"
     ]
    }
   ]
  },
  "prisub": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "in",
     "value": [
      "192.168.96.0/19",
      "192.168.128.0/19",
      "192.168.160.0/19"
     ]
    }
   ]
  },
  "firstpub": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "eq",
     "value": "192.168.0.0/19"
    }
   ]
  },
  "nat": {
   "types": [
    "aws_nat_gateway"
   ],
   "where": []
  },
  "igw": {
   "types": [
    "aws_internet_gateway"
   ],
   "where": []
  },
  "key": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  },
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": []
  },
  "sgs": {
   "types": [
    "aws_security_group"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "eks_cluster",
   "kind": "exists",
   "tier": "core",
   "quote": "creates the control plane of an Amazon EKS cluster named \"md-k8s\"",
   "select": "cluster"
  },
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "tier": "core",
   "quote": "a dedicated VPC with CIDR block 192.168.0.0/16",
   "select": "vpc",
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "eq",
    "value": "192.168.0.0/16"
   }
  },
  {
   "id": "vpc_dns_hostnames",
   "kind": "attr",
   "tier": "core",
   "quote": "DNS hostnames enabled",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_hostnames"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "public_subnets",
   "kind": "all_of",
   "tier": "core",
   "quote": "public subnets 192.168.0.0/19, 192.168.32.0/19, and 192.168.64.0/19",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "192.168.0.0/19"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "192.168.32.0/19"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "192.168.64.0/19"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "private_subnets",
   "kind": "all_of",
   "tier": "core",
   "quote": "private subnets 192.168.96.0/19, 192.168.128.0/19, and 192.168.160.0/19",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "192.168.96.0/19"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "192.168.128.0/19"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "192.168.160.0/19"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "subnets_no_public_ip",
   "kind": "attr",
   "tier": "core",
   "quote": "none of which auto-assign public IP addresses",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": [
     {
      "path": [
       "cidr_block"
      ],
      "op": "in",
      "value": [
       "192.168.0.0/19",
       "192.168.32.0/19",
       "192.168.64.0/19",
       "192.168.96.0/19",
       "192.168.128.0/19",
       "192.168.160.0/19"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "map_public_ip_on_launch"
    ],
    "op": "falsy"
   },
   "quantifier": "all"
  },
  {
   "id": "public_lb_tag",
   "kind": "attr",
   "tier": "detail",
   "quote": "all tagged for Kubernetes load balancer discovery",
   "select": "pubsub",
   "cond": {
    "path": [
     "tags",
     "kubernetes.io/role/elb"
    ],
    "op": "eq",
    "value": "1"
   },
   "quantifier": "all",
   "justify": "LB discovery tag kubernetes.io/role/elb=1 on public subnets"
  },
  {
   "id": "private_lb_tag",
   "kind": "attr",
   "tier": "detail",
   "quote": "all tagged for Kubernetes load balancer discovery",
   "select": "prisub",
   "cond": {
    "path": [
     "tags",
     "kubernetes.io/role/internal-elb"
    ],
    "op": "eq",
    "value": "1"
   },
   "quantifier": "all",
   "justify": "LB discovery tag kubernetes.io/role/internal-elb=1 on private subnets"
  },
  {
   "id": "igw",
   "kind": "exists",
   "tier": "core",
   "quote": "Add an internet gateway with a public route table",
   "select": "igw"
  },
  {
   "id": "igw_attached",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Add an internet gateway with a public route table",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     },
     "to": "vpc"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "vpc_id"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "public_route_to_igw",
   "kind": "any_of",
   "tier": "core",
   "quote": "an internet gateway with a public route table",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table"
      ],
      "where": []
     },
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": []
     },
     "to": "igw"
    }
   ]
  },
  {
   "id": "nat",
   "kind": "exists",
   "tier": "core",
   "quote": "a single NAT gateway with an Elastic IP in the first public subnet",
   "select": "nat",
   "min": 1,
   "max": 1,
   "justify": "a single NAT gateway means exactly one"
  },
  {
   "id": "nat_eip",
   "kind": "exists",
   "tier": "core",
   "quote": "a single NAT gateway with an Elastic IP",
   "select": {
    "types": [
     "aws_eip"
    ],
    "where": []
   }
  },
  {
   "id": "nat_uses_eip",
   "kind": "any_of",
   "tier": "core",
   "quote": "a single NAT gateway with an Elastic IP",
   "checks": [
    {
     "kind": "ref",
     "from": "nat",
     "to": {
      "types": [
       "aws_eip"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": "nat",
     "cond": {
      "path": [
       "allocation_id"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "nat_in_first_public",
   "kind": "ref",
   "tier": "core",
   "quote": "in the first public subnet",
   "from": "nat",
   "to": "firstpub"
  },
  {
   "id": "private_rt_via_nat",
   "kind": "any_of",
   "tier": "core",
   "quote": "serving a shared private route table",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table"
      ],
      "where": []
     },
     "to": "nat"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": []
     },
     "to": "nat"
    }
   ]
  },
  {
   "id": "db_subnet_group",
   "kind": "attr",
   "tier": "core",
   "quote": "a database subnet group named \"md-k8s-private-subnet-group\" over the private subnets",
   "select": {
    "types": [
     "aws_db_subnet_group"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "md-k8s-private-subnet-group"
   }
  },
  {
   "id": "db_subnet_group_private",
   "kind": "ref",
   "tier": "core",
   "quote": "over the private subnets",
   "from": {
    "types": [
     "aws_db_subnet_group"
    ],
    "where": []
   },
   "to": "prisub"
  },
  {
   "id": "service_role",
   "kind": "exists",
   "tier": "core",
   "quote": "The cluster must use a dedicated service role",
   "select": "role"
  },
  {
   "id": "role_trust_eks",
   "kind": "any_of",
   "tier": "core",
   "quote": "dedicated service role",
   "checks": [
    {
     "kind": "ref",
     "from": "cluster",
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "assume_role_policy"
        ],
        "op": "contains",
        "value": "eks.amazonaws.com"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
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
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "eks.amazonaws.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cluster_uses_role",
   "kind": "ref",
   "tier": "core",
   "quote": "The cluster must use a dedicated service role",
   "from": "cluster",
   "to": "role"
  },
  {
   "id": "managed_cluster_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "the AWS-managed EKS cluster and VPC resource controller policies",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AmazonEKSClusterPolicy"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "assume_role_policy"
        ],
        "op": "contains",
        "value": "eks.amazonaws.com"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "assume_role_policy"
        ],
        "op": "contains",
        "value": "eks.amazonaws.com"
       }
      ]
     },
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "contains",
      "value": "AmazonEKSClusterPolicy"
     }
    },
    {
     "kind": "ref",
     "from": {
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
         "aws_iam_role_policy_attachment",
         "aws_iam_policy_attachment"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "AmazonEKSClusterPolicy"
       }
      ]
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
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "eks.amazonaws.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "managed_vpc_rc_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "the AWS-managed EKS cluster and VPC resource controller policies",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AmazonEKSVPCResourceController"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "assume_role_policy"
        ],
        "op": "contains",
        "value": "eks.amazonaws.com"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "assume_role_policy"
        ],
        "op": "contains",
        "value": "eks.amazonaws.com"
       }
      ]
     },
     "cond": {
      "path": [
       "managed_policy_arns",
       "*"
      ],
      "op": "contains",
      "value": "AmazonEKSVPCResourceController"
     }
    },
    {
     "kind": "ref",
     "from": {
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
         "aws_iam_role_policy_attachment",
         "aws_iam_policy_attachment"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "AmazonEKSVPCResourceController"
       }
      ]
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
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "eks.amazonaws.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "custom_ec2_describe",
   "kind": "any_of",
   "tier": "detail",
   "quote": "small custom policies for describing EC2 networking",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "ec2:Describe"
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
      "op": "regex",
      "value": "ec2:Describe"
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "ec2:Describe"
     }
    }
   ]
  },
  {
   "id": "custom_cw_metrics",
   "kind": "any_of",
   "tier": "detail",
   "quote": "publishing CloudWatch metrics",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "cloudwatch:PutMetricData"
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
      "op": "regex",
      "value": "cloudwatch:PutMetricData"
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document",
         "aws_iam_role"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "cloudwatch:PutMetricData"
     }
    }
   ]
  },
  {
   "id": "private_endpoint",
   "kind": "attr",
   "tier": "core",
   "quote": "expose its API endpoint privately only",
   "select": "cluster",
   "cond": {
    "path": [
     "vpc_config",
     "*",
     "endpoint_private_access"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "no_public_endpoint",
   "kind": "attr",
   "tier": "core",
   "quote": "expose its API endpoint privately only",
   "select": "cluster",
   "cond": {
    "path": [
     "vpc_config",
     "*",
     "endpoint_public_access"
    ],
    "op": "eq",
    "value": false
   }
  },
  {
   "id": "secrets_encryption",
   "kind": "attr",
   "tier": "core",
   "quote": "envelope-encrypt Kubernetes secrets",
   "select": "cluster",
   "cond": {
    "path": [
     "encryption_config",
     "*",
     "resources",
     "*"
    ],
    "op": "eq",
    "value": "secrets"
   }
  },
  {
   "id": "kms_key",
   "kind": "exists",
   "tier": "core",
   "quote": "envelope-encrypt Kubernetes secrets with a new customer-managed KMS key",
   "select": "key"
  },
  {
   "id": "kms_rotation",
   "kind": "ref",
   "tier": "core",
   "quote": "that has rotation enabled",
   "from": "cluster",
   "to": {
    "types": [
     "aws_kms_key"
    ],
    "where": [
     {
      "path": [
       "enable_key_rotation"
      ],
      "op": "eq",
      "value": true
     }
    ]
   }
  },
  {
   "id": "cluster_uses_key",
   "kind": "ref",
   "tier": "core",
   "quote": "envelope-encrypt Kubernetes secrets with a new customer-managed KMS key",
   "from": "cluster",
   "to": "key"
  },
  {
   "id": "two_sgs",
   "kind": "exists",
   "tier": "core",
   "quote": "create a control plane security group and a shared node security group",
   "select": "sgs",
   "min": 2,
   "justify": "control plane SG and shared node SG are two groups"
  },
  {
   "id": "sg_egress_vpc_cidr",
   "kind": "any_of",
   "tier": "core",
   "quote": "with outbound traffic on both limited to the VPC CIDR",
   "justify": "VPC CIDR is stated as 192.168.0.0/16; 'on both' means at least two groups/rules",
   "checks": [
    {
     "kind": "attr",
     "select": "sgs",
     "quantifier": "all",
     "cond": {
      "path": [
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "192.168.0.0/16",
      "every": true
     }
    },
    {
     "kind": "exists",
     "min": 2,
     "select": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "egress"
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "192.168.0.0/16",
        "every": true
       }
      ]
     }
    },
    {
     "kind": "exists",
     "min": 2,
     "select": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "192.168.0.0/16"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "node_sg_internode",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a shared node security group that allows traffic between nodes",
   "checks": [
    {
     "kind": "attr",
     "select": "sgs",
     "cond": {
      "path": [
       "ingress",
       "*",
       "self"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       }
      ]
     },
     "cond": {
      "path": [
       "self"
      ],
      "op": "truthy"
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
        "value": "aws_vpc_security_group_ingress_rule"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "referenced_security_group_id"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "node_sg_from_cluster",
   "kind": "any_of",
   "tier": "detail",
   "quote": "and from the cluster's own security group",
   "checks": [
    {
     "kind": "ref",
     "from": "sgs",
     "to": {
      "types": [
       "aws_eks_cluster",
       "data.aws_security_groups",
       "data.aws_security_group"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": "sgs",
     "to": "sgs"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       }
      ]
     },
     "to": {
      "types": [
       "aws_eks_cluster",
       "data.aws_security_groups",
       "data.aws_security_group"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_eks_cluster",
       "data.aws_security_groups",
       "data.aws_security_group"
      ],
      "where": []
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
        "value": "aws_security_group_rule"
       },
       {
        "path": [
         "properties",
         "source_security_group_id"
        ],
        "op": "present"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "type"
      ],
      "op": "eq",
      "value": "ingress"
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
        "value": "aws_vpc_security_group_ingress_rule"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "referenced_security_group_id"
      ],
      "op": "present"
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
        "value": "aws_security_group"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "ingress",
       "*",
       "security_groups",
       "*"
      ],
      "op": "present"
     }
    }
   ],
   "justify": "allowing traffic from a security group means an ingress rule"
  },
  {
   "id": "x_kms_deletion_window",
   "kind": "attr",
   "tier": "extra",
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
    "op": "gte",
    "value": 1
   }
  },
  {
   "id": "x_vpc_dns_support",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "x_nat_public",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "connectivity_type"
    ],
    "op": "eq",
    "value": "public"
   }
  },
  {
   "id": "extra_type_aws_route_table_association",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
