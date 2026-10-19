package intent.tf.row_249

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "eks_cluster_named",
   "kind": "exists",
   "select": {
    "types": [
     "aws_eks_cluster"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "demo-eks"
     }
    ]
   },
   "tier": "core",
   "quote": "a custom Amazon EKS cluster named \"demo-eks\""
  },
  {
   "id": "cluster_private_endpoint",
   "kind": "attr",
   "select": {
    "types": [
     "aws_eks_cluster"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "demo-eks"
     }
    ]
   },
   "tier": "core",
   "quote": "a private-only API endpoint",
   "cond": {
    "path": [
     "vpc_config",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "endpoint_public_access"
      ],
      "op": "falsy"
     },
     {
      "path": [
       "endpoint_private_access"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "cluster_secrets_cmk",
   "kind": "all_of",
   "tier": "core",
   "quote": "secrets encrypted by a customer-managed KMS key",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_eks_cluster"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "demo-eks"
       }
      ]
     },
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
     "kind": "ref",
     "from": {
      "types": [
       "aws_eks_cluster"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "demo-eks"
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
  },
  {
   "id": "cluster_in_private_subnets",
   "kind": "ref",
   "tier": "detail",
   "quote": "attached to those private subnets",
   "from": {
    "types": [
     "aws_eks_cluster"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "demo-eks"
     }
    ]
   },
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   }
  },
  {
   "id": "provider_default_tag",
   "kind": "all_of",
   "tier": "detail",
   "quote": "ensuring the AWS provider applies a default tag of \"kubernetes.io/cluster/demo-eks\" set to \"owned\"",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags_all"
      ],
      "op": "regex",
      "value": "kubernetes\\.io/cluster/demo-eks\"?:\\s*\"owned\""
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_eks_cluster"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "demo-eks"
       }
      ]
     },
     "cond": {
      "path": [
       "tags_all"
      ],
      "op": "regex",
      "value": "kubernetes\\.io/cluster/demo-eks\"?:\\s*\"owned\""
     }
    }
   ]
  },
  {
   "id": "vpc_cidr_dns",
   "kind": "exists",
   "tier": "core",
   "quote": "create a 10.0.0.0/16 VPC with DNS support and hostnames",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": [
     {
      "path": [
       "cidr_block"
      ],
      "op": "eq",
      "value": "10.0.0.0/16"
     },
     {
      "path": [
       "enable_dns_support"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "enable_dns_hostnames"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "igw_attached",
   "kind": "ref",
   "tier": "detail",
   "quote": "an internet gateway",
   "from": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   }
  },
  {
   "id": "nat_in_subnet",
   "kind": "ref",
   "tier": "core",
   "quote": "a public subnet hosting a NAT gateway",
   "from": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   }
  },
  {
   "id": "public_route_to_igw",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a public subnet hosting a NAT gateway",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table"
      ],
      "where": [
       {
        "path": [
         "route",
         "*",
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": [
       {
        "path": [
         "destination_cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     }
    }
   ],
   "justify": "'public subnet' with internet access -> 0.0.0.0/0 route to the IGW"
  },
  {
   "id": "three_private_subnets",
   "kind": "exists",
   "tier": "detail",
   "min": 4,
   "quote": "three private subnets (one per availability zone)",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "justify": "a public subnet plus three private subnets -> at least 4 subnets"
  },
  {
   "id": "private_route_via_nat",
   "kind": "any_of",
   "tier": "core",
   "quote": "routed through that NAT gateway",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table"
      ],
      "where": [
       {
        "path": [
         "route",
         "*",
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": {
      "types": [
       "aws_nat_gateway"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": [
       {
        "path": [
         "destination_cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": {
      "types": [
       "aws_nat_gateway"
      ],
      "where": []
     }
    }
   ],
   "justify": "'routed through that NAT gateway' -> 0.0.0.0/0 route to the NAT"
  },
  {
   "kind": "ref",
   "from": {
    "types": [
     "aws_eks_cluster"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "demo-eks"
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
       "name"
      ],
      "op": "eq",
      "value": "eksClusterRole"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "eks.amazonaws.com"
     }
    ]
   },
   "id": "cluster_role",
   "tier": "core",
   "quote": "utilizing an IAM role named \"eksClusterRole\"",
   "justify": "EKS cluster role -> trusted by eks.amazonaws.com"
  },
  {
   "id": "cluster_role_policies",
   "kind": "any_of",
   "tier": "detail",
   "quote": "includes the standard EKS cluster and VPC resource controller policies",
   "checks": [
    {
     "kind": "exists",
     "min": 2,
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
        "value": "eksClusterRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "policy/(AmazonEKSClusterPolicy|AmazonEKSVPCResourceController)$"
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
         "name"
        ],
        "op": "eq",
        "value": "eksClusterRole"
       },
       {
        "path": [
         "managed_policy_arns",
         "*"
        ],
        "op": "contains",
        "value": "AmazonEKSClusterPolicy"
       },
       {
        "path": [
         "managed_policy_arns",
         "*"
        ],
        "op": "contains",
        "value": "AmazonEKSVPCResourceController"
       }
      ]
     }
    }
   ],
   "justify": "'standard EKS cluster and VPC resource controller policies' are AmazonEKSClusterPolicy and AmazonEKSVPCResourceController (two policies)"
  },
  {
   "id": "cluster_role_kms_permission",
   "kind": "any_of",
   "tier": "detail",
   "quote": "plus permission to use that KMS key",
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
       "aws_kms_key"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_grant"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "eksClusterRole"
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
         "name"
        ],
        "op": "eq",
        "value": "eksClusterRole"
       }
      ]
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "kms:"
     }
    }
   ]
  },
  {
   "id": "tls_rsa_4096",
   "kind": "exists",
   "tier": "core",
   "quote": "generate a 4096-bit RSA TLS private key",
   "select": {
    "types": [
     "tls_private_key"
    ],
    "where": [
     {
      "path": [
       "algorithm"
      ],
      "op": "eq",
      "value": "RSA"
     },
     {
      "path": [
       "rsa_bits"
      ],
      "op": "eq",
      "value": 4096
     }
    ]
   }
  },
  {
   "id": "key_saved_locally",
   "kind": "ref",
   "tier": "detail",
   "quote": "save it locally to \"~/.ssh/eks-aws.pem\"",
   "from": {
    "types": [
     "local_sensitive_file",
     "local_file"
    ],
    "where": [
     {
      "path": [
       "filename"
      ],
      "op": "regex",
      "value": "\\.ssh/eks-aws\\.pem$"
     }
    ]
   },
   "to": {
    "types": [
     "tls_private_key"
    ],
    "where": []
   }
  },
  {
   "id": "key_pair_eks_kp",
   "kind": "ref",
   "tier": "core",
   "quote": "register it as an AWS key pair named \"eks_kp\"",
   "from": {
    "types": [
     "aws_key_pair"
    ],
    "where": [
     {
      "path": [
       "key_name"
      ],
      "op": "eq",
      "value": "eks_kp"
     }
    ]
   },
   "to": {
    "types": [
     "tls_private_key"
    ],
    "where": []
   }
  },
  {
   "id": "node_sg_egress_vpc_only",
   "kind": "any_of",
   "tier": "core",
   "quote": "allowing outbound traffic only within the VPC CIDR",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "10.0.0.0/16"
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
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
        "value": "egress"
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "node_sg_self_ingress",
   "kind": "any_of",
   "tier": "detail",
   "quote": "unrestricted internal communication between nodes",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "self"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "-1"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
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
       },
       {
        "path": [
         "self"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "-1"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "-1"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "absent"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cp_ingress_443",
   "kind": "any_of",
   "tier": "core",
   "quote": "tightly scoped TCP ingress and egress rules on ports 443 and 1025-65535",
   "checks": [
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_eks_cluster"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_eks_cluster"
      ],
      "where": []
     },
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
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "data.aws_eks_cluster"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "data.aws_eks_cluster"
      ],
      "where": []
     },
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
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
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
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "cidr_blocks"
        ],
        "op": "absent"
       },
       {
        "path": [
         "self"
        ],
        "op": "falsy"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "security_groups"
        ],
        "op": "len_gte",
        "value": 1
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cp_ingress_1025_65535",
   "kind": "any_of",
   "tier": "core",
   "quote": "tightly scoped TCP ingress and egress rules on ports 443 and 1025-65535",
   "checks": [
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_eks_cluster"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_eks_cluster"
      ],
      "where": []
     },
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
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "data.aws_eks_cluster"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "data.aws_eks_cluster"
      ],
      "where": []
     },
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
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
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
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "cidr_blocks"
        ],
        "op": "absent"
       },
       {
        "path": [
         "self"
        ],
        "op": "falsy"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "security_groups"
        ],
        "op": "len_gte",
        "value": 1
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cp_egress_443",
   "kind": "any_of",
   "tier": "detail",
   "quote": "tightly scoped TCP ingress and egress rules on ports 443 and 1025-65535",
   "checks": [
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_eks_cluster"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_eks_cluster"
      ],
      "where": []
     },
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
        "value": "egress"
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "data.aws_eks_cluster"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "data.aws_eks_cluster"
      ],
      "where": []
     },
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
        "value": "egress"
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
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
        "value": "egress"
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "cidr_blocks"
        ],
        "op": "absent"
       },
       {
        "path": [
         "self"
        ],
        "op": "falsy"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "egress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "security_groups"
        ],
        "op": "len_gte",
        "value": 1
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cp_egress_1025_65535",
   "kind": "any_of",
   "tier": "detail",
   "quote": "tightly scoped TCP ingress and egress rules on ports 443 and 1025-65535",
   "checks": [
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_eks_cluster"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_eks_cluster"
      ],
      "where": []
     },
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
        "value": "egress"
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "data.aws_eks_cluster"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "data.aws_eks_cluster"
      ],
      "where": []
     },
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
        "value": "egress"
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
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
        "value": "egress"
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "cidr_blocks"
        ],
        "op": "absent"
       },
       {
        "path": [
         "self"
        ],
        "op": "falsy"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "egress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 1025
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 65535
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "security_groups"
        ],
        "op": "len_gte",
        "value": 1
       }
      ]
     }
    }
   ]
  },
  {
   "id": "node_role_policies",
   "kind": "any_of",
   "tier": "core",
   "quote": "Provision an IAM role named \"eks-demo-node\" with managed policies for EKS worker nodes, CNI, ECR read-only, and SSM core management",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "eks-demo-node"
       },
       {
        "path": [
         "assume_role_policy"
        ],
        "op": "contains",
        "value": "ec2.amazonaws.com"
       },
       {
        "path": [
         "managed_policy_arns",
         "*"
        ],
        "op": "contains",
        "value": "AmazonEKSWorkerNodePolicy"
       },
       {
        "path": [
         "managed_policy_arns",
         "*"
        ],
        "op": "contains",
        "value": "AmazonEKS_CNI_Policy"
       },
       {
        "path": [
         "managed_policy_arns",
         "*"
        ],
        "op": "contains",
        "value": "AmazonEC2ContainerRegistryReadOnly"
       },
       {
        "path": [
         "managed_policy_arns",
         "*"
        ],
        "op": "contains",
        "value": "AmazonSSMManagedInstanceCore"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "min": 4,
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
        "value": "eks-demo-node"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "regex",
        "value": "policy/(AmazonEKSWorkerNodePolicy|AmazonEKS_CNI_Policy|AmazonEC2ContainerRegistryReadOnly|AmazonSSMManagedInstanceCore)$"
       }
      ]
     }
    }
   ],
   "justify": "'EKS worker nodes, CNI, ECR read-only, SSM core' are AmazonEKSWorkerNodePolicy, AmazonEKS_CNI_Policy, AmazonEC2ContainerRegistryReadOnly, AmazonSSMManagedInstanceCore (four policies), node role trusted by EC2"
  },
  {
   "id": "node_instance_profile",
   "kind": "ref",
   "tier": "detail",
   "quote": "attach it to an instance profile",
   "from": {
    "types": [
     "aws_iam_instance_profile"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "eks-demo-node"
     }
    ]
   }
  },
  {
   "id": "launch_template_t3_medium",
   "kind": "attr",
   "select": {
    "types": [
     "aws_launch_template"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "an EC2 launch template using a t3.medium instance",
   "cond": {
    "path": [
     "instance_type"
    ],
    "op": "eq",
    "value": "t3.medium"
   }
  },
  {
   "id": "launch_template_root_volume",
   "kind": "attr",
   "select": {
    "types": [
     "aws_launch_template"
    ],
    "where": []
   },
   "tier": "detail",
   "quote": "a 30 GB gp2 root volume",
   "cond": {
    "path": [
     "block_device_mappings",
     "*",
     "ebs",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "volume_size"
      ],
      "op": "eq",
      "value": 30
     },
     {
      "path": [
       "volume_type"
      ],
      "op": "eq",
      "value": "gp2"
     }
    ]
   }
  },
  {
   "id": "launch_template_imdsv2",
   "kind": "attr",
   "select": {
    "types": [
     "aws_launch_template"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "required IMDSv2 HTTP tokens with a hop limit of 2",
   "cond": {
    "path": [
     "metadata_options",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "http_tokens"
      ],
      "op": "eq",
      "value": "required"
     },
     {
      "path": [
       "http_put_response_hop_limit"
      ],
      "op": "eq",
      "value": 2
     }
    ]
   }
  },
  {
   "id": "launch_template_ssm_ami",
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
      "value": "aws_launch_template"
     }
    ]
   },
   "tier": "detail",
   "quote": "the latest Amazon Linux 2 EKS-optimized AMI retrieved via SSM",
   "cond": {
    "path": [
     "properties",
     "image_id"
    ],
    "op": "regex",
    "value": "(?i)ssm"
   },
   "justify": "'retrieved via SSM' -> image_id sourced from SSM"
  },
  {
   "id": "launch_template_user_data_signal",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a base64-encoded user-data bootstrap script that connects to the cluster and signals a CloudFormation stack upon completion",
   "checks": [
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
        "value": "aws_launch_template"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "user_data"
      ],
      "op": "regex",
      "value": "(?i)(cfn-signal|signal-resource)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_launch_template"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "user_data"
      ],
      "op": "regex",
      "value": "c2lnbmFsLXJlc291cmNl|NpZ25hbC1yZXNvdXJj|zaWduYWwtcmVzb3Vy|Y2ZuLXNpZ25h|Nmbi1zaWdu|jZm4tc2lnbmFs"
     }
    }
   ],
   "justify": "\"signals a CloudFormation stack\" -> cfn-signal / signal-resource (planned user_data matched in its base64 form)"
  },
  {
   "id": "launch_template_user_data_bootstrap",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a base64-encoded user-data bootstrap script that connects to the cluster and signals a CloudFormation stack upon completion",
   "checks": [
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
        "value": "aws_launch_template"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "user_data"
      ],
      "op": "regex",
      "value": "(?i)(bootstrap|nodeadm)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_launch_template"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "user_data"
      ],
      "op": "regex",
      "value": "Ym9vdHN0cmFw|Jvb3RzdHJh|ib290c3Ry|bm9kZWFk|5vZGVh|ub2RlYWRt"
     }
    }
   ],
   "justify": "\"bootstrap script that connects to the cluster\" -> EKS bootstrap/nodeadm (planned user_data matched in its base64 form)"
  },
  {
   "id": "sleep_30s",
   "kind": "exists",
   "tier": "detail",
   "quote": "a 30-second delay",
   "select": {
    "types": [
     "time_sleep"
    ],
    "where": [
     {
      "path": [
       "create_duration"
      ],
      "op": "eq",
      "value": "30s"
     }
    ]
   },
   "justify": "'30-second delay' -> 30s"
  },
  {
   "id": "cfn_stack_named",
   "kind": "all_of",
   "tier": "core",
   "quote": "deploy a CloudFormation stack named \"eks-cluster-stack\" to provision the Auto Scaling Group across the private subnets",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_cloudformation_stack"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "eks-cluster-stack"
       }
      ]
     },
     "to": {
      "types": [
       "aws_launch_template"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_cloudformation_stack"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "eks-cluster-stack"
       }
      ]
     },
     "to": {
      "types": [
       "aws_subnet"
      ],
      "where": []
     }
    }
   ],
   "justify": "'provision the Auto Scaling Group' via the CloudFormation stack -> AWS::AutoScaling::AutoScalingGroup in its template"
  },
  {
   "id": "cfn_stack_provisions_asg",
   "kind": "any_of",
   "tier": "core",
   "quote": "to provision the Auto Scaling Group",
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
        "value": "aws_cloudformation_stack"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "contains",
        "value": "eks-cluster-stack"
       },
       {
        "path": [
         "properties",
         "template_body"
        ],
        "op": "contains",
        "value": "AWS::AutoScaling::AutoScalingGroup"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_cloudformation_stack"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "eks-cluster-stack"
       },
       {
        "path": [
         "template_body"
        ],
        "op": "contains",
        "value": "AWS::AutoScaling::AutoScalingGroup"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "asg_min_size_1",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a minimum size of 1",
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
        "value": "aws_cloudformation_stack"
       },
       {
        "path": [
         "properties",
         "template_body"
        ],
        "op": "regex",
        "value": "MinSize\\W{0,8}(Default\\W{0,6})?1([^0-9]|$)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_cloudformation_stack"
      ],
      "where": [
       {
        "path": [
         "template_body"
        ],
        "op": "regex",
        "value": "MinSize\\W{0,8}(Default\\W{0,6})?1([^0-9]|$)"
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
        "value": "aws_s3_object"
       },
       {
        "path": [
         "properties",
         "content"
        ],
        "op": "regex",
        "value": "MinSize\\W{0,8}(Default\\W{0,6})?1([^0-9]|$)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_object"
      ],
      "where": [
       {
        "path": [
         "content"
        ],
        "op": "regex",
        "value": "MinSize\\W{0,8}(Default\\W{0,6})?1([^0-9]|$)"
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
         "name"
        ],
        "op": "regex",
        "value": "(?i)min"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": 1
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_autoscaling_group"
      ],
      "where": [
       {
        "path": [
         "min_size"
        ],
        "op": "eq",
        "value": 1
       }
      ]
     }
    }
   ],
   "justify": "'minimum size of 1' -> MinSize"
  },
  {
   "id": "asg_desired_3",
   "kind": "any_of",
   "tier": "detail",
   "quote": "desired capacity of 3",
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
        "value": "aws_cloudformation_stack"
       },
       {
        "path": [
         "properties",
         "template_body"
        ],
        "op": "regex",
        "value": "DesiredCapacity\\W{0,8}(Default\\W{0,6})?3([^0-9]|$)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_cloudformation_stack"
      ],
      "where": [
       {
        "path": [
         "template_body"
        ],
        "op": "regex",
        "value": "DesiredCapacity\\W{0,8}(Default\\W{0,6})?3([^0-9]|$)"
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
        "value": "aws_s3_object"
       },
       {
        "path": [
         "properties",
         "content"
        ],
        "op": "regex",
        "value": "DesiredCapacity\\W{0,8}(Default\\W{0,6})?3([^0-9]|$)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_object"
      ],
      "where": [
       {
        "path": [
         "content"
        ],
        "op": "regex",
        "value": "DesiredCapacity\\W{0,8}(Default\\W{0,6})?3([^0-9]|$)"
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
         "name"
        ],
        "op": "regex",
        "value": "(?i)desired"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": 3
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_autoscaling_group"
      ],
      "where": [
       {
        "path": [
         "desired_capacity"
        ],
        "op": "eq",
        "value": 3
       }
      ]
     }
    }
   ],
   "justify": "'desired capacity of 3' -> DesiredCapacity"
  },
  {
   "id": "asg_max_size_4",
   "kind": "any_of",
   "tier": "detail",
   "quote": "maximum size of 4",
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
        "value": "aws_cloudformation_stack"
       },
       {
        "path": [
         "properties",
         "template_body"
        ],
        "op": "regex",
        "value": "MaxSize\\W{0,8}(Default\\W{0,6})?4([^0-9]|$)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_cloudformation_stack"
      ],
      "where": [
       {
        "path": [
         "template_body"
        ],
        "op": "regex",
        "value": "MaxSize\\W{0,8}(Default\\W{0,6})?4([^0-9]|$)"
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
        "value": "aws_s3_object"
       },
       {
        "path": [
         "properties",
         "content"
        ],
        "op": "regex",
        "value": "MaxSize\\W{0,8}(Default\\W{0,6})?4([^0-9]|$)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_object"
      ],
      "where": [
       {
        "path": [
         "content"
        ],
        "op": "regex",
        "value": "MaxSize\\W{0,8}(Default\\W{0,6})?4([^0-9]|$)"
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
         "name"
        ],
        "op": "regex",
        "value": "(?i)max"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": 4
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_autoscaling_group"
      ],
      "where": [
       {
        "path": [
         "max_size"
        ],
        "op": "eq",
        "value": 4
       }
      ]
     }
    }
   ],
   "justify": "'maximum size of 4' -> MaxSize"
  },
  {
   "id": "asg_rolling_update",
   "kind": "any_of",
   "tier": "core",
   "quote": "an update policy for rolling updates with a maximum batch size of 1, a minimum of 3 instances in service, and a 5-minute pause time",
   "justify": "'update policy for rolling updates ... maximum batch size of 1, minimum of 3 instances in service, 5-minute pause' -> AutoScalingRollingUpdate MaxBatchSize/MinInstancesInService/PT5M",
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
        "value": "aws_cloudformation_stack"
       },
       {
        "path": [
         "properties",
         "template_body"
        ],
        "op": "regex",
        "value": "AutoScalingRollingUpdate"
       },
       {
        "path": [
         "properties",
         "template_body"
        ],
        "op": "regex",
        "value": "MaxBatchSize\\W{0,8}(Default\\W{0,6})?1([^0-9]|$)"
       },
       {
        "path": [
         "properties",
         "template_body"
        ],
        "op": "regex",
        "value": "MinInstancesInService\\W{0,8}(Default\\W{0,6})?(3([^0-9]|$)|\\$\\{|Ref)"
       },
       {
        "path": [
         "properties",
         "template_body"
        ],
        "op": "regex",
        "value": "PT5M"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_cloudformation_stack"
      ],
      "where": [
       {
        "path": [
         "template_body"
        ],
        "op": "regex",
        "value": "AutoScalingRollingUpdate"
       },
       {
        "path": [
         "template_body"
        ],
        "op": "regex",
        "value": "MaxBatchSize\\W{0,8}(Default\\W{0,6})?1([^0-9]|$)"
       },
       {
        "path": [
         "template_body"
        ],
        "op": "regex",
        "value": "MinInstancesInService\\W{0,8}(Default\\W{0,6})?(3([^0-9]|$)|\\$\\{|Ref)"
       },
       {
        "path": [
         "template_body"
        ],
        "op": "regex",
        "value": "PT5M"
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
        "value": "aws_s3_object"
       },
       {
        "path": [
         "properties",
         "content"
        ],
        "op": "regex",
        "value": "AutoScalingRollingUpdate"
       },
       {
        "path": [
         "properties",
         "content"
        ],
        "op": "regex",
        "value": "MaxBatchSize\\W{0,8}(Default\\W{0,6})?1([^0-9]|$)"
       },
       {
        "path": [
         "properties",
         "content"
        ],
        "op": "regex",
        "value": "MinInstancesInService\\W{0,8}(Default\\W{0,6})?(3([^0-9]|$)|\\$\\{|Ref)"
       },
       {
        "path": [
         "properties",
         "content"
        ],
        "op": "regex",
        "value": "PT5M"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_object"
      ],
      "where": [
       {
        "path": [
         "content"
        ],
        "op": "regex",
        "value": "AutoScalingRollingUpdate"
       },
       {
        "path": [
         "content"
        ],
        "op": "regex",
        "value": "MaxBatchSize\\W{0,8}(Default\\W{0,6})?1([^0-9]|$)"
       },
       {
        "path": [
         "content"
        ],
        "op": "regex",
        "value": "MinInstancesInService\\W{0,8}(Default\\W{0,6})?(3([^0-9]|$)|\\$\\{|Ref)"
       },
       {
        "path": [
         "content"
        ],
        "op": "regex",
        "value": "PT5M"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "outputs",
   "kind": "all_of",
   "tier": "detail",
   "quote": "output the node instance role ARN, the node security group ID, and the newly created Auto Scaling Group ID returned directly by the CloudFormation stack",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "eks-demo-node"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_cloudformation_stack"
      ],
      "where": []
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
