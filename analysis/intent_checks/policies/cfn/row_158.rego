package intent.cfn.row_158

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "AWS::EC2::VPC"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.82.0.0/16"
    }
   ]
  },
  "subnet": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.82.10.0/24"
    }
   ]
  },
  "subnets": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": []
  },
  "inst": {
   "types": [
    "AWS::EC2::Instance"
   ],
   "where": []
  },
  "lt": {
   "types": [
    "AWS::EC2::LaunchTemplate"
   ],
   "where": []
  },
  "eip": {
   "types": [
    "AWS::EC2::EIP"
   ],
   "where": []
  },
  "eipassoc": {
   "types": [
    "AWS::EC2::EIPAssociation"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "profile": {
   "types": [
    "AWS::IAM::InstanceProfile"
   ],
   "where": []
  },
  "sg": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": []
  },
  "sgi": {
   "types": [
    "AWS::EC2::SecurityGroupIngress"
   ],
   "where": []
  },
  "sge": {
   "types": [
    "AWS::EC2::SecurityGroupEgress"
   ],
   "where": []
  },
  "igw": {
   "types": [
    "AWS::EC2::InternetGateway"
   ],
   "where": []
  },
  "route": {
   "types": [
    "AWS::EC2::Route"
   ],
   "where": [
    {
     "path": [
      "DestinationCidrBlock"
     ],
     "op": "eq",
     "value": "0.0.0.0/0"
    },
    {
     "path": [
      "GatewayId"
     ],
     "op": "present"
    }
   ]
  },
  "flow": {
   "types": [
    "AWS::EC2::FlowLog"
   ],
   "where": []
  },
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "kms": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "sg_in_range_only": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": [
    {
     "path": [
      "SecurityGroupIngress",
      "*",
      "CidrIp"
     ],
     "op": "eq",
     "value": "10.0.0.0/8",
     "every": true
    }
   ]
  },
  "sg_in_web_only": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": [
    {
     "path": [
      "SecurityGroupIngress",
      "*",
      "FromPort"
     ],
     "op": "in",
     "value": [
      80,
      443
     ],
     "every": true
    },
    {
     "path": [
      "SecurityGroupIngress",
      "*",
      "ToPort"
     ],
     "op": "in",
     "value": [
      80,
      443
     ],
     "every": true
    },
    {
     "path": [
      "SecurityGroupIngress",
      "*",
      "IpProtocol"
     ],
     "op": "none_eq",
     "value": "-1"
    }
   ]
  },
  "sg_out_https_range_only": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": [
    {
     "path": [
      "SecurityGroupEgress",
      "*",
      "CidrIp"
     ],
     "op": "eq",
     "value": "10.0.0.0/8",
     "every": true
    },
    {
     "path": [
      "SecurityGroupEgress",
      "*",
      "FromPort"
     ],
     "op": "eq",
     "value": 443,
     "every": true
    },
    {
     "path": [
      "SecurityGroupEgress",
      "*",
      "ToPort"
     ],
     "op": "eq",
     "value": 443,
     "every": true
    },
    {
     "path": [
      "SecurityGroupEgress",
      "*",
      "IpProtocol"
     ],
     "op": "none_eq",
     "value": "-1"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "tier": "core",
   "quote": "a VPC with a CIDR block of 10.82.0.0/16",
   "select": "vpc"
  },
  {
   "id": "private_subnet",
   "kind": "exists",
   "tier": "core",
   "quote": "a single private subnet using 10.82.10.0/24",
   "select": "subnet"
  },
  {
   "id": "single_subnet",
   "kind": "exists",
   "tier": "core",
   "quote": "a single private subnet",
   "justify": "\"single\" subnet",
   "select": "subnets",
   "max": 1
  },
  {
   "id": "subnet_no_public_ip",
   "kind": "attr",
   "tier": "core",
   "quote": "a single private subnet",
   "justify": "a private subnet does not auto-assign public IPs",
   "select": "subnet",
   "cond": {
    "path": [
     "MapPublicIpOnLaunch"
    ],
    "op": "none_eq",
    "value": true
   }
  },
  {
   "id": "subnet_in_vpc",
   "kind": "ref",
   "tier": "detail",
   "quote": "a single private subnet using 10.82.10.0/24",
   "from": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": []
   },
   "to": "vpc"
  },
  {
   "id": "instance",
   "kind": "exists",
   "tier": "core",
   "quote": "an EC2 instance",
   "select": "inst"
  },
  {
   "id": "instance_type",
   "kind": "any_of",
   "tier": "core",
   "quote": "an EC2 instance of type t3.micro",
   "checks": [
    {
     "kind": "attr",
     "select": "inst",
     "cond": {
      "path": [
       "InstanceType"
      ],
      "op": "eq",
      "value": "t3.micro"
     }
    },
    {
     "kind": "attr",
     "select": "lt",
     "cond": {
      "path": [
       "LaunchTemplateData",
       "InstanceType"
      ],
      "op": "eq",
      "value": "t3.micro"
     }
    }
   ]
  },
  {
   "id": "latest_al2023_ami",
   "kind": "any_of",
   "tier": "core",
   "quote": "dynamically fetching the latest Amazon Linux 2023 AMI",
   "justify": "the SSM public parameter for Amazon Linux 2023 contains al2023",
   "checks": [
    {
     "kind": "attr",
     "select": "inst",
     "cond": {
      "path": [
       "ImageId"
      ],
      "op": "regex",
      "value": "(?i)al2023|amzn2023|linux-2023"
     }
    },
    {
     "kind": "attr",
     "select": "lt",
     "cond": {
      "path": [
       "LaunchTemplateData",
       "ImageId"
      ],
      "op": "regex",
      "value": "(?i)al2023|amzn2023|linux-2023"
     }
    }
   ]
  },
  {
   "id": "serves_html",
   "kind": "any_of",
   "tier": "detail",
   "quote": "serves a simple static HTML page on HTTP port 80",
   "checks": [
    {
     "kind": "attr",
     "select": "inst",
     "cond": {
      "path": [
       "UserData"
      ],
      "op": "regex",
      "value": "(?i)html"
     }
    },
    {
     "kind": "attr",
     "select": "lt",
     "cond": {
      "path": [
       "LaunchTemplateData",
       "UserData"
      ],
      "op": "regex",
      "value": "(?i)html"
     }
    }
   ]
  },
  {
   "id": "eip",
   "kind": "exists",
   "tier": "core",
   "quote": "an Elastic IP",
   "select": "eip"
  },
  {
   "id": "eip_associated",
   "kind": "any_of",
   "tier": "core",
   "quote": "an Elastic IP associated to that instance",
   "checks": [
    {
     "kind": "ref",
     "from": "eipassoc",
     "to": "inst"
    },
    {
     "kind": "ref",
     "from": "eip",
     "to": "inst"
    }
   ]
  },
  {
   "id": "iam_role",
   "kind": "exists",
   "tier": "core",
   "quote": "a new IAM role",
   "select": "role"
  },
  {
   "id": "ssm_policy",
   "kind": "attr",
   "tier": "core",
   "quote": "the AmazonSSMManagedInstanceCore policy",
   "select": "role",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "regex",
    "value": "(^|/)AmazonSSMManagedInstanceCore$"
   }
  },
  {
   "id": "instance_uses_profile",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the instance must use a new IAM role",
   "checks": [
    {
     "kind": "ref",
     "from": "inst",
     "to": "profile"
    },
    {
     "kind": "ref",
     "from": "lt",
     "to": "profile"
    }
   ]
  },
  {
   "id": "profile_has_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "the instance must use a new IAM role",
   "from": {
    "types": [
     "AWS::IAM::InstanceProfile"
    ],
    "where": []
   },
   "to": "role"
  },
  {
   "id": "encrypted_ebs",
   "kind": "any_of",
   "tier": "core",
   "quote": "have encrypted EBS volumes",
   "checks": [
    {
     "kind": "attr",
     "select": "inst",
     "cond": {
      "path": [
       "BlockDeviceMappings",
       "*",
       "Ebs",
       "Encrypted"
      ],
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "attr",
     "select": "lt",
     "cond": {
      "path": [
       "LaunchTemplateData",
       "BlockDeviceMappings",
       "*",
       "Ebs",
       "Encrypted"
      ],
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::EC2::Volume"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Encrypted"
      ],
      "op": "eq",
      "value": true
     }
    }
   ]
  },
  {
   "id": "imdsv2",
   "kind": "any_of",
   "tier": "core",
   "quote": "enforce IMDSv2",
   "justify": "IMDSv2 means HttpTokens required",
   "checks": [
    {
     "kind": "attr",
     "select": "inst",
     "cond": {
      "path": [
       "MetadataOptions",
       "HttpTokens"
      ],
      "op": "eq",
      "value": "required"
     }
    },
    {
     "kind": "attr",
     "select": "lt",
     "cond": {
      "path": [
       "LaunchTemplateData",
       "MetadataOptions",
       "HttpTokens"
      ],
      "op": "eq",
      "value": "required"
     }
    }
   ]
  },
  {
   "id": "sg",
   "kind": "exists",
   "tier": "core",
   "quote": "placed in a security group",
   "select": "sg"
  },
  {
   "id": "sg_in_http",
   "kind": "any_of",
   "tier": "core",
   "quote": "only allows HTTP and HTTPS ingress from the internal network range 10.0.0.0/8",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "SecurityGroupIngress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "10.0.0.0/8"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "sgi",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "10.0.0.0/8"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sg_in_https",
   "kind": "any_of",
   "tier": "core",
   "quote": "only allows HTTP and HTTPS ingress from the internal network range 10.0.0.0/8",
   "justify": "HTTPS implies port 443",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "SecurityGroupIngress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "10.0.0.0/8"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "sgi",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "10.0.0.0/8"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sg_out_https",
   "kind": "any_of",
   "tier": "core",
   "quote": "HTTPS egress to the same range",
   "justify": "HTTPS implies port 443",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "SecurityGroupEgress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "10.0.0.0/8"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "sge",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "10.0.0.0/8"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sg_in_not_world",
   "kind": "any_of",
   "tier": "detail",
   "quote": "only allows HTTP and HTTPS ingress",
   "checks": [
    {
     "kind": "ref",
     "from": "inst",
     "to": "sg_in_range_only"
    },
    {
     "kind": "ref",
     "from": "lt",
     "to": "sg_in_range_only"
    },
    {
     "kind": "attr",
     "select": "sgi",
     "cond": {
      "path": [
       "CidrIp"
      ],
      "op": "none_eq",
      "value": "0.0.0.0/0"
     },
     "quantifier": "all"
    }
   ],
   "justify": "only from 10.0.0.0/8: the instance's own group has no other source"
  },
  {
   "id": "sg_in_only_web_ports",
   "kind": "any_of",
   "tier": "detail",
   "quote": "only allows HTTP and HTTPS ingress",
   "justify": "HTTP and HTTPS imply ports 80 and 443",
   "checks": [
    {
     "kind": "ref",
     "from": "inst",
     "to": "sg_in_web_only"
    },
    {
     "kind": "ref",
     "from": "lt",
     "to": "sg_in_web_only"
    },
    {
     "kind": "attr",
     "select": "sgi",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "FromPort"
        ],
        "op": "in",
        "value": [
         80,
         443
        ]
       },
       {
        "path": [
         "ToPort"
        ],
        "op": "in",
        "value": [
         80,
         443
        ]
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sg_out_only_https_range",
   "kind": "any_of",
   "tier": "detail",
   "quote": "HTTPS egress to the same range",
   "justify": "HTTPS implies port 443; the same range is 10.0.0.0/8, and 'only allows' covers egress too",
   "checks": [
    {
     "kind": "ref",
     "from": "inst",
     "to": "sg_out_https_range_only"
    },
    {
     "kind": "ref",
     "from": "lt",
     "to": "sg_out_https_range_only"
    },
    {
     "kind": "attr",
     "select": "sge",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "FromPort"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "ToPort"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "10.0.0.0/8"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "instance_in_sg",
   "kind": "any_of",
   "tier": "detail",
   "quote": "be placed in a security group",
   "checks": [
    {
     "kind": "ref",
     "from": "inst",
     "to": "sg"
    },
    {
     "kind": "ref",
     "from": "lt",
     "to": "sg"
    }
   ]
  },
  {
   "id": "igw",
   "kind": "exists",
   "tier": "core",
   "quote": "the VPC should have an Internet Gateway",
   "select": "igw"
  },
  {
   "id": "igw_attached",
   "kind": "ref",
   "tier": "core",
   "quote": "the VPC should have an Internet Gateway",
   "from": {
    "types": [
     "AWS::EC2::VPCGatewayAttachment"
    ],
    "where": []
   },
   "to": "vpc"
  },
  {
   "id": "default_route_igw",
   "kind": "ref",
   "tier": "core",
   "quote": "a default route to it",
   "justify": "a default route means destination 0.0.0.0/0",
   "from": "route",
   "to": "igw"
  },
  {
   "id": "flow_log",
   "kind": "exists",
   "tier": "core",
   "quote": "VPC Flow Logs enabled",
   "select": "flow"
  },
  {
   "id": "flow_log_vpc",
   "kind": "ref",
   "tier": "core",
   "quote": "VPC Flow Logs enabled",
   "from": {
    "types": [
     "AWS::EC2::FlowLog"
    ],
    "where": []
   },
   "to": "vpc"
  },
  {
   "id": "flow_log_group",
   "kind": "ref",
   "tier": "detail",
   "quote": "a 30-day retention log group",
   "from": {
    "types": [
     "AWS::EC2::FlowLog"
    ],
    "where": []
   },
   "to": "lg"
  },
  {
   "id": "log_retention",
   "kind": "attr",
   "tier": "core",
   "quote": "a 30-day retention log group",
   "select": "lg",
   "cond": {
    "path": [
     "RetentionInDays"
    ],
    "op": "eq",
    "value": 30
   }
  },
  {
   "id": "kms_key",
   "kind": "exists",
   "tier": "core",
   "quote": "encryption using a new customer-managed KMS key",
   "select": "kms"
  },
  {
   "id": "log_group_kms",
   "kind": "ref",
   "tier": "core",
   "quote": "encryption using a new customer-managed KMS key",
   "from": {
    "types": [
     "AWS::Logs::LogGroup"
    ],
    "where": []
   },
   "to": "kms"
  },
  {
   "id": "tagged_vpc",
   "kind": "any_of",
   "tier": "detail",
   "quote": "all resources should be tagged appropriately for the DR standby role",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::EC2::VPC"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Tags"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "tagged_instance",
   "kind": "any_of",
   "tier": "detail",
   "quote": "all resources should be tagged appropriately for the DR standby role",
   "checks": [
    {
     "kind": "attr",
     "select": "inst",
     "cond": {
      "path": [
       "Tags"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "lt",
     "cond": {
      "path": [
       "LaunchTemplateData",
       "TagSpecifications"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "lt",
     "cond": {
      "path": [
       "Tags"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "x_key_rotation",
   "kind": "attr",
   "tier": "extra",
   "select": "kms",
   "cond": {
    "path": [
     "EnableKeyRotation"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_flow_all",
   "kind": "attr",
   "tier": "extra",
   "select": "flow",
   "cond": {
    "path": [
     "TrafficType"
    ],
    "op": "eq",
    "value": "ALL"
   }
  },
  {
   "id": "x_flow_cwl",
   "kind": "attr",
   "tier": "extra",
   "select": "flow",
   "cond": {
    "path": [
     "LogDestinationType"
    ],
    "op": "eq",
    "value": "cloud-watch-logs"
   }
  },
  {
   "id": "x_eip_vpc",
   "kind": "attr",
   "tier": "extra",
   "select": "eip",
   "cond": {
    "path": [
     "Domain"
    ],
    "op": "eq",
    "value": "vpc"
   }
  },
  {
   "id": "x_dns_support",
   "kind": "attr",
   "tier": "extra",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsSupport"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_flow_role_trust",
   "kind": "attr",
   "tier": "extra",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Principal",
     "Service",
     "*"
    ],
    "op": "eq",
    "value": "vpc-flow-logs.amazonaws.com"
   }
  },
  {
   "id": "extra_type_aws_ec2_routetable",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::RouteTable"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_subnetroutetableassociation",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::SubnetRouteTableAssociation"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
