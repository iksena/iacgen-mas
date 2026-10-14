# GENERATED from specs/tf/row_159.json by intent_checks/build.py -- do not edit.
package intent.tf.row_159

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "aws_vpc"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "eq",
     "value": "10.255.0.0/16"
    }
   ]
  },
  "bastion": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Quasar-Bastion"
    }
   ]
  },
  "haproxy": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Quasar-HA-Proxy"
    }
   ]
  },
  "jenkins": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Quasar-Jenkins"
    }
   ]
  },
  "etl": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Quasar-ETL"
    }
   ]
  },
  "pg": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "Quasar-PostgreSQL"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "exists",
   "tier": "core",
   "quote": "The VPC must be created with CIDR block \"10.255.0.0/16\"",
   "select": "vpc"
  },
  {
   "id": "vpc_named_quasar",
   "kind": "attr",
   "tier": "detail",
   "quote": "named \"Quasar\"",
   "select": "vpc",
   "cond": {
    "path": [
     "tags",
     "Name"
    ],
    "op": "eq",
    "value": "Quasar"
   }
  },
  {
   "id": "vpc_tags",
   "kind": "all_of",
   "tier": "detail",
   "quote": "tagged with Application \"dosomething-quasar\", Environment \"production\", and Stack \"data\"",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "tags",
       "Application"
      ],
      "op": "eq",
      "value": "dosomething-quasar"
     }
    },
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "tags",
       "Environment"
      ],
      "op": "eq",
      "value": "production"
     }
    },
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "tags",
       "Stack"
      ],
      "op": "eq",
      "value": "data"
     }
    }
   ]
  },
  {
   "id": "rds_subnet_a",
   "kind": "ref",
   "tier": "core",
   "quote": "\"10.255.100.0/24\"",
   "to": "vpc",
   "from": {
    "types": [
     "aws_subnet"
    ],
    "where": [
     {
      "path": [
       "cidr_block"
      ],
      "op": "eq",
      "value": "10.255.100.0/24"
     }
    ]
   }
  },
  {
   "id": "rds_subnet_b",
   "kind": "ref",
   "tier": "core",
   "quote": "\"10.255.101.0/24\"",
   "to": "vpc",
   "from": {
    "types": [
     "aws_subnet"
    ],
    "where": [
     {
      "path": [
       "cidr_block"
      ],
      "op": "eq",
      "value": "10.255.101.0/24"
     }
    ]
   }
  },
  {
   "id": "rds_subnet_names",
   "kind": "all_of",
   "tier": "detail",
   "quote": "(tagged Name \"Quasar RDS - 1A\")",
   "checks": [
    {
     "kind": "attr",
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
        "value": "10.255.100.0/24"
       }
      ]
     },
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "Quasar RDS - 1A"
     }
    },
    {
     "kind": "attr",
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
        "value": "10.255.101.0/24"
       }
      ]
     },
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "Quasar RDS - 1E"
     }
    }
   ]
  },
  {
   "id": "sgs_named_in_vpc",
   "kind": "all_of",
   "tier": "core",
   "quote": "Five dedicated security groups with outbound egress limited to the VPC CIDR must be provisioned within the VPC",
   "checks": [
    {
     "kind": "ref",
     "from": "bastion",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "haproxy",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "jenkins",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "etl",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "pg",
     "to": "vpc"
    }
   ]
  },
  {
   "id": "sg_tagging_schema",
   "kind": "all_of",
   "tier": "detail",
   "quote": "using the same tagging schema",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "tags",
       "Application"
      ],
      "op": "eq",
      "value": "dosomething-quasar"
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
     "quantifier": "all",
     "cond": {
      "path": [
       "tags",
       "Environment"
      ],
      "op": "eq",
      "value": "production"
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
     "quantifier": "all",
     "cond": {
      "path": [
       "tags",
       "Stack"
      ],
      "op": "eq",
      "value": "data"
     }
    }
   ]
  },
  {
   "id": "egress_vpc_only",
   "kind": "any_of",
   "tier": "detail",
   "quote": "outbound egress limited to the VPC CIDR",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "10.255.0.0/16",
      "every": true
     }
    },
    {
     "kind": "exists",
     "min": 5,
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
        "value": "10.255.0.0/16",
        "every": true
       }
      ]
     }
    },
    {
     "kind": "exists",
     "min": 5,
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
        "value": "10.255.0.0/16"
       }
      ]
     }
    }
   ],
   "justify": "prompt states 'Five dedicated security groups' with egress limited to the VPC CIDR"
  },
  {
   "id": "bastion_ssh_admin_range",
   "kind": "any_of",
   "tier": "core",
   "quote": "allowing inbound SSH (port 22) only from the placeholder admin range \"203.0.113.0/24\"",
   "checks": [
    {
     "kind": "attr",
     "select": "bastion",
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "203.0.113.0/24"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "bastion",
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
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "203.0.113.0/24"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "bastion",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "203.0.113.0/24"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bastion_ssh_not_open",
   "kind": "any_of",
   "tier": "detail",
   "quote": "only from the placeholder admin range",
   "justify": "'only from the admin range' -> SSH ingress never opens 0.0.0.0/0 (rule resources or inline Bastion ingress)",
   "checks": [
    {
     "kind": "attr",
     "quantifier": "all",
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
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 22
       }
      ]
     },
     "cond": {
      "path": [
       "cidr_blocks",
       "*"
      ],
      "op": "none_eq",
      "value": "0.0.0.0/0"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Quasar-Bastion"
       },
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "present"
       }
      ]
     },
     "cond": {
      "path": [
       "ingress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "none_eq",
      "value": "0.0.0.0/0"
     }
    }
   ]
  },
  {
   "id": "haproxy_http_open",
   "kind": "any_of",
   "tier": "core",
   "quote": "allowing inbound HTTP (port 80) and HTTPS (port 443) from everywhere (\"0.0.0.0/0\")",
   "checks": [
    {
     "kind": "attr",
     "select": "haproxy",
     "cond": {
      "path": [
       "ingress",
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
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "haproxy",
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
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "haproxy",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "haproxy_https_open",
   "kind": "any_of",
   "tier": "core",
   "quote": "HTTPS (port 443) from everywhere (\"0.0.0.0/0\")",
   "checks": [
    {
     "kind": "attr",
     "select": "haproxy",
     "cond": {
      "path": [
       "ingress",
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
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "haproxy",
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
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "haproxy",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "haproxy_ssh_from_bastion",
   "kind": "any_of",
   "tier": "core",
   "quote": "SSH (port 22) from the Bastion security group",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Quasar-HA-Proxy"
       },
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "port_covers",
        "value": 22
       }
      ]
     },
     "to": "bastion"
    },
    {
     "kind": "ref",
     "to": "haproxy",
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
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "haproxy",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 22
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
   "id": "jenkins_ssh_from_bastion",
   "kind": "any_of",
   "tier": "core",
   "quote": "a \"Quasar-Jenkins\" security group allowing inbound SSH (port 22) from the Bastion security group",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Quasar-Jenkins"
       },
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "port_covers",
        "value": 22
       }
      ]
     },
     "to": "bastion"
    },
    {
     "kind": "ref",
     "to": "jenkins",
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
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "jenkins",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 22
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
   "id": "jenkins_8080_from_haproxy",
   "kind": "any_of",
   "tier": "core",
   "quote": "port 8080 from the HA-Proxy security group",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Quasar-Jenkins"
       },
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "port_covers",
        "value": 8080
       }
      ]
     },
     "to": "haproxy"
    },
    {
     "kind": "ref",
     "to": "jenkins",
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
        "path": [],
        "op": "port_covers",
        "value": 8080
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "jenkins",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 8080
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
   "id": "haproxy_is_8080_source",
   "kind": "any_of",
   "tier": "detail",
   "quote": "port 8080 from the HA-Proxy security group",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "port_covers",
        "value": 8080
       }
      ]
     },
     "to": "haproxy"
    },
    {
     "kind": "ref",
     "to": "haproxy",
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
        "path": [],
        "op": "port_covers",
        "value": 8080
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "haproxy",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 8080
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
   "id": "etl_ssh_from_bastion",
   "kind": "any_of",
   "tier": "core",
   "quote": "a \"Quasar-ETL\" security group allowing inbound SSH (port 22) from both the Bastion and Jenkins security groups",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Quasar-ETL"
       },
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "port_covers",
        "value": 22
       }
      ]
     },
     "to": "bastion"
    },
    {
     "kind": "ref",
     "to": "etl",
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
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "etl",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 22
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
   "id": "etl_ssh_from_jenkins",
   "kind": "any_of",
   "tier": "detail",
   "quote": "from both the Bastion and Jenkins security groups",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Quasar-ETL"
       },
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "port_covers",
        "value": 22
       }
      ]
     },
     "to": "jenkins"
    },
    {
     "kind": "ref",
     "to": "jenkins",
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
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "jenkins",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 22
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
   "id": "bastion_is_ssh_source",
   "kind": "any_of",
   "tier": "detail",
   "quote": "SSH (port 22) from the Bastion security group",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "port_covers",
        "value": 22
       }
      ]
     },
     "to": "bastion"
    },
    {
     "kind": "ref",
     "to": "bastion",
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
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "bastion",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 22
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
   "id": "pg_5432_open",
   "kind": "any_of",
   "tier": "core",
   "quote": "a \"Quasar-PostgreSQL\" security group allowing inbound PostgreSQL traffic (port 5432) both from everywhere (\"0.0.0.0/0\")",
   "checks": [
    {
     "kind": "attr",
     "select": "pg",
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 5432
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "pg",
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
        "path": [],
        "op": "port_covers",
        "value": 5432
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "pg",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 5432
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "pg_5432_from_etl",
   "kind": "any_of",
   "tier": "core",
   "quote": "specifically referenced from the ETL security group",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "Quasar-PostgreSQL"
       },
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "port_covers",
        "value": 5432
       }
      ]
     },
     "to": "etl"
    },
    {
     "kind": "ref",
     "to": "pg",
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
        "path": [],
        "op": "port_covers",
        "value": 5432
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "pg",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 5432
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
   "id": "etl_is_5432_source",
   "kind": "any_of",
   "tier": "detail",
   "quote": "specifically referenced from the ETL security group",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "port_covers",
        "value": 5432
       }
      ]
     },
     "to": "etl"
    },
    {
     "kind": "ref",
     "to": "etl",
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
        "path": [],
        "op": "port_covers",
        "value": 5432
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "etl",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 5432
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
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
