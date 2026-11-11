package intent.cfn.row_211

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "tg": {
   "types": [
    "AWS::EC2::TransitGateway"
   ],
   "where": []
  },
  "share": {
   "types": [
    "AWS::RAM::ResourceShare"
   ],
   "where": []
  },
  "decl_tg": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::EC2::TransitGateway"
    }
   ]
  },
  "decl_custom": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "regex",
     "value": "^(Custom::|AWS::CloudFormation::CustomResource)"
    }
   ]
  },
  "decl_share": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::RAM::ResourceShare"
    }
   ]
  },
  "outs": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "params_identification",
   "kind": "all_of",
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
         "name"
        ],
        "op": "eq",
        "value": "ReferenceFunctionsStackName"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": "ReferenceFunctions"
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
        "op": "eq",
        "value": "CompanyName"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": "Camelz"
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
        "op": "eq",
        "value": "SystemName"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": "Prototype"
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
        "op": "eq",
        "value": "AccountName"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": "Core"
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
        "op": "eq",
        "value": "EnvironmentName"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": "Core"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "ReferenceFunctionsStackName defaulting to \"ReferenceFunctions\", CompanyName defaulting to \"Camelz\", SystemName defaulting to \"Prototype\", AccountName defaulting to \"Core\", EnvironmentName defaulting to \"Core\""
  },
  {
   "id": "p_tg_account",
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
      "op": "eq",
      "value": "TransitGatewayAccount"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": ""
     }
    ]
   },
   "tier": "detail",
   "quote": "TransitGatewayAccount defaulting to an empty string"
  },
  {
   "id": "p_asn",
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
      "op": "eq",
      "value": "TransitGatewayASN"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": 64512
     }
    ]
   },
   "tier": "detail",
   "quote": "TransitGatewayASN defaulting to 64512"
  },
  {
   "id": "p_auto_accept",
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
      "op": "eq",
      "value": "AutoAcceptSharedAttachments"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "enable"
     },
     {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "enable"
     },
     {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "disable"
     }
    ]
   },
   "tier": "detail",
   "quote": "AutoAcceptSharedAttachments defaulting to \"enable\" (allowing \"enable\" or \"disable\")"
  },
  {
   "id": "p_dns",
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
      "op": "eq",
      "value": "DnsSupport"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "enable"
     },
     {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "enable"
     },
     {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "disable"
     }
    ]
   },
   "tier": "detail",
   "quote": "DnsSupport defaulting to \"enable\" (allowing \"enable\" or \"disable\")"
  },
  {
   "id": "p_ecmp",
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
      "op": "eq",
      "value": "VpnEcmpSupport"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "enable"
     },
     {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "enable"
     },
     {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "disable"
     }
    ]
   },
   "tier": "detail",
   "quote": "VpnEcmpSupport defaulting to \"enable\" (allowing \"enable\" or \"disable\")"
  },
  {
   "id": "p_share_name",
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
      "op": "eq",
      "value": "TransitGatewayResourceShareName"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "Core-TransitGatewayResourceShare"
     }
    ]
   },
   "tier": "detail",
   "quote": "TransitGatewayResourceShareName defaulting to \"Core-TransitGatewayResourceShare\""
  },
  {
   "id": "p_org",
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
      "op": "eq",
      "value": "Organization"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": ""
     }
    ]
   },
   "tier": "detail",
   "quote": "Organization defaulting to an empty string"
  },
  {
   "id": "p_external",
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
      "op": "eq",
      "value": "AllowExternalPrincipals"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "false"
     },
     {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "true"
     },
     {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "false"
     }
    ]
   },
   "tier": "detail",
   "quote": "AllowExternalPrincipals defaulting to \"false\" (allowing \"true\" or \"false\")"
  },
  {
   "id": "p_account_ids",
   "kind": "all_of",
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
         "name"
        ],
        "op": "eq",
        "value": "OrganizationAccount"
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
        "op": "eq",
        "value": "JumpstartAccount"
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
        "op": "eq",
        "value": "ManagementAccount"
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
        "op": "eq",
        "value": "LogAccount"
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
        "op": "eq",
        "value": "RecoveryAccount"
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
        "op": "eq",
        "value": "BuildAccount"
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
        "op": "eq",
        "value": "CoreAccount"
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
        "op": "eq",
        "value": "ProductionAccount"
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
        "op": "eq",
        "value": "StagingAccount"
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
        "op": "eq",
        "value": "UATAccount"
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
        "op": "eq",
        "value": "QAAccount"
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
        "op": "eq",
        "value": "TestingAccount"
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
        "op": "eq",
        "value": "DevelopmentAccount"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "individual AWS Account ID parameters for OrganizationAccount, JumpstartAccount, ManagementAccount, LogAccount, RecoveryAccount, BuildAccount, CoreAccount, ProductionAccount, StagingAccount, UATAccount, QAAccount, TestingAccount, and DevelopmentAccount"
  },
  {
   "id": "tg",
   "kind": "exists",
   "select": "tg",
   "tier": "core",
   "quote": "the stack must create an AWS EC2 Transit Gateway"
  },
  {
   "id": "tg_asn",
   "kind": "attr",
   "select": "tg",
   "cond": {
    "path": [
     "AmazonSideAsn"
    ],
    "op": "eq",
    "value": 64512
   },
   "tier": "core",
   "quote": "using the configured BGP ASN",
   "justify": "default of TransitGatewayASN"
  },
  {
   "id": "tg_auto_accept",
   "kind": "attr",
   "select": "tg",
   "cond": {
    "path": [
     "AutoAcceptSharedAttachments"
    ],
    "op": "eq",
    "value": "enable"
   },
   "tier": "core",
   "quote": "auto-accept settings",
   "justify": "default of AutoAcceptSharedAttachments"
  },
  {
   "id": "tg_dns",
   "kind": "attr",
   "select": "tg",
   "cond": {
    "path": [
     "DnsSupport"
    ],
    "op": "eq",
    "value": "enable"
   },
   "tier": "core",
   "quote": "DNS support",
   "justify": "default of DnsSupport"
  },
  {
   "id": "tg_ecmp",
   "kind": "attr",
   "select": "tg",
   "cond": {
    "path": [
     "VpnEcmpSupport"
    ],
    "op": "eq",
    "value": "enable"
   },
   "tier": "core",
   "quote": "VPN ECMP support",
   "justify": "default of VpnEcmpSupport"
  },
  {
   "id": "tg_no_default_assoc",
   "kind": "attr",
   "select": "tg",
   "cond": {
    "path": [
     "DefaultRouteTableAssociation"
    ],
    "op": "eq",
    "value": "disable"
   },
   "tier": "core",
   "quote": "explicitly disabling default route table association and propagation"
  },
  {
   "id": "tg_no_default_prop",
   "kind": "attr",
   "select": "tg",
   "cond": {
    "path": [
     "DefaultRouteTablePropagation"
    ],
    "op": "eq",
    "value": "disable"
   },
   "tier": "core",
   "quote": "explicitly disabling default route table association and propagation"
  },
  {
   "id": "tg_description",
   "kind": "attr",
   "select": "tg",
   "cond": {
    "path": [
     "Description"
    ],
    "op": "eq",
    "value": "Core-TransitGateway"
   },
   "tier": "detail",
   "quote": "described as \"{EnvironmentName}-TransitGateway\"",
   "justify": "EnvironmentName defaults to Core"
  },
  {
   "id": "tg_conditional",
   "kind": "attr",
   "select": "decl_tg",
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "tier": "detail",
   "quote": "When deployed in the primary transit account",
   "justify": "created only in the primary transit account, i.e. conditionally"
  },
  {
   "id": "share_conditional",
   "kind": "attr",
   "select": "decl_share",
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "tier": "detail",
   "quote": "In addition, it must provision an AWS RAM Resource Share",
   "justify": "the share belongs to the primary transit account branch, so it is conditional too"
  },
  {
   "id": "share",
   "kind": "exists",
   "select": "share",
   "tier": "core",
   "quote": "an AWS RAM Resource Share named after TransitGatewayResourceShareName"
  },
  {
   "id": "share_name",
   "kind": "attr",
   "select": "share",
   "cond": {
    "path": [
     "Name"
    ],
    "op": "eq",
    "value": "Core-TransitGatewayResourceShare"
   },
   "tier": "detail",
   "quote": "named after TransitGatewayResourceShareName",
   "justify": "default of TransitGatewayResourceShareName"
  },
  {
   "id": "share_tg",
   "kind": "ref",
   "from": "share",
   "to": "tg",
   "tier": "core",
   "quote": "shares the created Transit Gateway"
  },
  {
   "id": "share_external",
   "kind": "attr",
   "select": "share",
   "cond": {
    "path": [
     "AllowExternalPrincipals"
    ],
    "op": "present"
   },
   "tier": "detail",
   "quote": "automatically setting allow external principals to true if individual target accounts are configured outside an organization structure"
  },
  {
   "id": "spoke_custom_resource",
   "kind": "attr",
   "select": "decl_custom",
   "cond": {
    "path": [
     "properties",
     "ServiceToken",
     "import"
    ],
    "op": "contains",
    "value": "ReferenceFunctions-TransitGatewayReferenceFunctionArn"
   },
   "tier": "core",
   "quote": "deploy a custom resource using a service token imported from \"{ReferenceFunctionsStackName}-TransitGatewayReferenceFunctionArn\"",
   "justify": "ReferenceFunctionsStackName defaults to ReferenceFunctions"
  },
  {
   "id": "spoke_conditional",
   "kind": "attr",
   "select": "decl_custom",
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "tier": "detail",
   "quote": "If deployed in a secondary spoke account where TransitGatewayAccount is populated with a target account ID"
  },
  {
   "id": "output_export",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "export"
      ],
      "op": "regex",
      "value": "(?i)-TransitGateway$"
     }
    ]
   },
   "to": "tg",
   "tier": "detail",
   "quote": "exporting the resulting Transit Gateway ID output as \"{StackName}-TransitGateway\""
  },
  {
   "id": "x_custom_share_name",
   "kind": "attr",
   "tier": "extra",
   "select": "decl_custom",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "contains",
    "value": "Core-TransitGatewayResourceShare"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
