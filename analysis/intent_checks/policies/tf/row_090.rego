# GENERATED from specs/tf/row_090.json by intent_checks/build.py -- do not edit.
package intent.tf.row_090

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pool": {
   "types": [
    "aws_cognito_user_pool"
   ],
   "where": []
  },
  "client": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_cognito_user_pool_client"
    }
   ]
  },
  "pool_decl": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_cognito_user_pool"
    }
   ]
  },
  "r53_decl": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_route53_record"
    }
   ]
  },
  "group_decl": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_cognito_user_group"
    }
   ]
  },
  "domain_decl": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_cognito_user_pool_domain"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "pool_named",
   "kind": "exists",
   "tier": "core",
   "quote": "the pool name (\"Pool name\")",
   "select": {
    "types": [
     "aws_cognito_user_pool"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "Pool name"
     }
    ]
   }
  },
  {
   "id": "alias_attributes",
   "kind": "all_of",
   "tier": "core",
   "quote": "alias attributes ([\"email\", \"phone_number\"])",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "alias_attributes",
       "*"
      ],
      "op": "eq",
      "value": "email"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "alias_attributes",
       "*"
      ],
      "op": "eq",
      "value": "phone_number"
     }
    }
   ]
  },
  {
   "id": "mfa_optional",
   "kind": "attr",
   "select": "pool",
   "tier": "core",
   "quote": "MFA configuration (\"OPTIONAL\")",
   "cond": {
    "path": [
     "mfa_configuration"
    ],
    "op": "eq",
    "value": "OPTIONAL"
   }
  },
  {
   "id": "software_token_mfa",
   "kind": "attr",
   "select": "pool",
   "tier": "core",
   "quote": "software token MFA enabling (defaulting to true)",
   "cond": {
    "path": [
     "software_token_mfa_configuration",
     "*",
     "enabled"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "recovery_mechanisms",
   "kind": "all_of",
   "tier": "core",
   "quote": "recovery mechanisms (verified_email with priority 2, verified_phone_number with priority 1)",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "account_recovery_setting",
       "*",
       "recovery_mechanism",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "verified_email"
       },
       {
        "path": [
         "priority"
        ],
        "op": "eq",
        "value": 2
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "account_recovery_setting",
       "*",
       "recovery_mechanism",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "verified_phone_number"
       },
       {
        "path": [
         "priority"
        ],
        "op": "eq",
        "value": 1
       }
      ]
     }
    }
   ]
  },
  {
   "id": "schema_email_attribute",
   "kind": "attr",
   "select": "pool",
   "tier": "core",
   "quote": "custom schema definitions (defaulting to a required, mutable string email attribute)",
   "cond": {
    "path": [
     "schema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "email"
     },
     {
      "path": [
       "attribute_data_type"
      ],
      "op": "eq",
      "value": "String"
     },
     {
      "path": [
       "required"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "mutable"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "client_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "creating User Pool Clients",
   "select": "client",
   "justify": "Terraform resource type named by the prompt: User Pool Clients -> aws_cognito_user_pool_client"
  },
  {
   "id": "user_group_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "conditionally create a Cognito user group",
   "select": "group_decl",
   "justify": "Terraform resource type named by the prompt: Cognito user group -> aws_cognito_user_group"
  },
  {
   "id": "domain_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "a Cognito User Pool domain when a domain string variable is non-empty",
   "select": "domain_decl",
   "justify": "Terraform resource type named by the prompt: Cognito User Pool domain -> aws_cognito_user_pool_domain"
  },
  {
   "id": "route53_record_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "an alias Route 53 A-record targeting the domain CloudFront distribution ARN",
   "select": "r53_decl",
   "justify": "Terraform resource type named by the prompt: Route 53 A-record -> aws_route53_record"
  },
  {
   "id": "email_verification_message",
   "kind": "any_of",
   "tier": "detail",
   "quote": "email verification message (\"Some message {####}\")",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "email_verification_message"
      ],
      "op": "eq",
      "value": "Some message {####}"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "verification_message_template",
       "*",
       "email_message"
      ],
      "op": "eq",
      "value": "Some message {####}"
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
        "value": "Some message {####}"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "email_verification_subject",
   "kind": "any_of",
   "tier": "detail",
   "quote": "email verification subject (\"Some subject\")",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "email_verification_subject"
      ],
      "op": "eq",
      "value": "Some subject"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "verification_message_template",
       "*",
       "email_subject"
      ],
      "op": "eq",
      "value": "Some subject"
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
        "value": "Some subject"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sms_authentication_message",
   "kind": "attr",
   "select": "pool",
   "tier": "detail",
   "quote": "SMS authentication message (\"SMS authentication message {####}\")",
   "cond": {
    "path": [
     "sms_authentication_message"
    ],
    "op": "eq",
    "value": "SMS authentication message {####}"
   }
  },
  {
   "id": "sms_verification_message",
   "kind": "any_of",
   "tier": "detail",
   "quote": "SMS verification message (\"SMS verification message {####}\")",
   "checks": [
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "sms_verification_message"
      ],
      "op": "eq",
      "value": "SMS verification message {####}"
     }
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "verification_message_template",
       "*",
       "sms_message"
      ],
      "op": "eq",
      "value": "SMS verification message {####}"
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
        "value": "SMS verification message {####}"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "verification_template_by_link",
   "kind": "any_of",
   "tier": "detail",
   "quote": "verification message template by link",
   "checks": [
    {
     "select": "pool",
     "cond": {
      "path": [
       "verification_message_template",
       "*",
       "email_message_by_link"
      ],
      "op": "present"
     },
     "kind": "attr"
    },
    {
     "kind": "attr",
     "select": "pool",
     "cond": {
      "path": [
       "verification_message_template",
       "*",
       "default_email_option"
      ],
      "op": "eq",
      "value": "CONFIRM_WITH_LINK"
     }
    },
    {
     "kind": "attr",
     "select": "pool_decl",
     "cond": {
      "path": [
       "properties",
       "verification_message_template"
      ],
      "op": "contains",
      "value": "by_link"
     }
    }
   ]
  },
  {
   "id": "invite_message_template",
   "kind": "any_of",
   "tier": "detail",
   "quote": "invite message templates",
   "checks": [
    {
     "select": "pool",
     "cond": {
      "path": [
       "admin_create_user_config",
       "*",
       "invite_message_template",
       "*"
      ],
      "op": "present"
     },
     "kind": "attr"
    },
    {
     "kind": "attr",
     "select": "pool_decl",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "invite_message_template"
     }
    }
   ]
  },
  {
   "id": "admin_create_user_only_false",
   "kind": "attr",
   "select": "pool",
   "tier": "detail",
   "quote": "admin create user only flag (defaulting to false)",
   "cond": {
    "path": [
     "admin_create_user_config",
     "*",
     "allow_admin_create_user_only"
    ],
    "op": "falsy"
   }
  },
  {
   "id": "auto_verified_empty",
   "kind": "attr",
   "select": "pool",
   "tier": "detail",
   "quote": "auto-verified attributes (defaulting to empty)",
   "cond": {
    "path": [
     "auto_verified_attributes"
    ],
    "op": "absent"
   }
  },
  {
   "id": "sms_configuration_conditional",
   "kind": "attr",
   "select": "pool",
   "tier": "detail",
   "quote": "conditionally provision SMS configuration when both external ID and SNS caller ARN are non-empty",
   "cond": {
    "path": [
     "sms_configuration"
    ],
    "op": "absent"
   }
  },
  {
   "id": "param_create_route53_record",
   "kind": "exists",
   "tier": "detail",
   "quote": "a create_route53_record boolean flag defaulting to false",
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
      "value": "create_route53_record"
     },
     {
      "path": [
       "default"
      ],
      "op": "falsy"
     }
    ]
   }
  },
  {
   "id": "client_generate_secret_false",
   "kind": "any_of",
   "tier": "detail",
   "quote": "generate_secret defaulting to false",
   "checks": [
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [
       "properties",
       "generate_secret"
      ],
      "op": "regex",
      "value": "false"
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [
       "properties",
       "generate_secret"
      ],
      "op": "absent"
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
        "op": "regex",
        "value": "(?i)generate_secret\\W{0,6}false"
       }
      ]
     }
    }
   ],
   "justify": "selects the User Pool Client resource type; value from prompt; the default may live in a client variable/map default"
  },
  {
   "id": "client_token_validities",
   "kind": "any_of",
   "tier": "core",
   "quote": "token validities (access token: 120, ID token: 120, refresh token: 7)",
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
        "value": "aws_cognito_user_pool_client"
       },
       {
        "path": [
         "properties",
         "access_token_validity"
        ],
        "op": "regex",
        "value": "(^|[^0-9])120([^0-9]|$)"
       },
       {
        "path": [
         "properties",
         "id_token_validity"
        ],
        "op": "regex",
        "value": "(^|[^0-9])120([^0-9]|$)"
       },
       {
        "path": [
         "properties",
         "refresh_token_validity"
        ],
        "op": "regex",
        "value": "(^|[^0-9])7([^0-9]|$)"
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
         "default",
         "access_token"
        ],
        "op": "eq",
        "value": 120
       },
       {
        "path": [
         "default",
         "id_token"
        ],
        "op": "eq",
        "value": 120
       },
       {
        "path": [
         "default",
         "refresh_token"
        ],
        "op": "eq",
        "value": 7
       }
      ]
     }
    }
   ],
   "justify": "values from prompt; accepted as literals on the declared client or as a variable default map"
  },
  {
   "id": "client_token_validity_units",
   "kind": "any_of",
   "tier": "detail",
   "quote": "token_validity_units (access_token: \"minutes\", id_token: \"minutes\", refresh_token: \"days\")",
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
         "default",
         "access_token"
        ],
        "op": "eq",
        "value": "minutes"
       },
       {
        "path": [
         "default",
         "id_token"
        ],
        "op": "eq",
        "value": "minutes"
       },
       {
        "path": [
         "default",
         "refresh_token"
        ],
        "op": "eq",
        "value": "days"
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
        "value": "aws_cognito_user_pool_client"
       },
       {
        "path": [
         "properties",
         "token_validity_units",
         "*",
         "access_token"
        ],
        "op": "contains",
        "value": "minutes"
       },
       {
        "path": [
         "properties",
         "token_validity_units",
         "*",
         "id_token"
        ],
        "op": "contains",
        "value": "minutes"
       },
       {
        "path": [
         "properties",
         "token_validity_units",
         "*",
         "refresh_token"
        ],
        "op": "contains",
        "value": "days"
       }
      ]
     }
    }
   ],
   "justify": "selects the User Pool Client resource type; values from prompt"
  },
  {
   "id": "client_oauth_flag_false",
   "kind": "any_of",
   "tier": "detail",
   "quote": "allowed OAuth user pool client flag (defaulting to false)",
   "checks": [
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [
       "properties",
       "allowed_oauth_flows_user_pool_client"
      ],
      "op": "regex",
      "value": "false"
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
        "op": "regex",
        "value": "(?i)oauth_flows_user_pool\\W{0,6}false"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)oauth_flows_user_pool[^,]{0,80}try\\([^)]*,\\s*false\\)"
     }
    }
   ],
   "justify": "selects the User Pool Client resource type; value from prompt; the default may live in a client variable/map default"
  },
  {
   "id": "client_token_revocation",
   "kind": "any_of",
   "tier": "detail",
   "quote": "token revocation (defaulting to true)",
   "checks": [
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [
       "properties",
       "enable_token_revocation"
      ],
      "op": "regex",
      "value": "true"
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
        "op": "regex",
        "value": "(?i)token_revocation\\W{0,6}true"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "client",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)token_revocation[^,]{0,80}try\\([^)]*,\\s*true\\)"
     }
    }
   ],
   "justify": "selects the User Pool Client resource type; value from prompt; the default may live in a client variable/map default"
  },
  {
   "id": "client_explicit_auth_flows",
   "kind": "exists",
   "tier": "core",
   "quote": "explicit auth flows ([\"ALLOW_REFRESH_TOKEN_AUTH\", \"ALLOW_USER_PASSWORD_AUTH\", \"ALLOW_USER_SRP_AUTH\"])",
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
      "value": "aws_cognito_user_pool_client"
     },
     {
      "path": [
       "properties",
       "explicit_auth_flows"
      ],
      "op": "contains",
      "value": "ALLOW_REFRESH_TOKEN_AUTH"
     },
     {
      "path": [
       "properties",
       "explicit_auth_flows"
      ],
      "op": "contains",
      "value": "ALLOW_USER_PASSWORD_AUTH"
     },
     {
      "path": [
       "properties",
       "explicit_auth_flows"
      ],
      "op": "contains",
      "value": "ALLOW_USER_SRP_AUTH"
     }
    ]
   },
   "justify": "selects the User Pool Client resource type; values from prompt"
  },
  {
   "id": "client_prevent_user_existence_errors",
   "kind": "attr",
   "select": "client",
   "tier": "detail",
   "quote": "prevent_user_existence_errors (\"LEGACY\")",
   "cond": {
    "path": [
     "properties",
     "prevent_user_existence_errors"
    ],
    "op": "contains",
    "value": "LEGACY"
   },
   "justify": "selects the User Pool Client resource type; value from prompt"
  },
  {
   "id": "client_per_app_name",
   "kind": "attr",
   "select": "client",
   "tier": "detail",
   "quote": "support dynamic iteration over a list of client app names",
   "cond": {
    "path": [
     "properties",
     "for_each"
    ],
    "op": "present"
   },
   "justify": "'dynamic iteration over a list of client app names' -> the client resource uses for_each/count"
  },
  {
   "id": "group_precedence_zero",
   "kind": "any_of",
   "tier": "detail",
   "quote": "accepting precedence defaulting to 0",
   "justify": "selects the Cognito user group resource type; value from prompt",
   "checks": [
    {
     "kind": "attr",
     "select": "group_decl",
     "cond": {
      "path": [
       "properties",
       "precedence"
      ],
      "op": "regex",
      "value": "(^|[^0-9])0([^0-9]|$)"
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
        "value": "(?i)precedence"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": 0
       }
      ]
     }
    }
   ]
  },
  {
   "id": "route53_alias_cloudfront_zone",
   "kind": "any_of",
   "tier": "core",
   "quote": "using fixed CloudFront zone ID \"Z2FDTNDATAQYW2\"",
   "checks": [
    {
     "kind": "attr",
     "select": "r53_decl",
     "cond": {
      "path": [
       "properties",
       "alias",
       "*",
       "zone_id"
      ],
      "op": "contains",
      "value": "Z2FDTNDATAQYW2"
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
        "value": "Z2FDTNDATAQYW2"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "r53_decl",
     "cond": {
      "path": [
       "properties",
       "alias",
       "*",
       "zone_id"
      ],
      "op": "regex",
      "value": "(?i)local\\.\\w*cloudfront\\w*zone"
     }
    }
   ],
   "justify": "selects the Route 53 record resource type; zone ID from prompt; a fixed zone ID held in a local named for the CloudFront zone is invisible to the input, so the named local is accepted"
  },
  {
   "id": "route53_a_record_to_domain",
   "kind": "all_of",
   "tier": "detail",
   "quote": "an alias Route 53 A-record targeting the domain CloudFront distribution ARN",
   "checks": [
    {
     "kind": "attr",
     "select": "r53_decl",
     "cond": {
      "path": [
       "properties",
       "type"
      ],
      "op": "eq",
      "value": "A"
     }
    },
    {
     "kind": "attr",
     "select": "r53_decl",
     "cond": {
      "path": [
       "properties",
       "alias",
       "*",
       "name"
      ],
      "op": "contains",
      "value": "cloudfront_distribution"
     }
    }
   ],
   "justify": "record type A and target 'domain CloudFront distribution ARN' (the domain's cloudfront_distribution_arn attribute) are stated in the prompt"
  },
  {
   "id": "ignore_estimated_users",
   "kind": "attr",
   "select": "pool_decl",
   "tier": "detail",
   "quote": "ignoring changes to estimated_number_of_users",
   "cond": {
    "path": [
     "properties",
     "lifecycle",
     "*",
     "ignore_changes"
    ],
    "op": "contains",
    "value": "estimated_number_of_users"
   },
   "justify": "selects the user pool resource type; attribute named in prompt"
  },
  {
   "id": "conditional_pool_blocks",
   "kind": "all_of",
   "tier": "detail",
   "quote": "username case sensitivity, device configuration, custom email sender Lambda triggers",
   "checks": [
    {
     "kind": "attr",
     "select": "pool_decl",
     "cond": {
      "path": [
       "properties",
       "dynamic"
      ],
      "op": "contains",
      "value": "username_configuration"
     }
    },
    {
     "kind": "attr",
     "select": "pool_decl",
     "cond": {
      "path": [
       "properties",
       "dynamic"
      ],
      "op": "contains",
      "value": "device_configuration"
     }
    },
    {
     "kind": "attr",
     "select": "pool_decl",
     "cond": {
      "path": [
       "properties",
       "dynamic"
      ],
      "op": "contains",
      "value": "custom_email_sender"
     }
    }
   ],
   "justify": "'username case sensitivity', 'device configuration', 'custom email sender' are the username_configuration / device_configuration / custom_email_sender blocks; 'conditionally' -> dynamic blocks"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
