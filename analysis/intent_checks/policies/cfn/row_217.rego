package intent.cfn.row_217

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "ps": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::SSO::PermissionSet"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "four_sets",
   "kind": "exists",
   "select": "ps",
   "tier": "core",
   "quote": "conditionally create four IAM Identity Center permission sets",
   "min": 4,
   "max": 4
  },
  {
   "id": "admin_set",
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
      "value": "AWS::SSO::PermissionSet"
     },
     {
      "path": [
       "properties",
       "Name"
      ],
      "op": "regex",
      "value": "^IdentityCenterAdministrator$"
     },
     {
      "path": [
       "properties",
       "ManagedPolicies",
       "*"
      ],
      "op": "regex",
      "value": "policy/AdministratorAccess$"
     }
    ]
   },
   "tier": "core",
   "quote": "an administrator permission set named \"{LogicalName}Administrator\" with the \"AdministratorAccess\" managed policy attached",
   "justify": "LogicalName defaults to IdentityCenter"
  },
  {
   "id": "poweruser_set",
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
      "value": "AWS::SSO::PermissionSet"
     },
     {
      "path": [
       "properties",
       "Name"
      ],
      "op": "regex",
      "value": "^IdentityCenterPowerUser$"
     },
     {
      "path": [
       "properties",
       "ManagedPolicies",
       "*"
      ],
      "op": "regex",
      "value": "policy/PowerUserAccess$"
     }
    ]
   },
   "tier": "core",
   "quote": "a power user permission set named \"{LogicalName}PowerUser\" with the \"PowerUserAccess\" managed policy attached",
   "justify": "LogicalName defaults to IdentityCenter"
  },
  {
   "id": "orgs_set",
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
      "value": "AWS::SSO::PermissionSet"
     },
     {
      "path": [
       "properties",
       "Name"
      ],
      "op": "regex",
      "value": "^IdentityCenterOrganizationsFull$"
     },
     {
      "path": [
       "properties",
       "ManagedPolicies",
       "*"
      ],
      "op": "regex",
      "value": "policy/AWSOrganizationsFullAccess$"
     }
    ]
   },
   "tier": "core",
   "quote": "an organizations management permission set named \"{LogicalName}OrganizationsFull\" with the \"AWSOrganizationsFullAccess\" managed policy attached",
   "justify": "LogicalName defaults to IdentityCenter"
  },
  {
   "id": "readonly_set",
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
      "value": "AWS::SSO::PermissionSet"
     },
     {
      "path": [
       "properties",
       "Name"
      ],
      "op": "regex",
      "value": "^IdentityCenterReadOnly$"
     },
     {
      "path": [
       "properties",
       "ManagedPolicies",
       "*"
      ],
      "op": "regex",
      "value": "policy/job-function/ViewOnlyAccess$"
     }
    ]
   },
   "tier": "core",
   "quote": "a read-only permission set named \"{LogicalName}ReadOnly\" with the job-function \"ViewOnlyAccess\" managed policy attached",
   "justify": "LogicalName defaults to IdentityCenter"
  },
  {
   "id": "sets_conditional",
   "kind": "attr",
   "select": "ps",
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "tier": "detail",
   "quote": "When InstanceArn is provided, the stack must conditionally create",
   "quantifier": "all"
  },
  {
   "id": "sets_instance",
   "kind": "attr",
   "select": "ps",
   "cond": {
    "path": [
     "properties",
     "InstanceArn"
    ],
    "op": "eq",
    "value": ""
   },
   "tier": "detail",
   "quote": "under that instance ARN",
   "quantifier": "all",
   "justify": "InstanceArn is taken from the parameter, whose default is an empty string"
  },
  {
   "id": "sets_duration",
   "kind": "attr",
   "select": "ps",
   "cond": {
    "path": [
     "properties",
     "SessionDuration"
    ],
    "op": "eq",
    "value": "PT12H"
   },
   "tier": "detail",
   "quote": "using the defined session duration",
   "quantifier": "all",
   "justify": "default of DefaultSessionDuration"
  },
  {
   "id": "sets_tag_env",
   "kind": "attr",
   "select": "ps",
   "cond": {
    "path": [
     "properties",
     "Tags"
    ],
    "op": "regex",
    "value": "(?i)environment\\W{1,8}value\\W{1,4}production"
   },
   "tier": "detail",
   "quote": "each permission set must be tagged with the specified Environment parameter key",
   "quantifier": "all",
   "justify": "Environment defaults to production"
  },
  {
   "id": "sets_tag_custom",
   "kind": "attr",
   "select": "ps",
   "cond": {
    "path": [
     "properties",
     "Tags",
     "*"
    ],
    "op": "has_kv",
    "value": {
     "key": "createdby",
     "value": "aws-cloudformation-templates"
    }
   },
   "tier": "detail",
   "quote": "the custom TagKey and TagValue pair",
   "quantifier": "all",
   "justify": "defaults of TagKey and TagValue"
  },
  {
   "id": "p_instance_arn",
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
      "value": "InstanceArn"
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
   "tier": "core",
   "quote": "InstanceArn (defaulting to an empty string)"
  },
  {
   "id": "p_duration",
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
      "value": "DefaultSessionDuration"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "PT12H"
     }
    ]
   },
   "tier": "core",
   "quote": "DefaultSessionDuration in ISO-8601 format (defaulting to \"PT12H\")"
  },
  {
   "id": "p_logical_name",
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
      "value": "LogicalName"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "IdentityCenter"
     }
    ]
   },
   "tier": "core",
   "quote": "LogicalName prefix (defaulting to \"IdentityCenter\")"
  },
  {
   "id": "p_environment",
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
      "value": "Environment"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "production"
     },
     {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "production"
     },
     {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "test"
     },
     {
      "path": [
       "allowed_values",
       "*"
      ],
      "op": "eq",
      "value": "development"
     }
    ]
   },
   "tier": "core",
   "quote": "Environment (defaulting to \"production\", with allowed values \"production\", \"test\", or \"development\")"
  },
  {
   "id": "p_tag_key",
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
      "value": "TagKey"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "createdby"
     }
    ]
   },
   "tier": "detail",
   "quote": "TagKey (defaulting to \"createdby\")"
  },
  {
   "id": "p_tag_value",
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
      "value": "TagValue"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "aws-cloudformation-templates"
     }
    ]
   },
   "tier": "detail",
   "quote": "TagValue (defaulting to \"aws-cloudformation-templates\")"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
