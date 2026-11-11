package intent.tf.row_351

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "org_exists",
   "kind": "exists",
   "select": {
    "types": [
     "aws_organizations_organization"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "creates an AWS Organization"
  },
  {
   "id": "org_feature_all",
   "kind": "attr",
   "select": {
    "types": [
     "aws_organizations_organization"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "feature_set"
    ],
    "op": "eq",
    "value": "ALL"
   },
   "tier": "core",
   "quote": "with all features enabled"
  },
  {
   "id": "policy_ai_optout",
   "kind": "attr",
   "select": {
    "types": [
     "aws_organizations_organization"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enabled_policy_types",
     "*"
    ],
    "op": "eq",
    "value": "AISERVICES_OPT_OUT_POLICY"
   },
   "tier": "core",
   "quote": "the AI services opt-out, backup, service control, and tag policy types enabled on the organization root",
   "justify": "AI services opt-out policy type enum"
  },
  {
   "id": "policy_backup",
   "kind": "attr",
   "select": {
    "types": [
     "aws_organizations_organization"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enabled_policy_types",
     "*"
    ],
    "op": "eq",
    "value": "BACKUP_POLICY"
   },
   "tier": "core",
   "quote": "the AI services opt-out, backup, service control, and tag policy types enabled on the organization root",
   "justify": "backup policy type enum"
  },
  {
   "id": "policy_scp",
   "kind": "attr",
   "select": {
    "types": [
     "aws_organizations_organization"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enabled_policy_types",
     "*"
    ],
    "op": "eq",
    "value": "SERVICE_CONTROL_POLICY"
   },
   "tier": "core",
   "quote": "the AI services opt-out, backup, service control, and tag policy types enabled on the organization root",
   "justify": "service control policy type enum"
  },
  {
   "id": "policy_tag",
   "kind": "attr",
   "select": {
    "types": [
     "aws_organizations_organization"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enabled_policy_types",
     "*"
    ],
    "op": "eq",
    "value": "TAG_POLICY"
   },
   "tier": "core",
   "quote": "the AI services opt-out, backup, service control, and tag policy types enabled on the organization root",
   "justify": "tag policy type enum"
  },
  {
   "id": "ou_supported",
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
      "value": "aws_organizations_organizational_unit"
     }
    ]
   },
   "tier": "core",
   "quote": "support for optionally defining a nested hierarchy of organizational units"
  },
  {
   "id": "ou_nested",
   "kind": "any_of",
   "checks": [
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
        "value": "aws_organizations_organizational_unit"
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
        "value": "aws_organizations_organizational_unit"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "a nested hierarchy of organizational units up to five levels deep",
   "justify": "nesting means an OU block takes its parent from another OU block"
  },
  {
   "id": "ou_paths_default_empty",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
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
        "value": "(?i)((^|_)ous?(_|$)|organi[sz]ational|unit|path|hierarch)"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "len_eq",
      "value": 0
     }
    },
    {
     "kind": "attr",
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
        "value": "(?i)((^|_)ous?(_|$)|organi[sz]ational|unit|path|hierarch)"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": ""
     }
    }
   ],
   "tier": "detail",
   "quote": "which defaults to empty so no organizational units are created",
   "justify": "prompt says the OU path list defaults to empty; the variable is identified by a word the prompt uses (OU, organizational unit, path, hierarchy)"
  },
  {
   "id": "ou_five_levels",
   "kind": "exists",
   "tier": "detail",
   "quote": "a nested hierarchy of organizational units up to five levels deep",
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
      "value": "aws_organizations_organizational_unit"
     }
    ]
   },
   "min": 5,
   "justify": "Terraform blocks cannot reference themselves, so five nested levels need five chained OU blocks"
  },
  {
   "id": "no_ous_by_default",
   "kind": "exists",
   "tier": "detail",
   "quote": "which defaults to empty so no organizational units are created",
   "select": {
    "types": [
     "aws_organizations_organization",
     "aws_organizations_organizational_unit"
    ],
    "where": []
   },
   "min": 1,
   "max": 1,
   "justify": "the organization is the only one of these created; zero organizational units under defaults"
  },
  {
   "id": "x_ou_gated",
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
      "value": "aws_organizations_organizational_unit"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
