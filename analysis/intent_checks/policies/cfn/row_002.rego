package intent.cfn.row_002

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "fw": {
   "types": [
    "AWS::Backup::Framework"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "framework",
   "kind": "exists",
   "select": "fw",
   "tier": "core",
   "quote": "creates an AWS Backup Audit Manager framework for backup compliance"
  },
  {
   "id": "control_1",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Backup::Framework"
    ],
    "where": [
     {
      "path": [
       "FrameworkControls",
       "*",
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN"
     }
    ]
   },
   "tier": "core",
   "quote": "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN"
  },
  {
   "id": "control_2",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Backup::Framework"
    ],
    "where": [
     {
      "path": [
       "FrameworkControls",
       "*",
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_RECOVERY_POINT_ENCRYPTED"
     }
    ]
   },
   "tier": "core",
   "quote": "BACKUP_RECOVERY_POINT_ENCRYPTED"
  },
  {
   "id": "control_3",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Backup::Framework"
    ],
    "where": [
     {
      "path": [
       "FrameworkControls",
       "*",
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_RECOVERY_POINT_MANUAL_DELETION_DISABLED"
     }
    ]
   },
   "tier": "core",
   "quote": "BACKUP_RECOVERY_POINT_MANUAL_DELETION_DISABLED"
  },
  {
   "id": "control_4",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Backup::Framework"
    ],
    "where": [
     {
      "path": [
       "FrameworkControls",
       "*",
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK"
     }
    ]
   },
   "tier": "core",
   "quote": "BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK"
  },
  {
   "id": "control_5",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Backup::Framework"
    ],
    "where": [
     {
      "path": [
       "FrameworkControls",
       "*",
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK"
     }
    ]
   },
   "tier": "core",
   "quote": "BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK"
  },
  {
   "id": "controls_in_one_framework",
   "kind": "exists",
   "tier": "core",
   "quote": "including all five default controls",
   "select": {
    "types": [
     "AWS::Backup::Framework"
    ],
    "where": [
     {
      "path": [
       "FrameworkControls",
       "*",
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN"
     },
     {
      "path": [
       "FrameworkControls",
       "*",
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_RECOVERY_POINT_ENCRYPTED"
     },
     {
      "path": [
       "FrameworkControls",
       "*",
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_RECOVERY_POINT_MANUAL_DELETION_DISABLED"
     },
     {
      "path": [
       "FrameworkControls",
       "*",
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK"
     },
     {
      "path": [
       "FrameworkControls",
       "*",
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK"
     }
    ]
   }
  },
  {
   "id": "min_retention_35",
   "kind": "attr",
   "select": "fw",
   "tier": "detail",
   "justify": "The prompt gives the value and the kind of setting, not the API parameter name, so any parameter name saying retention on this control is accepted; the value is the one stated.",
   "quote": "BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK with a required retention of 35 days",
   "cond": {
    "path": [
     "FrameworkControls",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK"
     },
     {
      "path": [
       "ControlInputParameters"
      ],
      "op": "regex",
      "value": "(?i)retention[a-z]*[^}a-z]{0,8}parametervalue[^0-9a-z}]{0,8}35([^0-9]|$)"
     }
    ]
   }
  },
  {
   "id": "plan_retention_35",
   "kind": "attr",
   "select": "fw",
   "tier": "detail",
   "justify": "The prompt gives the value and the kind of setting, not the API parameter name, so any parameter name saying retention on this control is accepted; the value is the one stated.",
   "quote": "BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK with a 35-day retention",
   "cond": {
    "path": [
     "FrameworkControls",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK"
     },
     {
      "path": [
       "ControlInputParameters"
      ],
      "op": "regex",
      "value": "(?i)retention[a-z]*[^}a-z]{0,8}parametervalue[^0-9a-z}]{0,8}35([^0-9]|$)"
     }
    ]
   }
  },
  {
   "id": "plan_freq_unit",
   "kind": "attr",
   "select": "fw",
   "tier": "detail",
   "justify": "The prompt gives the value and the kind of setting, not the API parameter name, so any parameter name saying frequency unit on this control is accepted; the value is the one stated.",
   "quote": "a frequency unit of hours",
   "cond": {
    "path": [
     "FrameworkControls",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK"
     },
     {
      "path": [
       "ControlInputParameters"
      ],
      "op": "regex",
      "value": "(?i)frequency_?unit[a-z]*[^}a-z]{0,8}parametervalue[^0-9a-z}]{0,8}hours"
     }
    ]
   }
  },
  {
   "id": "plan_freq_value",
   "kind": "attr",
   "select": "fw",
   "tier": "detail",
   "justify": "The prompt gives the value and the kind of setting, not the API parameter name, so any parameter name saying frequency value on this control is accepted; the value is the one stated.",
   "quote": "a frequency value of 24",
   "cond": {
    "path": [
     "FrameworkControls",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "ControlName"
      ],
      "op": "eq",
      "value": "BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK"
     },
     {
      "path": [
       "ControlInputParameters"
      ],
      "op": "regex",
      "value": "(?i)frequency_?value[a-z]*[^}a-z]{0,8}parametervalue[^0-9a-z}]{0,8}24([^0-9]|$)"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
