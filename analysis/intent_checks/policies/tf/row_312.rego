package intent.tf.row_312

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "scanw": {
   "types": [
    "aws_ssm_maintenance_window"
   ],
   "where": [
    {
     "path": [
      "schedule"
     ],
     "op": "eq",
     "value": "cron(0 0 18 ? * WED *)"
    }
   ]
  },
  "instw": {
   "types": [
    "aws_ssm_maintenance_window"
   ],
   "where": [
    {
     "path": [
      "schedule"
     ],
     "op": "eq",
     "value": "cron(0 0 21 ? * WED *)"
    }
   ]
  },
  "wins": {
   "types": [
    "aws_ssm_maintenance_window"
   ],
   "where": []
  },
  "tasks": {
   "types": [
    "aws_ssm_maintenance_window_task"
   ],
   "where": []
  },
  "baseline": {
   "types": [
    "aws_ssm_patch_baseline"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "two_windows",
   "tier": "core",
   "quote": "Provision two maintenance windows",
   "kind": "exists",
   "select": "wins",
   "min": 2
  },
  {
   "id": "scan_window_schedule",
   "tier": "core",
   "quote": "a scan window scheduled by default at cron(0 0 18 ? * WED *)",
   "kind": "exists",
   "select": "scanw"
  },
  {
   "id": "install_window_schedule",
   "tier": "core",
   "quote": "an install window scheduled by default at cron(0 0 21 ? * WED *)",
   "kind": "exists",
   "select": "instw"
  },
  {
   "id": "window_duration",
   "tier": "core",
   "quote": "each lasting 3 hours",
   "kind": "attr",
   "select": "wins",
   "cond": {
    "path": [
     "duration"
    ],
    "op": "eq",
    "value": 3
   },
   "quantifier": "all"
  },
  {
   "id": "window_cutoff",
   "tier": "core",
   "quote": "with a 1-hour cutoff",
   "kind": "attr",
   "select": "wins",
   "cond": {
    "path": [
     "cutoff"
    ],
    "op": "eq",
    "value": 1
   },
   "quantifier": "all"
  },
  {
   "id": "scan_target",
   "tier": "core",
   "quote": "defaulting to instances tagged with Patch Group \"TOSCAN\" for scanning",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_ssm_maintenance_window_target"
      ],
      "where": [
       {
        "path": [
         "resource_type"
        ],
        "op": "eq",
        "value": "INSTANCE"
       },
       {
        "path": [
         "targets",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "key"
          ],
          "op": "eq",
          "value": "tag:Patch Group"
         },
         {
          "path": [
           "values",
           "*"
          ],
          "op": "eq",
          "value": "TOSCAN"
         }
        ]
       }
      ]
     },
     "to": "scanw"
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
        "value": "aws_ssm_maintenance_window_target"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "TOSCAN"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "Patch Group"
       }
      ]
     },
     "to": "scanw"
    }
   ]
  },
  {
   "id": "install_target",
   "tier": "core",
   "quote": "\"TOPATCH\" for installing",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_ssm_maintenance_window_target"
      ],
      "where": [
       {
        "path": [
         "resource_type"
        ],
        "op": "eq",
        "value": "INSTANCE"
       },
       {
        "path": [
         "targets",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "key"
          ],
          "op": "eq",
          "value": "tag:Patch Group"
         },
         {
          "path": [
           "values",
           "*"
          ],
          "op": "eq",
          "value": "TOPATCH"
         }
        ]
       }
      ]
     },
     "to": "instw"
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
        "value": "aws_ssm_maintenance_window_target"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "TOPATCH"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "Patch Group"
       }
      ]
     },
     "to": "instw"
    }
   ]
  },
  {
   "id": "explicit_targets_input",
   "tier": "detail",
   "quote": "unless explicit tag targets are provided",
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
      "value": "(?i)target"
     },
     {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "^\\["
     }
    ]
   }
  },
  {
   "id": "run_patch_baseline_tasks",
   "tier": "core",
   "quote": "a Run Command task using the AWS-RunPatchBaseline document",
   "kind": "exists",
   "select": {
    "types": [
     "aws_ssm_maintenance_window_task"
    ],
    "where": [
     {
      "path": [
       "task_arn"
      ],
      "op": "eq",
      "value": "AWS-RunPatchBaseline"
     },
     {
      "path": [
       "task_type"
      ],
      "op": "eq",
      "value": "RUN_COMMAND"
     }
    ]
   },
   "min": 2,
   "justify": "a scan task and an install task make two tasks"
  },
  {
   "id": "task_max_concurrency",
   "tier": "core",
   "quote": "a maximum concurrency of 20",
   "kind": "attr",
   "select": "tasks",
   "cond": {
    "path": [
     "max_concurrency"
    ],
    "op": "eq",
    "value": 20
   },
   "quantifier": "all"
  },
  {
   "id": "task_max_errors",
   "tier": "core",
   "quote": "maximum errors of 50",
   "kind": "attr",
   "select": "tasks",
   "cond": {
    "path": [
     "max_errors"
    ],
    "op": "eq",
    "value": 50
   },
   "quantifier": "all"
  },
  {
   "id": "scan_task_operation",
   "tier": "core",
   "quote": "the scan task runs the Scan operation",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_ssm_maintenance_window_task"
      ],
      "where": [
       {
        "path": [
         "task_arn"
        ],
        "op": "eq",
        "value": "AWS-RunPatchBaseline"
       },
       {
        "path": [
         "task_invocation_parameters",
         "*",
         "run_command_parameters",
         "*",
         "parameter",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "name"
          ],
          "op": "eq",
          "value": "Operation"
         },
         {
          "path": [
           "values",
           "*"
          ],
          "op": "eq",
          "value": "Scan"
         }
        ]
       }
      ]
     },
     "to": "scanw"
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
        "value": "aws_ssm_maintenance_window_task"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "AWS-RunPatchBaseline"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "\\bScan\\b"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "Operation"
       }
      ]
     },
     "to": "scanw"
    }
   ]
  },
  {
   "id": "scan_task_no_reboot",
   "tier": "core",
   "quote": "the scan task runs the Scan operation without rebooting",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ssm_maintenance_window_task"
      ],
      "where": [
       {
        "path": [
         "task_invocation_parameters",
         "*",
         "run_command_parameters",
         "*",
         "parameter",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "name"
          ],
          "op": "eq",
          "value": "Operation"
         },
         {
          "path": [
           "values",
           "*"
          ],
          "op": "eq",
          "value": "Scan"
         }
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "task_invocation_parameters",
       "*",
       "run_command_parameters",
       "*",
       "parameter",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "RebootOption"
       },
       {
        "path": [
         "values",
         "*"
        ],
        "op": "eq",
        "value": "NoReboot"
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
         "aws_ssm_maintenance_window_task"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "\\bScan\\b"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)RebootOption.{0,80}NoReboot"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ssm_maintenance_window_task"
      ],
      "where": [
       {
        "path": [
         "task_invocation_parameters",
         "*",
         "run_command_parameters",
         "*",
         "parameter",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "name"
          ],
          "op": "eq",
          "value": "Operation"
         },
         {
          "path": [
           "values",
           "*"
          ],
          "op": "eq",
          "value": "Scan"
         }
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "task_invocation_parameters",
       "*",
       "run_command_parameters",
       "*",
       "parameter",
       "*",
       "name"
      ],
      "op": "none_eq",
      "value": "RebootOption"
     }
    }
   ]
  },
  {
   "id": "install_task_operation",
   "tier": "core",
   "quote": "the install task runs the Install operation",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_ssm_maintenance_window_task"
      ],
      "where": [
       {
        "path": [
         "task_arn"
        ],
        "op": "eq",
        "value": "AWS-RunPatchBaseline"
       },
       {
        "path": [
         "task_invocation_parameters",
         "*",
         "run_command_parameters",
         "*",
         "parameter",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "name"
          ],
          "op": "eq",
          "value": "Operation"
         },
         {
          "path": [
           "values",
           "*"
          ],
          "op": "eq",
          "value": "Install"
         }
        ]
       }
      ]
     },
     "to": "instw"
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
        "value": "aws_ssm_maintenance_window_task"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "AWS-RunPatchBaseline"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "\\bInstall\\b"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "Operation"
       }
      ]
     },
     "to": "instw"
    }
   ]
  },
  {
   "id": "install_task_reboot",
   "tier": "detail",
   "quote": "the Install operation with a reboot option defaulting to RebootIfNeeded",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ssm_maintenance_window_task"
      ],
      "where": [
       {
        "path": [
         "task_invocation_parameters",
         "*",
         "run_command_parameters",
         "*",
         "parameter",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "name"
          ],
          "op": "eq",
          "value": "Operation"
         },
         {
          "path": [
           "values",
           "*"
          ],
          "op": "eq",
          "value": "Install"
         }
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "task_invocation_parameters",
       "*",
       "run_command_parameters",
       "*",
       "parameter",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "RebootOption"
       },
       {
        "path": [
         "values",
         "*"
        ],
        "op": "eq",
        "value": "RebootIfNeeded"
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
         "aws_ssm_maintenance_window_task"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "\\bInstall\\b"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)RebootOption.{0,80}RebootIfNeeded"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "s3_log_prefix_scanning",
   "tier": "detail",
   "quote": "Command output should go to an S3 log bucket under a \"scanning\" prefix by default",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_ssm_maintenance_window_task"
      ],
      "where": [
       {
        "path": [
         "task_invocation_parameters",
         "*",
         "run_command_parameters",
         "*",
         "parameter",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "name"
          ],
          "op": "eq",
          "value": "Operation"
         },
         {
          "path": [
           "values",
           "*"
          ],
          "op": "eq",
          "value": "Scan"
         }
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "task_invocation_parameters",
       "*",
       "run_command_parameters",
       "*",
       "output_s3_key_prefix"
      ],
      "op": "eq",
      "value": "scanning"
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
        "value": "(?i)prefix"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": "scanning"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sns_optional",
   "tier": "detail",
   "quote": "optional SNS notifications",
   "kind": "any_of",
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
        "op": "in",
        "value": [
         "aws_ssm_maintenance_window_task"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)notification_config"
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
        "value": "(?i)(sns|notif)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cloudwatch_optional",
   "tier": "detail",
   "quote": "CloudWatch Logs output",
   "kind": "any_of",
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
        "op": "in",
        "value": [
         "aws_ssm_maintenance_window_task"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)cloudwatch_config"
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
        "value": "(?i)cloudwatch"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sns_disabled_default",
   "tier": "detail",
   "quote": "optional SNS notifications and CloudWatch Logs output both disabled by default",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "tasks",
     "cond": {
      "path": [
       "task_invocation_parameters",
       "*",
       "run_command_parameters",
       "*",
       "notification_config"
      ],
      "op": "len_eq",
      "value": 0
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": "tasks",
     "cond": {
      "path": [
       "task_invocation_parameters",
       "*",
       "run_command_parameters",
       "*",
       "notification_config"
      ],
      "op": "absent"
     },
     "quantifier": "all"
    }
   ]
  },
  {
   "id": "cloudwatch_disabled_default",
   "tier": "detail",
   "quote": "optional SNS notifications and CloudWatch Logs output both disabled by default",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "tasks",
     "cond": {
      "path": [
       "task_invocation_parameters",
       "*",
       "run_command_parameters",
       "*",
       "cloudwatch_config"
      ],
      "op": "len_eq",
      "value": 0
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": "tasks",
     "cond": {
      "path": [
       "task_invocation_parameters",
       "*",
       "run_command_parameters",
       "*",
       "cloudwatch_config"
      ],
      "op": "absent"
     },
     "quantifier": "all"
    }
   ]
  },
  {
   "id": "log_bucket_policy_account",
   "tier": "detail",
   "quote": "whose policy grants the account read and write access",
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
       "aws_s3_bucket_policy",
       "data.aws_iam_policy_document"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "s3:GetObject"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "s3:PutObject"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)(:root|account)"
     }
    ]
   },
   "justify": "read and write access means GetObject and PutObject"
  },
  {
   "id": "baseline_os",
   "tier": "core",
   "quote": "an AMAZON_LINUX_2 patch baseline",
   "kind": "attr",
   "select": "baseline",
   "cond": {
    "path": [
     "operating_system"
    ],
    "op": "eq",
    "value": "AMAZON_LINUX_2"
   }
  },
  {
   "id": "baseline_approved_compliance",
   "tier": "core",
   "quote": "with a HIGH compliance level for approved patches",
   "kind": "attr",
   "select": "baseline",
   "cond": {
    "path": [
     "approved_patches_compliance_level"
    ],
    "op": "eq",
    "value": "HIGH"
   }
  },
  {
   "id": "baseline_approve_after_7",
   "tier": "core",
   "quote": "after 7 days",
   "kind": "attr",
   "select": "baseline",
   "cond": {
    "path": [
     "approval_rule",
     "*",
     "approve_after_days"
    ],
    "op": "eq",
    "value": 7
   }
  },
  {
   "id": "baseline_non_security",
   "tier": "detail",
   "quote": "with non-security updates enabled",
   "kind": "attr",
   "select": "baseline",
   "cond": {
    "path": [
     "approval_rule",
     "*",
     "enable_non_security"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "baseline_severities",
   "tier": "core",
   "quote": "automatically approves Critical, Important, and Medium severity",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "baseline",
     "cond": {
      "path": [
       "approval_rule",
       "*",
       "patch_filter",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "key"
        ],
        "op": "eq",
        "value": "SEVERITY"
       },
       {
        "path": [
         "values",
         "*"
        ],
        "op": "eq",
        "value": "Critical"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "baseline",
     "cond": {
      "path": [
       "approval_rule",
       "*",
       "patch_filter",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "key"
        ],
        "op": "eq",
        "value": "SEVERITY"
       },
       {
        "path": [
         "values",
         "*"
        ],
        "op": "eq",
        "value": "Important"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "baseline",
     "cond": {
      "path": [
       "approval_rule",
       "*",
       "patch_filter",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "key"
        ],
        "op": "eq",
        "value": "SEVERITY"
       },
       {
        "path": [
         "values",
         "*"
        ],
        "op": "eq",
        "value": "Medium"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "baseline_classifications",
   "tier": "core",
   "quote": "Security, Bugfix, and Recommended patches",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "baseline",
     "cond": {
      "path": [
       "approval_rule",
       "*",
       "patch_filter",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "key"
        ],
        "op": "eq",
        "value": "CLASSIFICATION"
       },
       {
        "path": [
         "values",
         "*"
        ],
        "op": "eq",
        "value": "Security"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "baseline",
     "cond": {
      "path": [
       "approval_rule",
       "*",
       "patch_filter",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "key"
        ],
        "op": "eq",
        "value": "CLASSIFICATION"
       },
       {
        "path": [
         "values",
         "*"
        ],
        "op": "eq",
        "value": "Bugfix"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "baseline",
     "cond": {
      "path": [
       "approval_rule",
       "*",
       "patch_filter",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "key"
        ],
        "op": "eq",
        "value": "CLASSIFICATION"
       },
       {
        "path": [
         "values",
         "*"
        ],
        "op": "eq",
        "value": "Recommended"
       }
      ]
     }
    }
   ],
   "justify": "Security, Bugfix, Recommended are classification values, matched in the CLASSIFICATION patch filter"
  },
  {
   "id": "baseline_product",
   "tier": "detail",
   "quote": "for Amazon Linux 2",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "baseline",
     "cond": {
      "path": [
       "approval_rule"
      ],
      "op": "regex",
      "value": "AmazonLinux2"
     }
    },
    {
     "kind": "attr",
     "select": "baseline",
     "cond": {
      "path": [
       "operating_system"
      ],
      "op": "eq",
      "value": "AMAZON_LINUX_2"
     }
    }
   ]
  },
  {
   "id": "scan_patch_group",
   "tier": "core",
   "quote": "register both patch groups against that baseline",
   "kind": "ref",
   "from": {
    "types": [
     "aws_ssm_patch_group"
    ],
    "where": [
     {
      "path": [
       "patch_group"
      ],
      "op": "eq",
      "value": "TOSCAN"
     }
    ]
   },
   "to": "baseline"
  },
  {
   "id": "install_patch_group",
   "tier": "core",
   "quote": "register both patch groups against that baseline",
   "kind": "ref",
   "from": {
    "types": [
     "aws_ssm_patch_group"
    ],
    "where": [
     {
      "path": [
       "patch_group"
      ],
      "op": "eq",
      "value": "TOPATCH"
     }
    ]
   },
   "to": "baseline"
  },
  {
   "id": "window_enabled",
   "tier": "extra",
   "kind": "attr",
   "select": "wins",
   "cond": {
    "path": [
     "enabled"
    ],
    "op": "truthy"
   },
   "quantifier": "all"
  },
  {
   "id": "no_unassociated_targets",
   "tier": "extra",
   "kind": "attr",
   "select": "wins",
   "cond": {
    "path": [
     "allow_unassociated_targets"
    ],
    "op": "falsy"
   },
   "quantifier": "all"
  },
  {
   "id": "task_priority_1",
   "tier": "extra",
   "kind": "attr",
   "select": "tasks",
   "cond": {
    "path": [
     "priority"
    ],
    "op": "eq",
    "value": 1
   },
   "quantifier": "all"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
