package intent.cfn.row_263

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "r_action_check",
   "kind": "any_of",
   "tier": "core",
   "quote": "one checking that CloudWatch alarms have the required actions configured",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConfigRule"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Source"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Owner"
        ],
        "op": "eq",
        "value": "AWS"
       },
       {
        "path": [
         "SourceIdentifier"
        ],
        "op": "eq",
        "value": "CLOUDWATCH_ALARM_ACTION_CHECK"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConformancePack"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "TemplateBody"
      ],
      "op": "contains",
      "value": "CLOUDWATCH_ALARM_ACTION_CHECK"
     }
    }
   ]
  },
  {
   "id": "r_action_enabled",
   "kind": "any_of",
   "tier": "core",
   "quote": "one checking that alarm actions are actually enabled",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConfigRule"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Source"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Owner"
        ],
        "op": "eq",
        "value": "AWS"
       },
       {
        "path": [
         "SourceIdentifier"
        ],
        "op": "eq",
        "value": "CLOUDWATCH_ALARM_ACTION_ENABLED_CHECK"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConformancePack"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "TemplateBody"
      ],
      "op": "contains",
      "value": "CLOUDWATCH_ALARM_ACTION_ENABLED_CHECK"
     }
    }
   ]
  },
  {
   "id": "r_resource_check",
   "kind": "any_of",
   "tier": "core",
   "quote": "one checking that an alarm exists for a given metric and resource type",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConfigRule"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Source"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Owner"
        ],
        "op": "eq",
        "value": "AWS"
       },
       {
        "path": [
         "SourceIdentifier"
        ],
        "op": "eq",
        "value": "CLOUDWATCH_ALARM_RESOURCE_CHECK"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConformancePack"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "TemplateBody"
      ],
      "op": "contains",
      "value": "CLOUDWATCH_ALARM_RESOURCE_CHECK"
     }
    }
   ]
  },
  {
   "id": "r_settings_check",
   "kind": "any_of",
   "tier": "core",
   "quote": "one checking alarm settings for a given metric",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConfigRule"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Source"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Owner"
        ],
        "op": "eq",
        "value": "AWS"
       },
       {
        "path": [
         "SourceIdentifier"
        ],
        "op": "eq",
        "value": "CLOUDWATCH_ALARM_SETTINGS_CHECK"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConformancePack"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "TemplateBody"
      ],
      "op": "contains",
      "value": "CLOUDWATCH_ALARM_SETTINGS_CHECK"
     }
    }
   ]
  },
  {
   "id": "r_log_encrypted",
   "kind": "any_of",
   "tier": "core",
   "quote": "one checking that CloudWatch log groups are encrypted",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConfigRule"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Source"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Owner"
        ],
        "op": "eq",
        "value": "AWS"
       },
       {
        "path": [
         "SourceIdentifier"
        ],
        "op": "eq",
        "value": "CLOUDWATCH_LOG_GROUP_ENCRYPTED"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConformancePack"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "TemplateBody"
      ],
      "op": "contains",
      "value": "CLOUDWATCH_LOG_GROUP_ENCRYPTED"
     }
    }
   ]
  },
  {
   "id": "scope_alarms",
   "tier": "core",
   "quote": "The first four should be scoped to CloudWatch alarm resources",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConfigRule"
      ],
      "where": [
       {
        "path": [
         "Source",
         "SourceIdentifier"
        ],
        "op": "in",
        "value": [
         "CLOUDWATCH_ALARM_ACTION_CHECK",
         "CLOUDWATCH_ALARM_ACTION_ENABLED_CHECK",
         "CLOUDWATCH_ALARM_SETTINGS_CHECK"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "Scope",
       "ComplianceResourceTypes",
       "*"
      ],
      "op": "eq",
      "value": "AWS::CloudWatch::Alarm"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConformancePack"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "TemplateBody"
      ],
      "op": "regex",
      "value": "(?s)(ComplianceResourceTypes.{0,80}AWS::CloudWatch::Alarm.*){3}"
     }
    }
   ]
  },
  {
   "id": "params_exist",
   "tier": "core",
   "quote": "Expose the rule inputs as parameters",
   "justify": "the stated defaults are three action flags, a metric and a resource type; a pack may hold its parameters itself",
   "kind": "any_of",
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
         "default"
        ],
        "op": "in",
        "value": [
         "true",
         "false",
         "CPUUtilization",
         "AWS::EC2::Instance"
        ]
       }
      ]
     },
     "min": 3
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConformancePack"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "ConformancePackInputParameters"
      ],
      "op": "len_gte",
      "value": 3
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConformancePack"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "TemplateBody"
      ],
      "op": "regex",
      "value": "(?s)((^|\\n)Parameters:|\"Parameters\"\\s*:).*Default"
     }
    }
   ]
  },
  {
   "id": "in_alarm_action",
   "tier": "detail",
   "quote": "defaulting to requiring alarm actions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConfigRule"
      ],
      "where": [
       {
        "path": [
         "Source",
         "SourceIdentifier"
        ],
        "op": "eq",
        "value": "CLOUDWATCH_ALARM_ACTION_CHECK"
       }
      ]
     },
     "cond": {
      "path": [
       "InputParameters"
      ],
      "op": "regex",
      "value": "(?i)alarmActionRequired\"?:\\s*\"?true"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConformancePack"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "TemplateBody"
      ],
      "op": "regex",
      "value": "(?is)alarmActionRequired\\W{1,6}true"
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
        "value": "(?i)^alarm.?actions?(.?required)?$"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "true"
     }
    }
   ],
   "justify": "'requiring' means the flag is true"
  },
  {
   "id": "in_insufficient",
   "tier": "detail",
   "quote": "insufficient-data actions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConfigRule"
      ],
      "where": [
       {
        "path": [
         "Source",
         "SourceIdentifier"
        ],
        "op": "eq",
        "value": "CLOUDWATCH_ALARM_ACTION_CHECK"
       }
      ]
     },
     "cond": {
      "path": [
       "InputParameters"
      ],
      "op": "regex",
      "value": "(?i)insufficientDataActionRequired\"?:\\s*\"?true"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConformancePack"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "TemplateBody"
      ],
      "op": "regex",
      "value": "(?is)insufficientDataActionRequired\\W{1,6}true"
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
        "value": "(?i)insufficient.?data"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "true"
     }
    }
   ],
   "justify": "'requiring' means the flag is true"
  },
  {
   "id": "in_ok_not",
   "tier": "detail",
   "quote": "but not OK actions",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConfigRule"
      ],
      "where": [
       {
        "path": [
         "Source",
         "SourceIdentifier"
        ],
        "op": "eq",
        "value": "CLOUDWATCH_ALARM_ACTION_CHECK"
       }
      ]
     },
     "cond": {
      "path": [
       "InputParameters",
       "okActionRequired"
      ],
      "op": "regex",
      "value": "(?i)^false$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConformancePack"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "TemplateBody"
      ],
      "op": "regex",
      "value": "(?is)okActionRequired\\W{1,6}false"
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
        "value": "(?i)^ok.?actions?"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "false"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConfigRule"
      ],
      "where": [
       {
        "path": [
         "Source",
         "SourceIdentifier"
        ],
        "op": "eq",
        "value": "CLOUDWATCH_ALARM_ACTION_CHECK"
       }
      ]
     },
     "cond": {
      "path": [
       "InputParameters",
       "okActionRequired"
      ],
      "op": "absent"
     }
    }
   ],
   "justify": "'not OK actions' means the flag is false, or left out because false is the rule's default"
  },
  {
   "id": "in_metric",
   "tier": "detail",
   "quote": "checking the CPUUtilization metric",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConfigRule"
      ],
      "where": [
       {
        "path": [
         "Source",
         "SourceIdentifier"
        ],
        "op": "in",
        "value": [
         "CLOUDWATCH_ALARM_RESOURCE_CHECK",
         "CLOUDWATCH_ALARM_SETTINGS_CHECK"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "InputParameters"
      ],
      "op": "contains",
      "value": "CPUUtilization"
     },
     "quantifier": "all"
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
        "value": "(?i)metric"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "CPUUtilization"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConformancePack"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "TemplateBody"
      ],
      "op": "regex",
      "value": "(?i)metricName\\W{1,6}CPUUtilization"
     }
    }
   ]
  },
  {
   "id": "in_resource_type",
   "tier": "detail",
   "quote": "on EC2 instances",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConfigRule"
      ],
      "where": [
       {
        "path": [
         "Source",
         "SourceIdentifier"
        ],
        "op": "eq",
        "value": "CLOUDWATCH_ALARM_RESOURCE_CHECK"
       }
      ]
     },
     "cond": {
      "path": [
       "InputParameters"
      ],
      "op": "contains",
      "value": "AWS::EC2::Instance"
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
        "value": "(?i)resource.?type"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "AWS::EC2::Instance"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::Config::ConformancePack"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "TemplateBody"
      ],
      "op": "regex",
      "value": "(?i)resourceType\\W{1,6}AWS::EC2::Instance"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
