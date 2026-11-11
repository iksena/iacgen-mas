package intent.cfn.row_055

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "doc": {
   "types": [
    "AWS::SSM::Document"
   ],
   "where": []
  },
  "assoc": {
   "types": [
    "AWS::SSM::Association"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "linux_param",
   "kind": "exists",
   "tier": "core",
   "quote": "Linux process keywords defaulting to \"CassandraDaemon,dse cassandra,mysql,postgres,redis-server,redis-sentinel,memcached\"",
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
      "value": "CassandraDaemon,dse cassandra,mysql,postgres,redis-server,redis-sentinel,memcached"
     }
    ]
   }
  },
  {
   "id": "windows_param",
   "kind": "exists",
   "tier": "core",
   "quote": "Windows process keywords defaulting to \"sqlservr,cassandra,mysql,postgres,redis-server,redis-sentinel,memcached\"",
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
      "value": "sqlservr,cassandra,mysql,postgres,redis-server,redis-sentinel,memcached"
     }
    ]
   }
  },
  {
   "id": "schedule_param",
   "kind": "exists",
   "tier": "core",
   "quote": "a schedule expression cron defaulting to \"rate(30 days)\"",
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
      "value": "rate(30 days)"
     }
    ]
   }
  },
  {
   "id": "document",
   "kind": "exists",
   "tier": "core",
   "quote": "provision an SSM Command document",
   "select": "doc"
  },
  {
   "id": "doc_command_type",
   "kind": "any_of",
   "tier": "core",
   "quote": "an SSM Command document",
   "justify": "Command is the default when DocumentType is omitted",
   "checks": [
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "DocumentType"
      ],
      "op": "eq",
      "value": "Command"
     }
    },
    {
     "kind": "attr",
     "select": "doc",
     "cond": {
      "path": [
       "DocumentType"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "doc_shell_step",
   "kind": "attr",
   "tier": "detail",
   "quote": "shell and PowerShell script execution steps",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)aws:runShellScript"
   }
  },
  {
   "id": "doc_powershell_step",
   "kind": "attr",
   "tier": "detail",
   "quote": "shell and PowerShell script execution steps",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)aws:runPowerShellScript"
   }
  },
  {
   "id": "doc_instance_metadata",
   "kind": "attr",
   "tier": "detail",
   "quote": "query instance metadata for the instance ID",
   "justify": "instance metadata service address or instance-id path",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)(169\\.254\\.169\\.254|instance-id|ec2-metadata)"
   }
  },
  {
   "id": "doc_process_search",
   "kind": "attr",
   "tier": "detail",
   "quote": "search for target running processes",
   "justify": "process listing commands",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)(get-process|\\bps\\b|pgrep|pidof|tasklist)"
   }
  },
  {
   "id": "doc_inventory_file",
   "kind": "attr",
   "tier": "detail",
   "quote": "format results into a custom inventory file",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)(inventory\\W{1,4}custom|Custom:[a-z])"
   },
   "justify": "SSM reads custom inventory from an inventory/custom directory, with a Custom: type name"
  },
  {
   "id": "assoc",
   "kind": "exists",
   "tier": "core",
   "quote": "an SSM association",
   "select": "assoc"
  },
  {
   "id": "assoc_name",
   "kind": "attr",
   "tier": "core",
   "quote": "named \"Custom-Inventory-Processes\"",
   "select": "assoc",
   "cond": {
    "path": [
     "AssociationName"
    ],
    "op": "eq",
    "value": "Custom-Inventory-Processes"
   }
  },
  {
   "id": "assoc_targets_all",
   "kind": "attr",
   "tier": "core",
   "quote": "targeting all instance IDs",
   "select": "assoc",
   "cond": {
    "path": [
     "Targets",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Key"
      ],
      "op": "regex",
      "value": "(?i)^instanceids$"
     },
     {
      "path": [
       "Values",
       "*"
      ],
      "op": "eq",
      "value": "*"
     }
    ]
   }
  },
  {
   "id": "assoc_schedule",
   "kind": "attr",
   "tier": "core",
   "quote": "on the specified schedule",
   "justify": "parameter default resolves to the stated schedule",
   "select": "assoc",
   "cond": {
    "path": [
     "ScheduleExpression"
    ],
    "op": "eq",
    "value": "rate(30 days)"
   }
  },
  {
   "id": "assoc_runs_doc",
   "kind": "any_of",
   "tier": "core",
   "quote": "to execute the custom document",
   "checks": [
    {
     "kind": "ref",
     "from": "assoc",
     "to": "doc"
    },
    {
     "kind": "join",
     "from": "assoc",
     "from_path": [
      "Name"
     ],
     "to": "doc",
     "to_path": [
      "Name"
     ]
    }
   ]
  },
  {
   "id": "assoc_linux_param",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with the defined process keyword parameters",
   "checks": [
    {
     "kind": "attr",
     "select": "assoc",
     "cond": {
      "path": [
       "Parameters",
       "*",
       "*"
      ],
      "op": "eq",
      "value": "CassandraDaemon,dse cassandra,mysql,postgres,redis-server,redis-sentinel,memcached"
     }
    },
    {
     "kind": "attr",
     "select": "assoc",
     "cond": {
      "path": [
       "Parameters",
       "*"
      ],
      "op": "eq",
      "value": "CassandraDaemon,dse cassandra,mysql,postgres,redis-server,redis-sentinel,memcached"
     }
    }
   ]
  },
  {
   "id": "assoc_windows_param",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with the defined process keyword parameters",
   "checks": [
    {
     "kind": "attr",
     "select": "assoc",
     "cond": {
      "path": [
       "Parameters",
       "*",
       "*"
      ],
      "op": "eq",
      "value": "sqlservr,cassandra,mysql,postgres,redis-server,redis-sentinel,memcached"
     }
    },
    {
     "kind": "attr",
     "select": "assoc",
     "cond": {
      "path": [
       "Parameters",
       "*"
      ],
      "op": "eq",
      "value": "sqlservr,cassandra,mysql,postgres,redis-server,redis-sentinel,memcached"
     }
    }
   ]
  },
  {
   "id": "x_schema",
   "kind": "attr",
   "tier": "extra",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)schemaVersion\\W+2\\.2"
   }
  },
  {
   "id": "x_platform_precondition",
   "kind": "attr",
   "tier": "extra",
   "select": "doc",
   "cond": {
    "path": [
     "Content"
    ],
    "op": "regex",
    "value": "(?i)platformType"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
