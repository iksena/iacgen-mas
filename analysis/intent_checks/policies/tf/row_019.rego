package intent.tf.row_019

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "td": {
   "types": [
    "aws_ecs_task_definition"
   ],
   "where": []
  },
  "efs": {
   "types": [
    "aws_efs_file_system"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "efs",
   "kind": "exists",
   "select": "efs",
   "tier": "core",
   "quote": "creates an encrypted Amazon EFS file system"
  },
  {
   "id": "efs_encrypted",
   "kind": "attr",
   "select": "efs",
   "cond": {
    "path": [
     "encrypted"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "encrypted Amazon EFS file system"
  },
  {
   "id": "efs_token",
   "kind": "attr",
   "select": "efs",
   "cond": {
    "path": [
     "creation_token"
    ],
    "op": "eq",
    "value": "cloudrail-test"
   },
   "tier": "core",
   "quote": "creation token of \"cloudrail-test\""
  },
  {
   "id": "task_def",
   "kind": "exists",
   "select": "td",
   "tier": "core",
   "quote": "an ECS task definition"
  },
  {
   "id": "task_family",
   "kind": "attr",
   "select": "td",
   "cond": {
    "path": [
     "family"
    ],
    "op": "eq",
    "value": "cloudrail-test-encryption"
   },
   "tier": "core",
   "quote": "within the family \"cloudrail-test-encryption\""
  },
  {
   "id": "container_first",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "container_definitions"
      ],
      "op": "regex",
      "value": "['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "container_definitions"
      ],
      "op": "regex",
      "value": "['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)"
     }
    }
   ],
   "tier": "core",
   "quote": "the first container named \"first\""
  },
  {
   "id": "container_second",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "container_definitions"
      ],
      "op": "regex",
      "value": "['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "container_definitions"
      ],
      "op": "regex",
      "value": "['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)"
     }
    }
   ],
   "tier": "core",
   "quote": "the second container named \"second\""
  },
  {
   "id": "image_first",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "container_definitions"
      ],
      "op": "regex",
      "value": "\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]first['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?image['\\\"]?\\s*[:=]\\s*['\"]service-first['\"](?:[^A-Za-z0-9_-]|$)|['\\\"]?image['\\\"]?\\s*[:=]\\s*['\"]service-first['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]first['\"](?:[^A-Za-z0-9_-]|$))"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "container_definitions"
      ],
      "op": "regex",
      "value": "\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]first['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?image['\\\"]?\\s*[:=]\\s*['\"]service-first['\"](?:[^A-Za-z0-9_-]|$)|['\\\"]?image['\\\"]?\\s*[:=]\\s*['\"]service-first['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]first['\"](?:[^A-Za-z0-9_-]|$))"
     }
    }
   ],
   "tier": "core",
   "quote": "using image \"service-first\""
  },
  {
   "id": "image_second",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "container_definitions"
      ],
      "op": "regex",
      "value": "\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]second['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?image['\\\"]?\\s*[:=]\\s*['\"]service-second['\"](?:[^A-Za-z0-9_-]|$)|['\\\"]?image['\\\"]?\\s*[:=]\\s*['\"]service-second['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]second['\"](?:[^A-Za-z0-9_-]|$))"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "container_definitions"
      ],
      "op": "regex",
      "value": "\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]second['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?image['\\\"]?\\s*[:=]\\s*['\"]service-second['\"](?:[^A-Za-z0-9_-]|$)|['\\\"]?image['\\\"]?\\s*[:=]\\s*['\"]service-second['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]second['\"](?:[^A-Za-z0-9_-]|$))"
     }
    }
   ],
   "tier": "core",
   "quote": "using image \"service-second\""
  },
  {
   "id": "cpu_both",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "container_definitions"
      ],
      "op": "regex",
      "value": "(?s)\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)).*\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$))|\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)).*\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$))"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "container_definitions"
      ],
      "op": "regex",
      "value": "(?s)\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)).*\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$))|\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)).*\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?cpu['\\\"]?\\s*[:=]\\s*['\\\"]?10['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$))"
     }
    }
   ],
   "tier": "detail",
   "quote": "allocated 10 CPU units",
   "justify": "both containers get 10 CPU units"
  },
  {
   "id": "memory_first",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "container_definitions"
      ],
      "op": "regex",
      "value": "\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]first['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?memory['\\\"]?\\s*[:=]\\s*['\\\"]?512['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?memory['\\\"]?\\s*[:=]\\s*['\\\"]?512['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]first['\"](?:[^A-Za-z0-9_-]|$))"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "container_definitions"
      ],
      "op": "regex",
      "value": "\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]first['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?memory['\\\"]?\\s*[:=]\\s*['\\\"]?512['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?memory['\\\"]?\\s*[:=]\\s*['\\\"]?512['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]first['\"](?:[^A-Za-z0-9_-]|$))"
     }
    }
   ],
   "tier": "detail",
   "quote": "512 MB memory"
  },
  {
   "id": "memory_second",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "container_definitions"
      ],
      "op": "regex",
      "value": "\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]second['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?memory['\\\"]?\\s*[:=]\\s*['\\\"]?256['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?memory['\\\"]?\\s*[:=]\\s*['\\\"]?256['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]second['\"](?:[^A-Za-z0-9_-]|$))"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "container_definitions"
      ],
      "op": "regex",
      "value": "\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]second['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?memory['\\\"]?\\s*[:=]\\s*['\\\"]?256['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?memory['\\\"]?\\s*[:=]\\s*['\\\"]?256['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]second['\"](?:[^A-Za-z0-9_-]|$))"
     }
    }
   ],
   "tier": "detail",
   "quote": "256 MB memory"
  },
  {
   "id": "essential_both",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "container_definitions"
      ],
      "op": "regex",
      "value": "(?s)\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)).*\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$))|\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)).*\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$))"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "container_definitions"
      ],
      "op": "regex",
      "value": "(?s)\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)).*\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$))|\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]second['\\\"](?:[^A-Za-z0-9_-]|$)).*\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)|['\\\"]?essential['\\\"]?\\s*[:=]\\s*['\\\"]?[Tt]rue['\\\"]?(?:[^A-Za-z0-9_.-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\\\"]first['\\\"](?:[^A-Za-z0-9_-]|$))"
     }
    }
   ],
   "tier": "detail",
   "quote": "two essential containers"
  },
  {
   "id": "port_80",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "container_definitions"
      ],
      "op": "regex",
      "value": "\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]first['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?portMappings['\\\"]?\\s*[:=]\\s*\\[[^\\]]*['\\\"]?containerPort['\\\"]?\\s*[:=]\\s*['\\\"]?80['\\\"]?(?:[^0-9]|$)|['\\\"]?portMappings['\\\"]?\\s*[:=]\\s*\\[[^\\]]*['\\\"]?containerPort['\\\"]?\\s*[:=]\\s*['\\\"]?80['\\\"]?(?:[^0-9]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]first['\"](?:[^A-Za-z0-9_-]|$))"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "container_definitions"
      ],
      "op": "regex",
      "value": "\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]first['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?portMappings['\\\"]?\\s*[:=]\\s*\\[[^\\]]*['\\\"]?containerPort['\\\"]?\\s*[:=]\\s*['\\\"]?80['\\\"]?(?:[^0-9]|$)|['\\\"]?portMappings['\\\"]?\\s*[:=]\\s*\\[[^\\]]*['\\\"]?containerPort['\\\"]?\\s*[:=]\\s*['\\\"]?80['\\\"]?(?:[^0-9]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]first['\"](?:[^A-Za-z0-9_-]|$))"
     }
    }
   ],
   "tier": "detail",
   "quote": "the first container named \"first\" using image \"service-first\" allocated 10 CPU units and 512 MB memory mapping host and container port 80"
  },
  {
   "id": "port_443",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "container_definitions"
      ],
      "op": "regex",
      "value": "\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]second['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?portMappings['\\\"]?\\s*[:=]\\s*\\[[^\\]]*['\\\"]?containerPort['\\\"]?\\s*[:=]\\s*['\\\"]?443['\\\"]?(?:[^0-9]|$)|['\\\"]?portMappings['\\\"]?\\s*[:=]\\s*\\[[^\\]]*['\\\"]?containerPort['\\\"]?\\s*[:=]\\s*['\\\"]?443['\\\"]?(?:[^0-9]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]second['\"](?:[^A-Za-z0-9_-]|$))"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "container_definitions"
      ],
      "op": "regex",
      "value": "\\{(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*(?:['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]second['\"](?:[^A-Za-z0-9_-]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?portMappings['\\\"]?\\s*[:=]\\s*\\[[^\\]]*['\\\"]?containerPort['\\\"]?\\s*[:=]\\s*['\\\"]?443['\\\"]?(?:[^0-9]|$)|['\\\"]?portMappings['\\\"]?\\s*[:=]\\s*\\[[^\\]]*['\\\"]?containerPort['\\\"]?\\s*[:=]\\s*['\\\"]?443['\\\"]?(?:[^0-9]|$)(?:[^{}]|\\{(?:[^{}]|\\{[^{}]*\\})*\\})*['\\\"]?name['\\\"]?\\s*[:=]\\s*['\"]second['\"](?:[^A-Za-z0-9_-]|$))"
     }
    }
   ],
   "tier": "detail",
   "quote": "the second container named \"second\" using image \"service-second\" allocated 10 CPU units and 256 MB memory mapping host and container port 443"
  },
  {
   "id": "volume_name",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "volume",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "service-storage"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "volume",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "service-storage"
     }
    }
   ],
   "tier": "core",
   "quote": "an EFS volume named \"service-storage\""
  },
  {
   "id": "volume_root",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "volume",
       "*",
       "efs_volume_configuration",
       "*",
       "root_directory"
      ],
      "op": "eq",
      "value": "/opt/data"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "volume",
       "*",
       "efs_volume_configuration",
       "*",
       "root_directory"
      ],
      "op": "eq",
      "value": "/opt/data"
     }
    }
   ],
   "tier": "core",
   "quote": "root directory configured to \"/opt/data\""
  },
  {
   "id": "volume_transit",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "volume",
       "*",
       "efs_volume_configuration",
       "*",
       "transit_encryption"
      ],
      "op": "eq",
      "value": "ENABLED"
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "volume",
       "*",
       "efs_volume_configuration",
       "*",
       "transit_encryption"
      ],
      "op": "eq",
      "value": "ENABLED"
     }
    }
   ],
   "tier": "core",
   "quote": "in-transit encryption enabled"
  },
  {
   "id": "volume_port",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "volume",
       "*",
       "efs_volume_configuration",
       "*",
       "transit_encryption_port"
      ],
      "op": "eq",
      "value": 2999
     }
    },
    {
     "kind": "attr",
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
        "value": "aws_ecs_task_definition"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "volume",
       "*",
       "efs_volume_configuration",
       "*",
       "transit_encryption_port"
      ],
      "op": "eq",
      "value": 2999
     }
    }
   ],
   "tier": "core",
   "quote": "in-transit encryption enabled on port 2999"
  },
  {
   "id": "volume_links_efs",
   "kind": "ref",
   "from": "td",
   "to": "efs",
   "tier": "core",
   "quote": "linked to the created EFS file system"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
