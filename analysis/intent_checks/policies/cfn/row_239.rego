package intent.cfn.row_239

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "exec": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "ManagedPolicyArns",
      "*"
     ],
     "op": "regex",
     "value": "AmazonECSTaskExecutionRolePolicy$"
    }
   ]
  },
  "td": {
   "types": [
    "AWS::ECS::TaskDefinition"
   ],
   "where": []
  },
  "ecs_roles": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "eq",
     "value": "ecs-tasks.amazonaws.com"
    }
   ]
  },
  "ecs_roles_path": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "eq",
     "value": "ecs-tasks.amazonaws.com"
    },
    {
     "path": [
      "Path"
     ],
     "op": "present"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "exec_role",
   "kind": "exists",
   "tier": "core",
   "select": "exec",
   "quote": "attached to managed policies \"AmazonECSTaskExecutionRolePolicy\""
  },
  {
   "id": "exec_ssm",
   "kind": "attr",
   "tier": "core",
   "select": "exec",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "regex",
    "value": "AmazonSSMReadOnlyAccess$"
   },
   "quote": "\"AmazonSSMReadOnlyAccess\", and \"SecretsManagerReadWrite\""
  },
  {
   "id": "exec_sm",
   "kind": "attr",
   "tier": "core",
   "select": "exec",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "regex",
    "value": "SecretsManagerReadWrite$"
   },
   "quote": "\"AmazonSSMReadOnlyAccess\", and \"SecretsManagerReadWrite\""
  },
  {
   "id": "exec_trust",
   "kind": "attr",
   "tier": "core",
   "select": "exec",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Principal",
     "Service",
     "*"
    ],
    "op": "eq",
    "value": "ecs-tasks.amazonaws.com"
   },
   "quote": "trusting \"ecs-tasks.amazonaws.com\""
  },
  {
   "id": "two_roles",
   "kind": "exists",
   "tier": "core",
   "select": "role",
   "min": 2,
   "quote": "alongside a standard application task role",
   "justify": "an execution role plus a separate task role are two roles"
  },
  {
   "id": "roles_trust",
   "tier": "core",
   "quote": "a standard application task role at path \"/\" also trusting \"ecs-tasks.amazonaws.com\"",
   "kind": "exists",
   "select": "ecs_roles",
   "min": 2,
   "justify": "the execution role and the task role both trust ecs-tasks"
  },
  {
   "id": "roles_path",
   "tier": "detail",
   "quote": "at path \"/\"",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "ecs_roles_path",
     "quantifier": "all",
     "cond": {
      "path": [
       "Path"
      ],
      "op": "eq",
      "value": "/"
     }
    },
    {
     "kind": "attr",
     "select": "ecs_roles",
     "quantifier": "all",
     "cond": {
      "path": [
       "Path"
      ],
      "op": "absent"
     }
    }
   ],
   "justify": "an omitted Path is the default path /"
  },
  {
   "id": "td",
   "kind": "exists",
   "tier": "core",
   "select": "td",
   "quote": "a Fargate-compatible ECS task definition"
  },
  {
   "id": "td_fargate",
   "kind": "attr",
   "tier": "core",
   "select": "td",
   "cond": {
    "path": [
     "RequiresCompatibilities",
     "*"
    ],
    "op": "eq",
    "value": "FARGATE"
   },
   "quote": "Fargate-compatible ECS task definition"
  },
  {
   "id": "td_family",
   "kind": "attr",
   "tier": "core",
   "select": "td",
   "cond": {
    "path": [
     "Family"
    ],
    "op": "eq",
    "value": "test"
   },
   "quote": "family name \"test\""
  },
  {
   "id": "td_net",
   "kind": "attr",
   "tier": "core",
   "select": "td",
   "cond": {
    "path": [
     "NetworkMode"
    ],
    "op": "eq",
    "value": "awsvpc"
   },
   "quote": "using \"awsvpc\" network mode"
  },
  {
   "id": "td_cpu",
   "tier": "core",
   "quote": "256 CPU units",
   "kind": "attr",
   "select": "td",
   "cond": {
    "path": [
     "Cpu"
    ],
    "op": "in",
    "value": [
     "256",
     "0.25 vCPU"
    ]
   },
   "justify": "0.25 vCPU is the API's equivalent of 256 units"
  },
  {
   "id": "td_mem",
   "tier": "core",
   "quote": "1024 MB memory",
   "kind": "attr",
   "select": "td",
   "cond": {
    "path": [
     "Memory"
    ],
    "op": "in",
    "value": [
     "1024",
     "1GB",
     "1 GB"
    ]
   },
   "justify": "1 GB is the API's equivalent of 1024 MB"
  },
  {
   "id": "c_name",
   "kind": "attr",
   "tier": "core",
   "select": "td",
   "cond": {
    "path": [
     "ContainerDefinitions",
     "*",
     "Name"
    ],
    "op": "eq",
    "value": "main"
   },
   "quote": "a single container named \"main\""
  },
  {
   "id": "c_single",
   "kind": "attr",
   "tier": "core",
   "select": "td",
   "cond": {
    "path": [
     "ContainerDefinitions"
    ],
    "op": "len_eq",
    "value": 1
   },
   "quote": "a single container",
   "justify": "single means one container definition"
  },
  {
   "id": "c_image",
   "kind": "attr",
   "tier": "core",
   "select": "td",
   "cond": {
    "path": [
     "ContainerDefinitions",
     "*",
     "Image"
    ],
    "op": "regex",
    "value": "(?i)(^|/)nginx(:|@|$)"
   },
   "quote": "running the \"nginx\" image"
  },
  {
   "id": "c_driver",
   "kind": "attr",
   "tier": "core",
   "select": "td",
   "cond": {
    "path": [
     "ContainerDefinitions",
     "*",
     "LogConfiguration",
     "LogDriver"
    ],
    "op": "eq",
    "value": "awslogs"
   },
   "quote": "configured with the \"awslogs\" log driver"
  },
  {
   "id": "c_group",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "ContainerDefinitions",
       "*",
       "LogConfiguration",
       "Options",
       "awslogs-group"
      ],
      "op": "eq",
      "value": "/aws/ecs/test/main"
     }
    },
    {
     "kind": "ref",
     "from": "td",
     "to": {
      "types": [
       "AWS::Logs::LogGroup"
      ],
      "where": [
       {
        "path": [
         "LogGroupName"
        ],
        "op": "eq",
        "value": "/aws/ecs/test/main"
       }
      ]
     }
    }
   ],
   "quote": "outputting to log group \"/aws/ecs/test/main\""
  },
  {
   "id": "c_prefix",
   "kind": "attr",
   "tier": "detail",
   "select": "td",
   "cond": {
    "path": [
     "ContainerDefinitions",
     "*",
     "LogConfiguration",
     "Options",
     "awslogs-stream-prefix"
    ],
    "op": "eq",
    "value": "ecs"
   },
   "quote": "with stream prefix \"ecs\""
  },
  {
   "id": "td_exec",
   "tier": "detail",
   "quote": "IAM execution and task roles",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::ECS::TaskDefinition"
    ],
    "where": [
     {
      "path": [
       "ExecutionRoleArn"
      ],
      "op": "present"
     }
    ]
   },
   "to": "exec"
  },
  {
   "id": "td_task_role",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "AWS::ECS::TaskDefinition"
    ],
    "where": [
     {
      "path": [
       "TaskRoleArn"
      ],
      "op": "present"
     }
    ]
   },
   "to": "ecs_roles",
   "quote": "IAM execution and task roles"
  },
  {
   "id": "x_assume",
   "kind": "attr",
   "tier": "extra",
   "select": "ecs_roles",
   "quantifier": "all",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Action",
     "*"
    ],
    "op": "glob_covers",
    "value": "sts:AssumeRole"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
