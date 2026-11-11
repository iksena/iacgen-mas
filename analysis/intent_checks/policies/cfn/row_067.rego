package intent.cfn.row_067

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "role_task": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "RoleName"
     ],
     "op": "regex",
     "value": "(?i)-TaskRole$"
    }
   ]
  },
  "role_exec": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "RoleName"
     ],
     "op": "regex",
     "value": "(?i)-TaskExecutionRole$"
    }
   ]
  },
  "td": {
   "types": [
    "AWS::ECS::TaskDefinition"
   ],
   "where": []
  },
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "param_repo",
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
      "value": "book-app"
     }
    ]
   },
   "tier": "core",
   "quote": "accept a parameter for the ECR repository name defaulting to \"book-app\""
  },
  {
   "id": "log_group",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Logs::LogGroup"
    ],
    "where": [
     {
      "path": [
       "LogGroupName"
      ],
      "op": "eq",
      "value": "/ecs/book-app"
     }
    ]
   },
   "tier": "core",
   "quote": "a CloudWatch log group named \"/ecs/{EcrRepoName}\"",
   "justify": "/ecs/{EcrRepoName} resolves to /ecs/book-app with the default"
  },
  {
   "id": "log_retention",
   "kind": "attr",
   "select": "lg",
   "cond": {
    "path": [
     "RetentionInDays"
    ],
    "op": "eq",
    "value": 7
   },
   "tier": "core",
   "quote": "7-day log retention period",
   "justify": "7-day"
  },
  {
   "id": "log_deletion_policy",
   "kind": "attr",
   "select": "lg",
   "cond": {
    "path": [
     "__resource__",
     "DeletionPolicy"
    ],
    "op": "eq",
    "value": "Delete"
   },
   "tier": "detail",
   "quote": "deletion policies set to delete the log group upon stack deletion or update replacement"
  },
  {
   "id": "log_update_replace_policy",
   "kind": "attr",
   "select": "lg",
   "cond": {
    "path": [
     "__resource__",
     "UpdateReplacePolicy"
    ],
    "op": "eq",
    "value": "Delete"
   },
   "tier": "detail",
   "quote": "deletion policies set to delete the log group upon stack deletion or update replacement"
  },
  {
   "id": "task_role",
   "kind": "exists",
   "select": "role_task",
   "tier": "core",
   "quote": "an ECS task role named \"{StackName}-TaskRole\"",
   "justify": "{StackName}-TaskRole matched by suffix since the stack name varies"
  },
  {
   "id": "task_role_trust",
   "kind": "attr",
   "select": "role_task",
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
   "tier": "core",
   "quote": "trusting \"ecs-tasks.amazonaws.com\""
  },
  {
   "id": "task_role_root_policy",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "role_task",
     "cond": {
      "path": [
       "Policies",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "PolicyName"
        ],
        "op": "eq",
        "value": "root"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ssmmessages:CreateDataChannel"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::RolePolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyName"
        ],
        "op": "eq",
        "value": "root"
       },
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ssmmessages:CreateDataChannel"
       }
      ]
     },
     "to": "role_task"
    }
   ],
   "tier": "core",
   "quote": "an inline policy named \"root\" granting permissions for SSM messages actions to enable ECS Exec",
   "justify": "ECS Exec needs the ssmmessages data channel action"
  },
  {
   "id": "exec_role",
   "kind": "exists",
   "select": "role_exec",
   "tier": "core",
   "quote": "an ECS task execution role named \"{StackName}-TaskExecutionRole\"",
   "justify": "{StackName}-TaskExecutionRole matched by suffix since the stack name varies"
  },
  {
   "id": "exec_role_trust",
   "kind": "attr",
   "select": "role_exec",
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
   "tier": "core",
   "quote": "trusting \"ecs-tasks.amazonaws.com\""
  },
  {
   "id": "exec_role_managed",
   "kind": "attr",
   "select": "role_exec",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "contains",
    "value": "AmazonECSTaskExecutionRolePolicy"
   },
   "tier": "core",
   "quote": "with the \"AmazonECSTaskExecutionRolePolicy\" managed policy attached"
  },
  {
   "id": "td_family",
   "kind": "attr",
   "select": "td",
   "cond": {
    "path": [
     "Family"
    ],
    "op": "eq",
    "value": "book-app"
   },
   "tier": "core",
   "quote": "with family set to the ECR repository name parameter",
   "justify": "default of the ECR repo name parameter"
  },
  {
   "id": "td_fargate",
   "kind": "attr",
   "select": "td",
   "cond": {
    "path": [
     "RequiresCompatibilities",
     "*"
    ],
    "op": "eq",
    "value": "FARGATE"
   },
   "tier": "core",
   "quote": "AWS Fargate task definition"
  },
  {
   "id": "td_network",
   "kind": "attr",
   "select": "td",
   "cond": {
    "path": [
     "NetworkMode"
    ],
    "op": "eq",
    "value": "awsvpc"
   },
   "tier": "core",
   "quote": "using awsvpc network mode"
  },
  {
   "id": "td_cpu",
   "kind": "attr",
   "select": "td",
   "cond": {
    "path": [
     "Cpu"
    ],
    "op": "eq",
    "value": 256
   },
   "tier": "core",
   "quote": "256 CPU units"
  },
  {
   "id": "td_memory",
   "kind": "attr",
   "select": "td",
   "cond": {
    "path": [
     "Memory"
    ],
    "op": "eq",
    "value": 512
   },
   "tier": "core",
   "quote": "512 MiB memory"
  },
  {
   "id": "td_task_role",
   "kind": "ref",
   "from": "td",
   "to": "role_task",
   "tier": "core",
   "quote": "the specified task and execution roles"
  },
  {
   "id": "td_exec_role",
   "kind": "ref",
   "from": "td",
   "to": "role_exec",
   "tier": "core",
   "quote": "the specified task and execution roles"
  },
  {
   "id": "ctr_name",
   "kind": "attr",
   "select": "td",
   "cond": {
    "path": [
     "ContainerDefinitions",
     "*",
     "Name"
    ],
    "op": "eq",
    "value": "book-app"
   },
   "tier": "detail",
   "quote": "a container definition named after the ECR repository",
   "justify": "default of the ECR repo name parameter"
  },
  {
   "id": "ctr_image",
   "kind": "attr",
   "select": "td",
   "cond": {
    "path": [
     "ContainerDefinitions",
     "*",
     "Image"
    ],
    "op": "regex",
    "value": "^public\\.ecr\\.aws/nginx/nginx(:.*)?$"
   },
   "tier": "detail",
   "quote": "using image \"public.ecr.aws/nginx/nginx\""
  },
  {
   "id": "ctr_port",
   "kind": "attr",
   "select": "td",
   "cond": {
    "path": [
     "ContainerDefinitions",
     "*",
     "PortMappings",
     "*",
     "ContainerPort"
    ],
    "op": "eq",
    "value": 80
   },
   "tier": "detail",
   "quote": "container port 80 mapping"
  },
  {
   "id": "ctr_not_privileged",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "ContainerDefinitions",
       "*",
       "Privileged"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
     "select": "td",
     "cond": {
      "path": [
       "ContainerDefinitions",
       "*",
       "Privileged"
      ],
      "op": "absent"
     }
    }
   ],
   "tier": "detail",
   "quote": "privileged set to false"
  },
  {
   "id": "ctr_awslogs",
   "kind": "attr",
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
   "tier": "detail",
   "quote": "awslogs log configuration"
  },
  {
   "id": "ctr_log_group",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "td",
     "to": "lg"
    },
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
      "value": "/ecs/book-app"
     }
    }
   ],
   "tier": "detail",
   "quote": "streaming to the created log group"
  },
  {
   "id": "ctr_stream_prefix",
   "kind": "attr",
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
    "value": "book-app"
   },
   "tier": "detail",
   "quote": "under a log stream prefix equal to the ECR repository name",
   "justify": "default of the ECR repo name parameter"
  },
  {
   "id": "x_awslogs_region",
   "kind": "attr",
   "tier": "extra",
   "select": "td",
   "cond": {
    "path": [
     "ContainerDefinitions",
     "*",
     "LogConfiguration",
     "Options",
     "awslogs-region"
    ],
    "op": "present"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
