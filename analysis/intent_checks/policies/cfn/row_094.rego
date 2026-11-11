package intent.cfn.row_094

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "td": {
   "types": [
    "AWS::ECS::TaskDefinition"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "ecs_role": {
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
  }
 },
 "checks": [
  {
   "id": "task_definition",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a Fargate ECS task definition",
   "select": "td"
  },
  {
   "id": "fargate",
   "kind": "attr",
   "tier": "core",
   "quote": "a Fargate ECS task definition",
   "select": "td",
   "cond": {
    "path": [
     "RequiresCompatibilities",
     "*"
    ],
    "op": "eq",
    "value": "FARGATE"
   }
  },
  {
   "id": "cpu_256",
   "kind": "attr",
   "tier": "core",
   "quote": "allocate 256 CPU units",
   "select": "td",
   "cond": {
    "path": [
     "Cpu"
    ],
    "op": "eq",
    "value": 256
   }
  },
  {
   "id": "memory_512",
   "kind": "attr",
   "tier": "core",
   "quote": "512 MB of memory",
   "select": "td",
   "cond": {
    "path": [
     "Memory"
    ],
    "op": "eq",
    "value": 512
   }
  },
  {
   "id": "awsvpc",
   "kind": "attr",
   "tier": "core",
   "quote": "use the awsvpc network mode",
   "select": "td",
   "cond": {
    "path": [
     "NetworkMode"
    ],
    "op": "eq",
    "value": "awsvpc"
   }
  },
  {
   "id": "image_from_ecr",
   "kind": "attr",
   "tier": "core",
   "quote": "referencing a container image located in an ECR repository",
   "select": "td",
   "cond": {
    "path": [
     "ContainerDefinitions",
     "*",
     "Image"
    ],
    "op": "regex",
    "value": "(\\.dkr\\.ecr\\.[^/]+\\.amazonaws\\.com/|\\.RepositoryUri\\})"
   },
   "justify": "ECR image URIs have the form <account>.dkr.ecr.<region>.amazonaws.com/<repo>, or come from a repository's RepositoryUri"
  },
  {
   "id": "image_has_tag",
   "kind": "attr",
   "tier": "detail",
   "quote": "with a specific but immutable tag",
   "select": "td",
   "cond": {
    "path": [
     "ContainerDefinitions",
     "*",
     "Image"
    ],
    "op": "regex",
    "value": ":(([^l:/][^:/]*)|l|la|lat|late|lates|l[^a:/][^:/]*|la[^t:/][^:/]*|lat[^e:/][^:/]*|late[^s:/][^:/]*|lates[^t:/][^:/]*|latest[^:/]+)$|@sha256:[0-9a-f]+$"
   },
   "justify": "a specific, immutable tag is a pinned tag or digest, not the moving tag latest"
  },
  {
   "id": "output_image_uri",
   "kind": "attr",
   "tier": "detail",
   "quote": "while also outputting the full image URI",
   "select": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "value"
    ],
    "op": "regex",
    "value": "(\\.dkr\\.ecr\\.[^/]+\\.amazonaws\\.com/|\\.RepositoryUri\\}).*[:@]"
   },
   "justify": "the full image URI includes the tag"
  },
  {
   "id": "two_roles",
   "kind": "exists",
   "tier": "core",
   "quote": "provision both a task role and a separate execution role",
   "select": "role",
   "min": 2,
   "justify": "a task role and a separate execution role are two roles"
  },
  {
   "id": "task_role_attr",
   "kind": "attr",
   "tier": "core",
   "quote": "a task role",
   "select": "td",
   "cond": {
    "path": [
     "TaskRoleArn"
    ],
    "op": "regex",
    "value": "(ref|\\$\\{)"
   },
   "justify": "the task definition uses a role the template provisions, not a literal ARN"
  },
  {
   "id": "execution_role_attr",
   "kind": "attr",
   "tier": "core",
   "quote": "a separate execution role",
   "select": "td",
   "cond": {
    "path": [
     "ExecutionRoleArn"
    ],
    "op": "regex",
    "value": "(ref|\\$\\{)"
   },
   "justify": "the task definition uses a role the template provisions, not a literal ARN"
  },
  {
   "id": "roles_trust_ecs_tasks",
   "kind": "exists",
   "tier": "detail",
   "quote": "provision both a task role and a separate execution role",
   "select": "ecs_role",
   "min": 2,
   "justify": "ECS task and execution roles are both assumed by the ecs-tasks service"
  },
  {
   "id": "execution_role_ecr_pull",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the necessary permissions to pull the image from ECR",
   "checks": [
    {
     "kind": "attr",
     "select": "ecs_role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ecr:BatchGetImage"
     }
    },
    {
     "kind": "ref",
     "bidirectional": true,
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "ecr:BatchGetImage"
       }
      ]
     },
     "to": "ecs_role"
    },
    {
     "kind": "attr",
     "select": "ecs_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)(AmazonECSTaskExecutionRolePolicy|ContainerRegistry)"
     }
    }
   ]
  },
  {
   "id": "x_container_memory",
   "kind": "attr",
   "tier": "extra",
   "select": "td",
   "cond": {
    "path": [
     "ContainerDefinitions",
     "*",
     "Memory"
    ],
    "op": "eq",
    "value": 512
   }
  },
  {
   "id": "x_container_essential",
   "kind": "attr",
   "tier": "extra",
   "select": "td",
   "cond": {
    "path": [
     "ContainerDefinitions",
     "*",
     "Essential"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_ecr_auth_token",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ecr:GetAuthorizationToken"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ecr:GetAuthorizationToken"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::IAM::ManagedPolicy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "ecr:GetAuthorizationToken"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)(AmazonECSTaskExecutionRolePolicy|ContainerRegistry)"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
