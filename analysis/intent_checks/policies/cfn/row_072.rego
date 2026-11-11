package intent.cfn.row_072

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "proj": {
   "types": [
    "AWS::CodeBuild::Project"
   ],
   "where": []
  },
  "rules": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": []
  },
  "cb_role": {
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
     "value": "codebuild.amazonaws.com"
    }
   ]
  },
  "ev_role": {
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
     "value": "events.amazonaws.com"
    }
   ]
  },
  "cc_rules": {
   "types": [
    "AWS::Events::Rule"
   ],
   "where": [
    {
     "path": [
      "EventPattern"
     ],
     "op": "contains",
     "value": "aws.codecommit"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "project",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a CodeBuild project to mirror three existing CodeCommit repositories",
   "select": "proj"
  },
  {
   "id": "linux_standard_image",
   "kind": "attr",
   "tier": "core",
   "quote": "utilizing a standard CodeBuild Linux container image",
   "justify": "standard image is aws/codebuild/standard:*",
   "select": "proj",
   "cond": {
    "path": [
     "Environment",
     "Image"
    ],
    "op": "regex",
    "value": "(?i)aws/codebuild/.*standard"
   }
  },
  {
   "id": "linux_container",
   "kind": "attr",
   "tier": "detail",
   "quote": "standard CodeBuild Linux container image",
   "select": "proj",
   "cond": {
    "path": [
     "Environment",
     "Type"
    ],
    "op": "regex",
    "value": "(?i)^LINUX"
   }
  },
  {
   "id": "git_remote_codecommit",
   "kind": "all_of",
   "tier": "core",
   "quote": "uses 'git-remote-codecommit' to clone and push the repositories",
   "checks": [
    {
     "kind": "attr",
     "select": "proj",
     "cond": {
      "path": [
       "Source",
       "BuildSpec"
      ],
      "op": "contains",
      "value": "git-remote-codecommit"
     }
    },
    {
     "kind": "attr",
     "select": "proj",
     "cond": {
      "path": [
       "Source",
       "BuildSpec"
      ],
      "op": "regex",
      "value": "(?i)git\\s+clone"
     }
    },
    {
     "kind": "attr",
     "select": "proj",
     "cond": {
      "path": [
       "Source",
       "BuildSpec"
      ],
      "op": "regex",
      "value": "(?i)git\\s+push"
     }
    }
   ]
  },
  {
   "id": "buildspec_repos",
   "kind": "all_of",
   "tier": "core",
   "quote": "('card-service', 'rule-service', and 'ecs-pipeline')",
   "checks": [
    {
     "kind": "attr",
     "select": "proj",
     "cond": {
      "path": [],
      "op": "contains",
      "value": "card-service"
     }
    },
    {
     "kind": "attr",
     "select": "proj",
     "cond": {
      "path": [],
      "op": "contains",
      "value": "rule-service"
     }
    },
    {
     "kind": "attr",
     "select": "proj",
     "cond": {
      "path": [],
      "op": "contains",
      "value": "ecs-pipeline"
     }
    }
   ]
  },
  {
   "id": "rules_exist",
   "kind": "exists",
   "tier": "core",
   "quote": "provision EventBridge rules that automatically trigger the build",
   "select": "rules"
  },
  {
   "id": "rules_target_project",
   "kind": "ref",
   "tier": "core",
   "quote": "trigger the build",
   "from": "rules",
   "to": "proj"
  },
  {
   "id": "rules_codecommit_source",
   "kind": "attr",
   "tier": "core",
   "quote": "whenever a commit is pushed",
   "select": "rules",
   "cond": {
    "path": [
     "EventPattern"
    ],
    "op": "contains",
    "value": "aws.codecommit"
   }
  },
  {
   "id": "rules_mainline",
   "kind": "attr",
   "tier": "core",
   "quote": "the 'mainline' branch",
   "select": "cc_rules",
   "quantifier": "all",
   "cond": {
    "path": [
     "EventPattern",
     "detail"
    ],
    "op": "regex",
    "value": "(?i)mainline"
   }
  },
  {
   "id": "rules_cover_repos",
   "kind": "all_of",
   "tier": "core",
   "quote": "whenever a commit is pushed to the 'mainline' branch in any of the source repositories",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Events::Rule"
      ],
      "where": [
       {
        "path": [
         "EventPattern"
        ],
        "op": "contains",
        "value": "aws.codecommit"
       },
       {
        "path": [
         "EventPattern",
         "detail"
        ],
        "op": "regex",
        "value": "(?i)mainline"
       },
       {
        "path": [
         "EventPattern"
        ],
        "op": "contains",
        "value": "card-service"
       }
      ]
     },
     "to": "proj"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Events::Rule"
      ],
      "where": [
       {
        "path": [
         "EventPattern"
        ],
        "op": "contains",
        "value": "aws.codecommit"
       },
       {
        "path": [
         "EventPattern",
         "detail"
        ],
        "op": "regex",
        "value": "(?i)mainline"
       },
       {
        "path": [
         "EventPattern"
        ],
        "op": "contains",
        "value": "rule-service"
       }
      ]
     },
     "to": "proj"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Events::Rule"
      ],
      "where": [
       {
        "path": [
         "EventPattern"
        ],
        "op": "contains",
        "value": "aws.codecommit"
       },
       {
        "path": [
         "EventPattern",
         "detail"
        ],
        "op": "regex",
        "value": "(?i)mainline"
       },
       {
        "path": [
         "EventPattern"
        ],
        "op": "contains",
        "value": "ecs-pipeline"
       }
      ]
     },
     "to": "proj"
    }
   ]
  },
  {
   "id": "codebuild_role",
   "kind": "exists",
   "tier": "core",
   "quote": "IAM roles and policies for CodeBuild",
   "select": "cb_role"
  },
  {
   "id": "proj_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "IAM roles and policies for CodeBuild",
   "from": "proj",
   "to": "cb_role"
  },
  {
   "id": "events_role",
   "kind": "exists",
   "tier": "core",
   "quote": "IAM roles and policies for CodeBuild and EventBridge",
   "select": "ev_role"
  },
  {
   "id": "events_startbuild",
   "kind": "any_of",
   "tier": "detail",
   "quote": "IAM roles and policies for CodeBuild and EventBridge",
   "justify": "EventBridge triggering a build needs codebuild:StartBuild",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "ev_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "codebuild:StartBuild"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "ev_role",
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
      "value": "codebuild:StartBuild"
     }
    }
   ]
  },
  {
   "id": "rules_use_events_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "IAM roles and policies for CodeBuild and EventBridge",
   "from": "rules",
   "to": "ev_role"
  },
  {
   "id": "replica_region_push",
   "kind": "attr",
   "tier": "detail",
   "quote": "to a target replica region",
   "select": "proj",
   "justify": "reaching a second region with git-remote-codecommit needs a second codecommit:: URL",
   "cond": {
    "path": [
     "Source",
     "BuildSpec"
    ],
    "op": "regex",
    "value": "(?s)codecommit::.*codecommit::"
   }
  },
  {
   "id": "repos_not_created",
   "kind": "attr",
   "tier": "detail",
   "quote": "Assume the repositories already exist and do not need to be provisioned by this template",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": []
   },
   "quantifier": "all",
   "cond": {
    "path": [
     "type"
    ],
    "op": "none_eq",
    "value": "AWS::CodeCommit::Repository"
   }
  },
  {
   "id": "x_artifacts",
   "kind": "attr",
   "tier": "extra",
   "select": "proj",
   "cond": {
    "path": [
     "Artifacts",
     "Type"
    ],
    "op": "eq",
    "value": "NO_ARTIFACTS"
   }
  },
  {
   "id": "x_events",
   "kind": "attr",
   "tier": "extra",
   "select": "rules",
   "quantifier": "all",
   "cond": {
    "path": [
     "EventPattern",
     "detail",
     "event",
     "*"
    ],
    "op": "eq",
    "value": "referenceUpdated"
   }
  },
  {
   "id": "x_codecommit_perm",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "ref",
     "bidirectional": true,
     "to": "cb_role",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy",
       "AWS::IAM::RolePolicy"
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
        "value": "codecommit:GitPull"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "cb_role",
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
      "value": "codecommit:GitPull"
     }
    },
    {
     "kind": "attr",
     "select": "cb_role",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "CodeCommit"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
