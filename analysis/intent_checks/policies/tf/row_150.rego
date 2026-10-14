# GENERATED from specs/tf/row_150.json by intent_checks/build.py -- do not edit.
package intent.tf.row_150

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "agent_role",
   "kind": "exists",
   "tier": "core",
   "quote": "AWSElasticDisasterRecoveryAgentRole and AWSElasticDisasterRecoveryFailbackRole (both allowing drs.amazonaws.com to assume the role and set source identity, conditioned on the calling account ID and source identity prefixes \"s-\" and \"i-\", respectively)",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "AWSElasticDisasterRecoveryAgentRole"
     },
     {
      "path": [
       "path"
      ],
      "op": "eq",
      "value": "/service-role/"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "drs.amazonaws.com"
     }
    ]
   }
  },
  {
   "id": "agent_role_trust_conditions",
   "kind": "exists",
   "tier": "detail",
   "quote": "AWSElasticDisasterRecoveryAgentRole and AWSElasticDisasterRecoveryFailbackRole (both allowing drs.amazonaws.com to assume the role and set source identity, conditioned on the calling account ID and source identity prefixes \"s-\" and \"i-\", respectively)",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "AWSElasticDisasterRecoveryAgentRole"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "sts:SetSourceIdentity"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)\"aws:[A-Za-z]*Account\""
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "\"s-"
     }
    ]
   },
   "justify": "'set source identity' -> sts:SetSourceIdentity"
  },
  {
   "id": "failback_role",
   "kind": "exists",
   "tier": "core",
   "quote": "AWSElasticDisasterRecoveryAgentRole and AWSElasticDisasterRecoveryFailbackRole (both allowing drs.amazonaws.com to assume the role and set source identity, conditioned on the calling account ID and source identity prefixes \"s-\" and \"i-\", respectively)",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "AWSElasticDisasterRecoveryFailbackRole"
     },
     {
      "path": [
       "path"
      ],
      "op": "eq",
      "value": "/service-role/"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "drs.amazonaws.com"
     }
    ]
   }
  },
  {
   "id": "failback_role_trust_conditions",
   "kind": "exists",
   "tier": "detail",
   "quote": "AWSElasticDisasterRecoveryAgentRole and AWSElasticDisasterRecoveryFailbackRole (both allowing drs.amazonaws.com to assume the role and set source identity, conditioned on the calling account ID and source identity prefixes \"s-\" and \"i-\", respectively)",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "AWSElasticDisasterRecoveryFailbackRole"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "sts:SetSourceIdentity"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "(?i)\"aws:[A-Za-z]*Account\""
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "\"i-"
     }
    ]
   },
   "justify": "'set source identity' -> sts:SetSourceIdentity"
  },
  {
   "id": "conversion_server_role",
   "kind": "exists",
   "tier": "core",
   "quote": "AWSElasticDisasterRecoveryConversionServerRole, AWSElasticDisasterRecoveryRecoveryInstanceRole, AWSElasticDisasterRecoveryReplicationServerRole, and AWSElasticDisasterRecoveryRecoveryInstanceWithLaunchActionsRole (all assuming ec2.amazonaws.com)",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "AWSElasticDisasterRecoveryConversionServerRole"
     },
     {
      "path": [
       "path"
      ],
      "op": "eq",
      "value": "/service-role/"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ec2.amazonaws.com"
     }
    ]
   }
  },
  {
   "id": "recovery_instance_role",
   "kind": "exists",
   "tier": "core",
   "quote": "AWSElasticDisasterRecoveryConversionServerRole, AWSElasticDisasterRecoveryRecoveryInstanceRole, AWSElasticDisasterRecoveryReplicationServerRole, and AWSElasticDisasterRecoveryRecoveryInstanceWithLaunchActionsRole (all assuming ec2.amazonaws.com)",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "AWSElasticDisasterRecoveryRecoveryInstanceRole"
     },
     {
      "path": [
       "path"
      ],
      "op": "eq",
      "value": "/service-role/"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ec2.amazonaws.com"
     }
    ]
   }
  },
  {
   "id": "replication_server_role",
   "kind": "exists",
   "tier": "core",
   "quote": "AWSElasticDisasterRecoveryConversionServerRole, AWSElasticDisasterRecoveryRecoveryInstanceRole, AWSElasticDisasterRecoveryReplicationServerRole, and AWSElasticDisasterRecoveryRecoveryInstanceWithLaunchActionsRole (all assuming ec2.amazonaws.com)",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "AWSElasticDisasterRecoveryReplicationServerRole"
     },
     {
      "path": [
       "path"
      ],
      "op": "eq",
      "value": "/service-role/"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ec2.amazonaws.com"
     }
    ]
   }
  },
  {
   "id": "launch_actions_role",
   "kind": "exists",
   "tier": "core",
   "quote": "AWSElasticDisasterRecoveryConversionServerRole, AWSElasticDisasterRecoveryRecoveryInstanceRole, AWSElasticDisasterRecoveryReplicationServerRole, and AWSElasticDisasterRecoveryRecoveryInstanceWithLaunchActionsRole (all assuming ec2.amazonaws.com)",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "AWSElasticDisasterRecoveryRecoveryInstanceWithLaunchActionsRole"
     },
     {
      "path": [
       "path"
      ],
      "op": "eq",
      "value": "/service-role/"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "ec2.amazonaws.com"
     }
    ]
   }
  },
  {
   "id": "attach_agent_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "Attach corresponding AWS-managed policies (AWSElasticDisasterRecoveryAgentPolicy, AWSElasticDisasterRecoveryFailbackPolicy, AWSElasticDisasterRecoveryConversionServerPolicy, AWSElasticDisasterRecoveryRecoveryInstancePolicy, and AWSElasticDisasterRecoveryReplicationServerPolicy) to their respective service roles",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryAgentRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryAgentPolicy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryAgentRole"
       },
       {
        "path": [
         "managed_policy_arns",
         "*"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryAgentPolicy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryAgentRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryAgentPolicy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "attach_failback_policy",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Attach corresponding AWS-managed policies (AWSElasticDisasterRecoveryAgentPolicy, AWSElasticDisasterRecoveryFailbackPolicy, AWSElasticDisasterRecoveryConversionServerPolicy, AWSElasticDisasterRecoveryRecoveryInstancePolicy, and AWSElasticDisasterRecoveryReplicationServerPolicy) to their respective service roles",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryFailbackRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryFailbackPolicy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryFailbackRole"
       },
       {
        "path": [
         "managed_policy_arns",
         "*"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryFailbackPolicy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryFailbackRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryFailbackPolicy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "attach_conversion_policy",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Attach corresponding AWS-managed policies (AWSElasticDisasterRecoveryAgentPolicy, AWSElasticDisasterRecoveryFailbackPolicy, AWSElasticDisasterRecoveryConversionServerPolicy, AWSElasticDisasterRecoveryRecoveryInstancePolicy, and AWSElasticDisasterRecoveryReplicationServerPolicy) to their respective service roles",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryConversionServerRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryConversionServerPolicy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryConversionServerRole"
       },
       {
        "path": [
         "managed_policy_arns",
         "*"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryConversionServerPolicy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryConversionServerRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryConversionServerPolicy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "attach_recovery_policy",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Attach corresponding AWS-managed policies (AWSElasticDisasterRecoveryAgentPolicy, AWSElasticDisasterRecoveryFailbackPolicy, AWSElasticDisasterRecoveryConversionServerPolicy, AWSElasticDisasterRecoveryRecoveryInstancePolicy, and AWSElasticDisasterRecoveryReplicationServerPolicy) to their respective service roles",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryRecoveryInstanceRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryRecoveryInstancePolicy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryRecoveryInstanceRole"
       },
       {
        "path": [
         "managed_policy_arns",
         "*"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryRecoveryInstancePolicy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryRecoveryInstanceRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryRecoveryInstancePolicy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "attach_replication_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "Attach corresponding AWS-managed policies (AWSElasticDisasterRecoveryAgentPolicy, AWSElasticDisasterRecoveryFailbackPolicy, AWSElasticDisasterRecoveryConversionServerPolicy, AWSElasticDisasterRecoveryRecoveryInstancePolicy, and AWSElasticDisasterRecoveryReplicationServerPolicy) to their respective service roles",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryReplicationServerRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryReplicationServerPolicy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryReplicationServerRole"
       },
       {
        "path": [
         "managed_policy_arns",
         "*"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryReplicationServerPolicy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryReplicationServerRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryReplicationServerPolicy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "attach_launch_actions_recovery_policy",
   "kind": "any_of",
   "tier": "detail",
   "quote": "attaching both AWSElasticDisasterRecoveryRecoveryInstancePolicy and AmazonSSMManagedInstanceCore to AWSElasticDisasterRecoveryRecoveryInstanceWithLaunchActionsRole",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryRecoveryInstanceWithLaunchActionsRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryRecoveryInstancePolicy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryRecoveryInstanceWithLaunchActionsRole"
       },
       {
        "path": [
         "managed_policy_arns",
         "*"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryRecoveryInstancePolicy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryRecoveryInstanceWithLaunchActionsRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecoveryRecoveryInstancePolicy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "attach_launch_actions_ssm_core",
   "kind": "any_of",
   "tier": "detail",
   "quote": "attaching both AWSElasticDisasterRecoveryRecoveryInstancePolicy and AmazonSSMManagedInstanceCore to AWSElasticDisasterRecoveryRecoveryInstanceWithLaunchActionsRole",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryRecoveryInstanceWithLaunchActionsRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AmazonSSMManagedInstanceCore"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryRecoveryInstanceWithLaunchActionsRole"
       },
       {
        "path": [
         "managed_policy_arns",
         "*"
        ],
        "op": "contains",
        "value": "AmazonSSMManagedInstanceCore"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "roles",
         "*"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryRecoveryInstanceWithLaunchActionsRole"
       },
       {
        "path": [
         "policy_arn"
        ],
        "op": "contains",
        "value": "AmazonSSMManagedInstanceCore"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "initializer_role",
   "kind": "exists",
   "tier": "core",
   "quote": "create a root-path initializer role named AWSElasticDisasterRecoveryInitializerRole that allows the current calling identity user ID to assume it",
   "select": {
    "types": [
     "aws_iam_role"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "AWSElasticDisasterRecoveryInitializerRole"
     },
     {
      "path": [
       "path"
      ],
      "op": "eq",
      "value": "/"
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "\"Principal\":\\{\"AWS\""
     },
     {
      "path": [
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "sts:AssumeRole"
     }
    ]
   },
   "justify": "'allows ... to assume it' -> sts:AssumeRole"
  },
  {
   "id": "initialize_policy_bound",
   "kind": "any_of",
   "tier": "core",
   "quote": "bound to a custom InitializePolicy",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryInitializerRole"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "InitializePolicy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "InitializePolicy"
       },
       {
        "path": [
         "role"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryInitializerRole"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "InitializePolicy"
       }
      ]
     },
     "to": {
      "types": [
       "aws_iam_role"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "AWSElasticDisasterRecoveryInitializerRole"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "init_policy_initialize_service",
   "kind": "any_of",
   "tier": "core",
   "quote": "permitting service initialization",
   "justify": "IAM action names implied by the stated permissions (service initialization, instance profile creation, PassRole, service-linked role creation, full EC2, role policy attachments); policy name \"InitializePolicy\" matched loosely; declared policy text accepted when the planned policy is unknown",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)initiali[sz]e"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "drs:InitializeService"
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)drs:InitializeService"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "init_policy_instance_profile",
   "kind": "any_of",
   "tier": "detail",
   "quote": "instance profile creation",
   "justify": "IAM action names implied by the stated permissions (service initialization, instance profile creation, PassRole, service-linked role creation, full EC2, role policy attachments); policy name \"InitializePolicy\" matched loosely; declared policy text accepted when the planned policy is unknown",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)initiali[sz]e"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "iam:CreateInstanceProfile"
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:(CreateInstanceProfile|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "init_policy_passrole",
   "kind": "any_of",
   "tier": "detail",
   "quote": "PassRole actions for EC2 and DRS services",
   "justify": "'PassRole actions' -> iam:PassRole (or iam:*); scoping to EC2/DRS may be via condition or not at all; policy name \"InitializePolicy\" matched loosely; declared policy text accepted when the planned policy is unknown",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)initiali[sz]e"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)iam:(PassRole|\\*)"
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:(PassRole|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "init_policy_slr",
   "kind": "any_of",
   "tier": "detail",
   "quote": "service-linked role creation for AWSServiceRoleForElasticDisasterRecovery",
   "justify": "'service-linked role creation' -> iam:CreateServiceLinkedRole, scoped by SLR name or by the DRS service principal; policy name \"InitializePolicy\" matched loosely; declared policy text accepted when the planned policy is unknown",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)initiali[sz]e"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "iam:CreateServiceLinkedRole"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)AWSServiceRoleForElasticDisasterRecovery|drs\\.amazonaws\\.com"
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:CreateServiceLinkedRole"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)AWSServiceRoleForElasticDisasterRecovery|drs"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "init_policy_ec2_full",
   "kind": "any_of",
   "tier": "detail",
   "quote": "full EC2 actions",
   "justify": "IAM action names implied by the stated permissions (service initialization, instance profile creation, PassRole, service-linked role creation, full EC2, role policy attachments); policy name \"InitializePolicy\" matched loosely; declared policy text accepted when the planned policy is unknown",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)initiali[sz]e"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "\"ec2:*\""
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ec2:\\*"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "init_policy_attach_restricted",
   "kind": "any_of",
   "tier": "detail",
   "quote": "role policy attachments restricted to the DRS managed policies",
   "justify": "'role policy attachments' -> iam:AttachRolePolicy, restricted to the DRS managed policies (listed or wildcarded); policy name \"InitializePolicy\" matched loosely; declared policy text accepted when the planned policy is unknown",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)initiali[sz]e"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "iam:AttachRolePolicy"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "AWSElasticDisasterRecovery"
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)iam:AttachRolePolicy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)AWSElasticDisasterRecovery"
       }
      ]
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
