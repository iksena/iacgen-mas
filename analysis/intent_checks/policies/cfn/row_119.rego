# GENERATED from specs/cfn/row_119.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_119

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "cluster": {
   "types": [
    "AWS::ECS::Cluster"
   ],
   "where": []
  },
  "svc": {
   "types": [
    "AWS::ECS::Service"
   ],
   "where": []
  },
  "taskdef": {
   "types": [
    "AWS::ECS::TaskDefinition"
   ],
   "where": []
  },
  "ns": {
   "types": [
    "AWS::ServiceDiscovery::PrivateDnsNamespace"
   ],
   "where": []
  },
  "sd": {
   "types": [
    "AWS::ServiceDiscovery::Service"
   ],
   "where": []
  },
  "vpc": {
   "types": [
    "AWS::EC2::VPC"
   ],
   "where": []
  },
  "subnet": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": []
  },
  "sg": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": []
  },
  "target": {
   "types": [
    "AWS::ApplicationAutoScaling::ScalableTarget"
   ],
   "where": []
  },
  "policy": {
   "types": [
    "AWS::ApplicationAutoScaling::ScalingPolicy"
   ],
   "where": []
  },
  "alarm": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": []
  },
  "param": {
   "types": [
    "__parameter__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "ecs_cluster",
   "kind": "exists",
   "select": "cluster",
   "tier": "core",
   "quote": "an ECS cluster"
  },
  {
   "id": "fargate_service",
   "kind": "any_of",
   "tier": "core",
   "quote": "a self-contained ECS Fargate microservice",
   "checks": [
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "LaunchType"
      ],
      "op": "eq",
      "value": "FARGATE"
     }
    },
    {
     "kind": "attr",
     "select": "svc",
     "cond": {
      "path": [
       "CapacityProviderStrategy",
       "*",
       "CapacityProvider"
      ],
      "op": "regex",
      "value": "(?i)^fargate"
     }
    }
   ]
  },
  {
   "id": "service_in_cluster",
   "kind": "ref",
   "from": "svc",
   "to": "cluster",
   "tier": "detail",
   "quote": "along with an ECS cluster"
  },
  {
   "id": "private_namespace_in_vpc",
   "kind": "ref",
   "from": "ns",
   "to": "vpc",
   "tier": "core",
   "quote": "a private Cloud Map service discovery namespace"
  },
  {
   "id": "cloud_map_service_in_namespace",
   "kind": "ref",
   "from": "sd",
   "to": "ns",
   "tier": "core",
   "quote": "a Cloud Map service so the ECS service can be discovered"
  },
  {
   "id": "srv_record",
   "kind": "attr",
   "select": "sd",
   "tier": "core",
   "quote": "via a private DNS SRV record",
   "cond": {
    "path": [
     "DnsConfig",
     "DnsRecords",
     "*",
     "Type"
    ],
    "op": "eq",
    "value": "SRV"
   }
  },
  {
   "id": "service_registers",
   "kind": "ref",
   "from": "svc",
   "to": "sd",
   "tier": "core",
   "quote": "registers itself with a private Cloud Map service discovery namespace"
  },
  {
   "id": "vpc",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "The stack should build its own VPC"
  },
  {
   "id": "three_subnets",
   "kind": "exists",
   "select": "subnet",
   "min": 3,
   "tier": "detail",
   "quote": "a public subnet, two private subnets",
   "justify": "one public plus two private subnets"
  },
  {
   "id": "subnets_two_azs",
   "kind": "exists",
   "select": "subnet",
   "distinct_path": [
    "AvailabilityZone"
   ],
   "min": 2,
   "tier": "detail",
   "quote": "two private subnets across separate availability zones",
   "justify": "separate availability zones means at least two distinct AZs"
  },
  {
   "id": "internet_gateway_attached",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::EC2::VPCGatewayAttachment"
    ],
    "where": []
   },
   "to": {
    "types": [
     "AWS::EC2::InternetGateway"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "an internet gateway"
  },
  {
   "id": "nat_gateway",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::EC2::NatGateway"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "a NAT gateway for the private subnets"
  },
  {
   "id": "private_route_via_nat",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::EC2::Route"
    ],
    "where": []
   },
   "to": {
    "types": [
     "AWS::EC2::NatGateway"
    ],
    "where": []
   },
   "tier": "detail",
   "quote": "a NAT gateway for the private subnets"
  },
  {
   "id": "sg_ingress_vpc_cidr",
   "kind": "any_of",
   "tier": "core",
   "quote": "a security group allowing the containers to communicate with each other within the VPC's CIDR range",
   "checks": [
    {
     "kind": "join",
     "from": "sg",
     "from_path": [
      "SecurityGroupIngress",
      "*",
      "CidrIp"
     ],
     "to": "vpc",
     "to_path": [
      "CidrBlock"
     ]
    },
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "SecurityGroupIngress",
       "*",
       "CidrIp"
      ],
      "op": "regex",
      "value": "CidrBlock"
     }
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::EC2::SecurityGroupIngress"
      ],
      "where": []
     },
     "from_path": [
      "CidrIp"
     ],
     "to": "vpc",
     "to_path": [
      "CidrBlock"
     ]
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::EC2::SecurityGroupIngress"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "CidrIp"
      ],
      "op": "regex",
      "value": "CidrBlock"
     }
    }
   ]
  },
  {
   "id": "task_execution_role",
   "kind": "ref",
   "from": "taskdef",
   "to": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": [
     {
      "path": [
       "AssumeRolePolicyDocument"
      ],
      "op": "contains",
      "value": "ecs-tasks.amazonaws.com"
     }
    ]
   },
   "tier": "core",
   "quote": "Provision the ECS task execution role"
  },
  {
   "id": "log_group",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::Logs::LogGroup"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "a CloudWatch log group for the container logs"
  },
  {
   "id": "container_awslogs",
   "kind": "attr",
   "select": "taskdef",
   "tier": "detail",
   "quote": "a CloudWatch log group for the container logs",
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
   "justify": "sending container logs to CloudWatch Logs uses the awslogs driver"
  },
  {
   "id": "param_container_port_80",
   "kind": "exists",
   "tier": "detail",
   "quote": "container port (defaulting to port 80",
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
      "value": "(?i)port"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": 80
     }
    ]
   }
  },
  {
   "id": "param_image_nginx",
   "kind": "exists",
   "tier": "detail",
   "quote": "on the nginx image",
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
      "value": "(?i)image"
     },
     {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "(?i)nginx"
     }
    ]
   }
  },
  {
   "id": "param_desired_count_2",
   "kind": "exists",
   "tier": "detail",
   "quote": "desired task count (defaulting to two tasks)",
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
      "value": "(?i)(desired|count)"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": 2
     }
    ]
   },
   "justify": "\"defaulting to two tasks\" means default 2"
  },
  {
   "id": "param_cpu_memory",
   "kind": "all_of",
   "tier": "detail",
   "quote": "CPU and memory",
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
         "name"
        ],
        "op": "regex",
        "value": "(?i)cpu"
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
        "value": "(?i)mem"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "param_env_service_names",
   "kind": "all_of",
   "tier": "detail",
   "quote": "parameters for the environment name, service name",
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
         "name"
        ],
        "op": "regex",
        "value": "(?i)env"
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
        "value": "(?i)service"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "param_optional_task_role",
   "kind": "exists",
   "tier": "detail",
   "quote": "an optional custom IAM role the containers can assume",
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
      "value": "(?i)role"
     }
    ]
   }
  },
  {
   "id": "scalable_target_2_to_10",
   "kind": "attr",
   "select": "target",
   "tier": "core",
   "quote": "configure application auto scaling on the ECS service between two and ten tasks",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "MinCapacity"
      ],
      "op": "eq",
      "value": 2
     },
     {
      "path": [
       "MaxCapacity"
      ],
      "op": "eq",
      "value": 10
     }
    ]
   },
   "justify": "\"between two and ten tasks\" means MinCapacity 2, MaxCapacity 10"
  },
  {
   "id": "scale_down_alarm_20",
   "kind": "ref",
   "tier": "core",
   "quote": "scaling down when average CPU utilization drops to or below 20 percent",
   "from": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "CPUUtilization"
     },
     {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 20
     },
     {
      "path": [
       "ComparisonOperator"
      ],
      "op": "eq",
      "value": "LessThanOrEqualToThreshold"
     }
    ]
   },
   "to": "policy",
   "justify": "\"drops to or below\" maps to LessThanOrEqualToThreshold"
  },
  {
   "id": "scale_up_alarm_70",
   "kind": "ref",
   "tier": "core",
   "quote": "scaling up in graduated steps when it climbs to or above 70 percent",
   "from": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "CPUUtilization"
     },
     {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 70
     },
     {
      "path": [
       "ComparisonOperator"
      ],
      "op": "eq",
      "value": "GreaterThanOrEqualToThreshold"
     }
    ]
   },
   "to": "policy",
   "justify": "\"climbs to or above\" maps to GreaterThanOrEqualToThreshold"
  },
  {
   "id": "graduated_step_policy",
   "kind": "attr",
   "select": "policy",
   "tier": "detail",
   "quote": "scaling up in graduated steps",
   "cond": {
    "path": [
     "StepScalingPolicyConfiguration",
     "StepAdjustments"
    ],
    "op": "len_gte",
    "value": 2
   },
   "justify": "graduated steps means more than one step adjustment"
  },
  {
   "id": "alarms_average_statistic",
   "kind": "attr",
   "select": "alarm",
   "quantifier": "all",
   "tier": "detail",
   "quote": "average CPU utilization",
   "cond": {
    "path": [
     "Statistic"
    ],
    "op": "eq",
    "value": "Average"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
