package intent.cfn.row_256

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "AWS::EC2::VPC"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "172.16.0.0/16"
    }
   ]
  },
  "subnet": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": []
  },
  "subnet1": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "172.16.1.0/24"
    }
   ]
  },
  "subnet2": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "172.16.2.0/24"
    }
   ]
  },
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "launch_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "servicecatalog.amazonaws.com"
    }
   ]
  },
  "dms_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "RoleName"
     ],
     "op": "eq",
     "value": "dms-vpc-role"
    }
   ]
  },
  "dms_sng": {
   "types": [
    "AWS::DMS::ReplicationSubnetGroup"
   ],
   "where": []
  },
  "ec_sng": {
   "types": [
    "AWS::ElastiCache::SubnetGroup"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "provision a virtual private cloud using the 172.16.0.0/16 range"
  },
  {
   "id": "vpc_dns",
   "kind": "all_of",
   "tier": "detail",
   "quote": "with DNS support and DNS hostnames enabled",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "EnableDnsSupport"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "EnableDnsHostnames"
      ],
      "op": "truthy"
     }
    }
   ]
  },
  {
   "id": "two_subnets",
   "kind": "all_of",
   "tier": "core",
   "quote": "two subnets using 172.16.1.0/24 and 172.16.2.0/24",
   "checks": [
    {
     "kind": "ref",
     "from": "subnet1",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "subnet2",
     "to": "vpc"
    }
   ]
  },
  {
   "id": "subnets_first_two_azs",
   "kind": "exists",
   "tier": "detail",
   "quote": "in the first two availability zones in the region",
   "select": "subnet",
   "distinct_path": [
    "AvailabilityZone"
   ],
   "min": 2
  },
  {
   "id": "test_security_group",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::EC2::SecurityGroup"
    ],
    "where": []
   },
   "to": "vpc",
   "tier": "core",
   "quote": "a security group for the test resources"
  },
  {
   "id": "kms_key",
   "kind": "exists",
   "select": "key",
   "tier": "core",
   "quote": "create a customer managed KMS key"
  },
  {
   "id": "dms_subnet_group_both_subnets",
   "kind": "all_of",
   "tier": "core",
   "quote": "a DMS replication subnet group spanning both subnets",
   "checks": [
    {
     "kind": "ref",
     "from": "dms_sng",
     "to": "subnet1"
    },
    {
     "kind": "ref",
     "from": "dms_sng",
     "to": "subnet2"
    }
   ]
  },
  {
   "id": "dms_vpc_role",
   "kind": "exists",
   "select": "dms_role",
   "tier": "core",
   "quote": "the service role named dms-vpc-role"
  },
  {
   "id": "dms_vpc_role_trust",
   "kind": "attr",
   "select": "dms_role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "contains",
    "value": "dms.amazonaws.com"
   },
   "tier": "detail",
   "quote": "the service role named dms-vpc-role that DMS requires"
  },
  {
   "id": "elasticache_subnet_group",
   "kind": "ref",
   "from": "ec_sng",
   "to": "subnet",
   "tier": "core",
   "quote": "an ElastiCache subnet group"
  },
  {
   "id": "elasticache_security_group",
   "kind": "any_of",
   "tier": "detail",
   "quote": "cache security group",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::ElastiCache::SecurityGroup"
      ],
      "where": []
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::EC2::SecurityGroup"
      ],
      "where": []
     },
     "min": 2
    }
   ],
   "justify": "two security groups are stated (one for the test resources, one for the cache); a VPC security group is the modern equivalent of the legacy ElastiCache security group"
  },
  {
   "id": "sagemaker_execution_role",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": [
     {
      "path": [
       "AssumeRolePolicyDocument"
      ],
      "op": "contains",
      "value": "sagemaker.amazonaws.com"
     }
    ]
   },
   "quote": "an execution role for SageMaker"
  },
  {
   "id": "launch_roles_per_product",
   "kind": "exists",
   "select": "launch_role",
   "min": 14,
   "tier": "core",
   "quote": "create the launch roles that the Service Catalog products under test assume, one per product type covering application load balancers, listeners and target groups, autoscaling, DMS endpoints and instances, DynamoDB, EBS, EFS, ElastiCache, Elasticsearch, FSx, Kinesis, SNS, SQS, SageMaker and S3",
   "justify": "the listed product types number 14-17 depending on whether \"load balancers, listeners and target groups\" and \"DMS endpoints and instances\" are one type each; the lower bound is used"
  },
  {
   "id": "key_policy_grants_launch_roles",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the KMS key policy should grant those roles use of the key",
   "checks": [
    {
     "kind": "ref",
     "from": "key",
     "to": "launch_role"
    },
    {
     "kind": "attr",
     "select": "key",
     "cond": {
      "path": [
       "KeyPolicy"
      ],
      "op": "regex",
      "value": "(:role/[\\s\\S]*){14}"
     }
    }
   ],
   "justify": "same 14-role lower bound as launch_roles_per_product"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
