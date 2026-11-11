package intent.cfn.row_029

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
  "pod_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "regex",
     "value": "pods\\.eks\\.amazonaws\\.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "role",
   "kind": "exists",
   "select": "role",
   "tier": "core",
   "quote": "creates an IAM role for SageMaker HyperPod training operator access"
  },
  {
   "id": "prefix_param",
   "kind": "attr",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "sagemaker-hyperpod-eks"
   },
   "tier": "detail",
   "quote": "a configurable resource name prefix with a default value of \"sagemaker-hyperpod-eks\""
  },
  {
   "id": "pod_identity_trust",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument"
    ],
    "op": "regex",
    "value": "pods\\.eks\\.amazonaws\\.com"
   },
   "tier": "core",
   "quote": "assumable by the EKS pod identity service",
   "justify": "the EKS pod identity service principal is pods.eks.amazonaws.com"
  },
  {
   "id": "hpto_managed_policy",
   "kind": "attr",
   "select": "pod_role",
   "cond": {
    "path": [
     "ManagedPolicyArns",
     "*"
    ],
    "op": "contains",
    "value": "AmazonSageMakerHyperPodTrainingOperatorAccess"
   },
   "tier": "core",
   "quote": "the AWS managed policy for SageMaker HyperPod training operator access",
   "justify": "managed policy name follows from the stated access type, on the role that the EKS pod identity principal pods.eks.amazonaws.com assumes"
  },
  {
   "id": "role_uses_prefix",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "RoleName"
    ],
    "op": "contains",
    "value": "sagemaker-hyperpod-eks"
   },
   "tier": "detail",
   "quote": "using a configurable resource name prefix",
   "justify": "the prefix default resolves into the role name"
  },
  {
   "id": "x_tag_session",
   "kind": "attr",
   "select": "role",
   "tier": "extra",
   "cond": {
    "path": [
     "AssumeRolePolicyDocument",
     "Statement",
     "*",
     "Action",
     "*"
    ],
    "op": "glob_covers",
    "value": "sts:TagSession"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
