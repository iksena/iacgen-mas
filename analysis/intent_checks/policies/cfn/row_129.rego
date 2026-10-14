# GENERATED from specs/cfn/row_129.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_129

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "pool": {
   "types": [
    "AWS::Cognito::UserPool"
   ],
   "where": []
  },
  "client": {
   "types": [
    "AWS::Cognito::UserPoolClient"
   ],
   "where": []
  },
  "idpool": {
   "types": [
    "AWS::Cognito::IdentityPool"
   ],
   "where": []
  },
  "attach": {
   "types": [
    "AWS::Cognito::IdentityPoolRoleAttachment"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "cog_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "cognito-identity.amazonaws.com"
    }
   ]
  },
  "iampol": {
   "types": [
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  },
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "two_user_pools",
   "kind": "exists",
   "select": "pool",
   "min": 2,
   "tier": "core",
   "quote": "two separate Cognito authentication setups"
  },
  {
   "id": "two_clients",
   "kind": "exists",
   "select": "client",
   "min": 2,
   "tier": "core",
   "quote": "a user pool client",
   "justify": "\"two separate Cognito authentication setups\", each with a user pool client"
  },
  {
   "id": "client_refs_pool",
   "kind": "ref",
   "from": "client",
   "to": "pool",
   "tier": "detail",
   "quote": "a user pool, a user pool client"
  },
  {
   "id": "two_identity_pools",
   "kind": "exists",
   "select": "idpool",
   "min": 2,
   "tier": "core",
   "quote": "an identity pool that allows unauthenticated access",
   "justify": "\"two separate Cognito authentication setups\", each with an identity pool"
  },
  {
   "id": "identity_pool_unauth",
   "kind": "attr",
   "select": "idpool",
   "tier": "core",
   "quote": "allows unauthenticated access",
   "cond": {
    "path": [
     "AllowUnauthenticatedIdentities"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "identity_pool_uses_user_pool",
   "kind": "any_of",
   "tier": "detail",
   "quote": "The main web app setup should include a user pool, a user pool client, an identity pool",
   "checks": [
    {
     "kind": "ref",
     "from": "idpool",
     "to": "client"
    },
    {
     "kind": "ref",
     "from": "idpool",
     "to": "pool"
    }
   ]
  },
  {
   "id": "cognito_roles_auth_unauth",
   "kind": "exists",
   "select": "cog_role",
   "min": 3,
   "tier": "core",
   "quote": "IAM roles for authenticated and unauthenticated users",
   "justify": "main setup names authenticated + unauthenticated roles; the provisioning setup only names \"the authenticated role\", so 3 is the lower bound"
  },
  {
   "id": "role_attachments",
   "kind": "exists",
   "select": "attach",
   "min": 2,
   "tier": "core",
   "quote": "Both identity pools should be attached to their respective roles"
  },
  {
   "id": "attachment_refs_idpool",
   "kind": "ref",
   "from": "attach",
   "to": "idpool",
   "tier": "core",
   "quote": "Both identity pools should be attached to their respective roles"
  },
  {
   "id": "attachment_auth_unauth",
   "kind": "all_of",
   "tier": "detail",
   "quote": "IAM roles for authenticated and unauthenticated users",
   "checks": [
    {
     "kind": "attr",
     "select": "attach",
     "cond": {
      "path": [
       "Roles",
       "authenticated"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "attach",
     "cond": {
      "path": [
       "Roles",
       "unauthenticated"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "attachment_refs_role",
   "kind": "ref",
   "from": "attach",
   "to": "role",
   "tier": "detail",
   "quote": "attached to their respective roles"
  },
  {
   "id": "perm_iot_ops",
   "kind": "any_of",
   "tier": "core",
   "quote": "permissions for common IoT operations",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "regex",
      "value": "(?i)iot:(Connect|Publish|Subscribe|Receive|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "iampol",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)iot:(Connect|Publish|Subscribe|Receive|\\*)"
     }
    }
   ]
  },
  {
   "id": "perm_kinesis_video",
   "kind": "any_of",
   "tier": "core",
   "quote": "Kinesis Video streaming actions",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "contains",
      "value": "kinesisvideo:"
     }
    },
    {
     "kind": "attr",
     "select": "iampol",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "contains",
      "value": "kinesisvideo:"
     }
    }
   ]
  },
  {
   "id": "perm_rekognition_labels",
   "kind": "any_of",
   "tier": "core",
   "quote": "Rekognition label detection",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "regex",
      "value": "(?i)rekognition:(DetectLabels|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "iampol",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)rekognition:(DetectLabels|\\*)"
     }
    }
   ]
  },
  {
   "id": "perm_cognito_mobileanalytics",
   "kind": "any_of",
   "tier": "detail",
   "quote": "standard Cognito and mobile analytics actions",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "regex",
      "value": "(?is)mobileanalytics:.*cognito-(sync|identity):|cognito-(sync|identity):.*mobileanalytics:"
     }
    },
    {
     "kind": "attr",
     "select": "iampol",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?is)mobileanalytics:.*cognito-(sync|identity):|cognito-(sync|identity):.*mobileanalytics:"
     }
    }
   ]
  },
  {
   "id": "perm_trusted_user_provisioning",
   "kind": "any_of",
   "tier": "core",
   "quote": "the authenticated role should instead grant permissions for IoT trusted user provisioning actions",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "regex",
      "value": "(?i)iot:(CreateProvisioningClaim|RegisterThing|CreateKeysAndCertificate|CreateCertificateFromCsr|[A-Za-z]*Provisioning[A-Za-z]*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "iampol",
     "cond": {
      "path": [
       "PolicyDocument"
      ],
      "op": "regex",
      "value": "(?i)iot:(CreateProvisioningClaim|RegisterThing|CreateKeysAndCertificate|CreateCertificateFromCsr|[A-Za-z]*Provisioning[A-Za-z]*|\\*)"
     }
    }
   ]
  },
  {
   "id": "output_identity_pool_ids",
   "kind": "ref",
   "from": "out",
   "to": "idpool",
   "tier": "detail",
   "quote": "output the identity pool IDs"
  },
  {
   "id": "output_user_pool_ids",
   "kind": "ref",
   "from": "out",
   "to": "pool",
   "tier": "detail",
   "quote": "user pool IDs"
  },
  {
   "id": "output_client_ids",
   "kind": "ref",
   "from": "out",
   "to": "client",
   "tier": "detail",
   "quote": "client IDs for both setups"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
