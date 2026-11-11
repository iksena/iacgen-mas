package intent.tf.row_020

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "repos": {
   "types": [
    "aws_ecr_repository"
   ],
   "where": []
  },
  "flask": {
   "types": [
    "aws_ecr_repository"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "saints-xctf-api-flask"
    }
   ]
  },
  "nginx": {
   "types": [
    "aws_ecr_repository"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "saints-xctf-api-nginx"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "repo_flask",
   "kind": "exists",
   "select": "flask",
   "tier": "core",
   "quote": "The first repository must be named \"saints-xctf-api-flask\""
  },
  {
   "id": "repo_nginx",
   "kind": "exists",
   "select": "nginx",
   "tier": "core",
   "quote": "the second repository must be named \"saints-xctf-api-nginx\""
  },
  {
   "id": "flask_name_tag",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "flask",
     "cond": {
      "path": [
       "tags_all",
       "Name"
      ],
      "op": "eq",
      "value": "saints-xctf-api-flask-container-repository"
     }
    },
    {
     "kind": "attr",
     "select": "flask",
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "saints-xctf-api-flask-container-repository"
     }
    }
   ],
   "tier": "detail",
   "quote": "a Name tag of \"saints-xctf-api-flask-container-repository\""
  },
  {
   "id": "nginx_name_tag",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "nginx",
     "cond": {
      "path": [
       "tags_all",
       "Name"
      ],
      "op": "eq",
      "value": "saints-xctf-api-nginx-container-repository"
     }
    },
    {
     "kind": "attr",
     "select": "nginx",
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "saints-xctf-api-nginx-container-repository"
     }
    }
   ],
   "tier": "detail",
   "quote": "a Name tag of \"saints-xctf-api-nginx-container-repository\""
  },
  {
   "id": "immutable",
   "kind": "attr",
   "select": "repos",
   "cond": {
    "path": [
     "image_tag_mutability"
    ],
    "op": "eq",
    "value": "IMMUTABLE"
   },
   "tier": "core",
   "quote": "Both repositories must be configured with immutable image tags",
   "quantifier": "all"
  },
  {
   "id": "scan_on_push",
   "kind": "attr",
   "select": "repos",
   "cond": {
    "path": [
     "image_scanning_configuration",
     "*",
     "scan_on_push"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "automatic image scanning on push enabled",
   "quantifier": "all"
  },
  {
   "id": "tag_application",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "repos",
     "cond": {
      "path": [
       "tags_all",
       "Application"
      ],
      "op": "eq",
      "value": "saints-xctf"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": "repos",
     "cond": {
      "path": [
       "tags",
       "Application"
      ],
      "op": "eq",
      "value": "saints-xctf"
     },
     "quantifier": "all"
    }
   ],
   "tier": "detail",
   "quote": "shared tags specifying Application as \"saints-xctf\""
  },
  {
   "id": "tag_environment",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "repos",
     "cond": {
      "path": [
       "tags_all",
       "Environment"
      ],
      "op": "eq",
      "value": "all"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": "repos",
     "cond": {
      "path": [
       "tags",
       "Environment"
      ],
      "op": "eq",
      "value": "all"
     },
     "quantifier": "all"
    }
   ],
   "tier": "detail",
   "quote": "Environment as \"all\""
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
