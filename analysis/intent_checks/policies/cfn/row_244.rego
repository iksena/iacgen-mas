package intent.cfn.row_244

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "idx": {
   "types": [
    "AWS::ResourceExplorer2::Index"
   ],
   "where": []
  },
  "view": {
   "types": [
    "AWS::ResourceExplorer2::View"
   ],
   "where": []
  },
  "dva": {
   "types": [
    "AWS::ResourceExplorer2::DefaultViewAssociation"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "tagkey_param",
   "kind": "exists",
   "tier": "detail",
   "quote": "parameters TagKey (defaulting to \"createdby\")",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "TagKey"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "createdby"
     }
    ]
   }
  },
  {
   "id": "tagvalue_param",
   "kind": "exists",
   "tier": "detail",
   "quote": "TagValue (defaulting to \"aws-cloudformation-templates\")",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "TagValue"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "aws-cloudformation-templates"
     }
    ]
   }
  },
  {
   "id": "index",
   "kind": "exists",
   "tier": "core",
   "quote": "an index",
   "select": "idx"
  },
  {
   "id": "index_aggregator",
   "kind": "attr",
   "tier": "core",
   "quote": "an aggregator-type Resource Explorer index",
   "select": "idx",
   "cond": {
    "path": [
     "Type"
    ],
    "op": "eq",
    "value": "AGGREGATOR"
   }
  },
  {
   "id": "index_tag",
   "kind": "attr",
   "tier": "detail",
   "quote": "tagged with key \"cratedby\" set to TagValue",
   "justify": "TagValue defaults to aws-cloudformation-templates",
   "select": "idx",
   "cond": {
    "path": [
     "Tags",
     "cratedby"
    ],
    "op": "eq",
    "value": "aws-cloudformation-templates"
   }
  },
  {
   "id": "view",
   "kind": "exists",
   "tier": "core",
   "quote": "a custom view",
   "select": "view"
  },
  {
   "id": "view_name",
   "kind": "attr",
   "tier": "core",
   "quote": "a Resource Explorer view named \"{TagKey}-{TagValue}\"",
   "justify": "TagKey and TagValue defaults are createdby and aws-cloudformation-templates",
   "select": "view",
   "cond": {
    "path": [
     "ViewName"
    ],
    "op": "eq",
    "value": "createdby-aws-cloudformation-templates"
   }
  },
  {
   "id": "view_tag",
   "kind": "attr",
   "tier": "detail",
   "quote": "a Resource Explorer view named \"{TagKey}-{TagValue}\" tagged with key \"cratedby\" set to TagValue",
   "justify": "TagValue defaults to aws-cloudformation-templates",
   "select": "view",
   "cond": {
    "path": [
     "Tags",
     "cratedby"
    ],
    "op": "eq",
    "value": "aws-cloudformation-templates"
   }
  },
  {
   "id": "view_includes_tags",
   "kind": "attr",
   "tier": "detail",
   "quote": "includes the \"tags\" property",
   "select": "view",
   "cond": {
    "path": [
     "IncludedProperties",
     "*",
     "Name"
    ],
    "op": "eq",
    "value": "tags"
   }
  },
  {
   "id": "view_depends_on_index",
   "kind": "any_of",
   "tier": "detail",
   "quote": "depends on the index",
   "checks": [
    {
     "kind": "ref",
     "from": "view",
     "to": "idx"
    },
    {
     "kind": "join",
     "from": "view",
     "from_path": [
      "__resource__",
      "DependsOn",
      "*"
     ],
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "AWS::ResourceExplorer2::Index"
       }
      ]
     },
     "to_path": [
      "name"
     ]
    }
   ]
  },
  {
   "id": "default_view_assoc",
   "kind": "exists",
   "tier": "core",
   "quote": "a default view association",
   "select": "dva"
  },
  {
   "id": "assoc_links_view",
   "kind": "ref",
   "tier": "core",
   "quote": "a default view association linking the created view",
   "from": "dva",
   "to": "view"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
