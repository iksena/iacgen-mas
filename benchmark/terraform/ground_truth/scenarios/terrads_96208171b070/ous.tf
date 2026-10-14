locals {
  # ["a", "/a/", "b/c/", "/b/d", "e/f/g/"] => ["a", "b/c", "b/d", "e/f/g"]
  trimmed_ous = distinct([for ou in var.ous : trim(ou, "/")])
  # ["a", "b/c", "b/d", "e/f/g"] => [["a"], ["b", "c"], ["b", "d"], ["e", "f", "g"]]
  safe_ous = distinct([for ou in local.trimmed_ous : split("/", ou)])

  # [["a"], ["b", "c"], ["b", "d"], ["e", "f", "g"]] => [["a"], ["b"], ["e"]]
  l0_ou_paths = distinct([for ou in local.safe_ous : slice(ou, 0, 1)])
  # [["a"], ["b", "c"], ["b", "d"], ["e", "f", "g"]] => [["b", "c"], ["b", "d"], ["e", "f"]]
  l1_ou_paths = distinct([for ou in local.safe_ous : slice(ou, 0, 2) if length(ou) > 1])
  # [["a"], ["b", "c"], ["b", "d"], ["e", "f", "g"]] => [["e", "f", "g"]]
  l2_ou_paths = distinct([for ou in local.safe_ous : slice(ou, 0, 3) if length(ou) > 2])
  l3_ou_paths = distinct([for ou in local.safe_ous : slice(ou, 0, 4) if length(ou) > 3])
  l4_ou_paths = distinct([for ou in local.safe_ous : slice(ou, 0, 5) if length(ou) > 4])

  # [["a"], ["b"], ["e"]] =>
  #   {a = {name = "a"}, b = {name = "b"}, e = {name = "e"}}
  l0_ous = { for ou_path in local.l0_ou_paths :
    join("/", ou_path) => {
      name = element(ou_path, length(ou_path) - 1)
    }
  }
  # [["b", "c"], ["b", "d"], ["e", "f"]] =>
  #   {b/c = {name = "c", parent_name = "b"}, b/d = {name = "d", parent_name = "b"}, e/f = {name = "f", parent_name = "e"}}
  l1_ous = { for ou_path in local.l1_ou_paths :
    join("/", ou_path) => {
      name = element(ou_path, length(ou_path) - 1)
      # parent_name = element(ou_path, length(ou_path) - 2)
      parent_name = join("/", slice(ou_path, 0, length(ou_path) - 1))
    }
  }
  # [["e", "f", "g"]] => {e/f/g = {name = "g", parent_name = "e/f"}}
  l2_ous = { for ou_path in local.l2_ou_paths :
    join("/", ou_path) => {
      name        = element(ou_path, length(ou_path) - 1)
      parent_name = join("/", slice(ou_path, 0, length(ou_path) - 1))
    }
  }
  l3_ous = { for ou_path in local.l3_ou_paths :
    join("/", ou_path) => {
      name        = element(ou_path, length(ou_path) - 1)
      parent_name = join("/", slice(ou_path, 0, length(ou_path) - 1))
    }
  }
  l4_ous = { for ou_path in local.l4_ou_paths :
    join("/", ou_path) => {
      name        = element(ou_path, length(ou_path) - 1)
      parent_name = join("/", slice(ou_path, 0, length(ou_path) - 1))
    }
  }

  # {a/b/c = {level = 2, name = c}}
  ous_helper = {
    for p in concat(
      local.l0_ou_paths,
      local.l1_ou_paths,
      local.l2_ou_paths,
      local.l3_ou_paths,
      local.l4_ou_paths,
    ) : join("/", p) => { level = length(p) - 1 }
  }
  # {a/b/c = resource.2["a/b/c"]}
  ous = { for ou_path_str, ou in local.ous_helper : ou_path_str =>
    ou["level"] == 0 ? aws_organizations_organizational_unit.l0[ou_path_str] :
    ou["level"] == 1 ? aws_organizations_organizational_unit.l1[ou_path_str] :
    ou["level"] == 2 ? aws_organizations_organizational_unit.l2[ou_path_str] :
    ou["level"] == 3 ? aws_organizations_organizational_unit.l3[ou_path_str] :
    aws_organizations_organizational_unit.l4[ou_path_str]
  }
}

resource "aws_organizations_organizational_unit" "l0" {
  for_each  = local.l0_ous
  name      = each.value["name"]
  parent_id = aws_organizations_organization.org.roots[0].id
}

resource "aws_organizations_organizational_unit" "l1" {
  for_each  = local.l1_ous
  name      = each.value["name"]
  parent_id = aws_organizations_organizational_unit.l0[each.value["parent_name"]].id
}

resource "aws_organizations_organizational_unit" "l2" {
  for_each  = local.l2_ous
  name      = each.value["name"]
  parent_id = aws_organizations_organizational_unit.l1[each.value["parent_name"]].id
}

resource "aws_organizations_organizational_unit" "l3" {
  for_each  = local.l3_ous
  name      = each.value["name"]
  parent_id = aws_organizations_organizational_unit.l2[each.value["parent_name"]].id
}

resource "aws_organizations_organizational_unit" "l4" {
  for_each  = local.l4_ous
  name      = each.value["name"]
  parent_id = aws_organizations_organizational_unit.l3[each.value["parent_name"]].id
}
