provider "aws" {
    region = "ap-northeast-2"
}

resource "aws_iam_user" "ersia_iam" {
    for_each = var.ersia_iam_maps
	
	name = each.value["Name"]
	tags = each.value["tags"]
}

resource "aws_iam_user_group_membership" "ersia_iam_group_attach_devel" {
    for_each = var.ersia_iam_maps
	
    user   = each.value["Name"]
    groups = "${ each.value["tags"]["Owner"] == "Devel" ? [aws_iam_group.ersia_devel_group.name] : [aws_iam_group.ersia_guest_group.name] }"
}