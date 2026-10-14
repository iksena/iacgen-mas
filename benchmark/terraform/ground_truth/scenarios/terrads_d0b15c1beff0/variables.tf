variable "account_name" {
    description = "Create AWS Account Name"
    type        = string
    default     = "ersia"
}

variable "ersia_iam_maps" {
    description = "Create IAM users with these names"
    type = map(object({
	    Name = string
		tags = map(string)
    }))
	
    default = {
        "dev1" = {
	        Name = "dev1"
			tags = {
	            Owner = "Devel"
	            email = "dev1@dev.com"
			}
	    }
	    
	    "dev2" = {
	        Name = "dev2"
			tags = {
	            Owner = "Devel"
	            email = "dev2@dev.com"
			}
	    }
	    
	    "guest" = {
	        Name = "guest"
			tags = {
	            Owner = "Guest"
	            email = "geust@dev.com"
			}
	    }
	}
}