###############################################################
#
# This file contains configuration for all data source queries
#
###############################################################


# Get Public IP of your broadband account. This allows us to lock down SSH access
# into the environment from anyone other than yourself, by inserting your public
# IP to a security group ingress rule.
# Try this URL in your browser!
data "http" "cloudshell_ip" {
  url = "https://checkip.amazonaws.com/"
}


# Get AMI ID for latest recommended Amazon Linux 2 image
data "aws_ssm_parameter" "node_ami" {
  name = "/aws/service/eks/optimized-ami/1.24/amazon-linux-2/recommended/image_id"
}