data "aws_security_group" "default" {
  filter {
    name   = "group-name"
    values = ["default"]
  }

  vpc_id = data.aws_vpc.default.id
}

resource "aws_security_group_rule" "allow_all_traffic" {
  type        = "ingress"
  security_group_id = data.aws_security_group.default.id
  from_port    = 0
  to_port      = 0
  protocol     = "tcp"
  cidr_blocks  = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "allow_http" {
  type        = "ingress"
  security_group_id = data.aws_security_group.default.id
  from_port    = 80
  to_port      = 80
  protocol     = "tcp"
  cidr_blocks  = ["0.0.0.0/0"]
}
