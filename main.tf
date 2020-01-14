locals {
  is_t_instance_type = replace(var.instance_type, "/^t[23]{1}\\..*$/", "1") == "1" ? true : false
}

resource "aws_instance" "this" {
  count = var.instance_count

  ami              = data.aws_ami.default_ami.image_id
  instance_type    = var.instance_type
  user_data        = var.user_data
  user_data_base64 = var.user_data_base64
  subnet_id = length(var.network_interface) > 0 ? null : element(
    distinct(compact(concat([var.subnet_id], var.subnet_ids))),
    count.index,
  )
  key_name               = var.key_name
  monitoring             = var.monitoring
  get_password_data      = var.get_password_data
  vpc_security_group_ids = concat([aws_security_group.ec2_instance_sg.id], var.vpc_security_group_ids)
  iam_instance_profile   = aws_iam_role.ec2_instance_role.name

  associate_public_ip_address = var.associate_public_ip_address
  private_ip                  = length(var.private_ips) > 0 ? element(var.private_ips, count.index) : var.private_ip
  ipv6_address_count          = var.ipv6_address_count
  ipv6_addresses              = var.ipv6_addresses

  ebs_optimized = var.ebs_optimized

  dynamic "root_block_device" {
    for_each = var.root_block_device
    content {
      delete_on_termination = lookup(root_block_device.value, "delete_on_termination", null)
      encrypted             = lookup(root_block_device.value, "encrypted", null)
      iops                  = lookup(root_block_device.value, "iops", null)
      kms_key_id            = lookup(root_block_device.value, "kms_key_id", null)
      volume_size           = lookup(root_block_device.value, "volume_size", null)
      volume_type           = lookup(root_block_device.value, "volume_type", null)
    }
  }

  dynamic "ebs_block_device" {
    for_each = var.ebs_block_device
    content {
      delete_on_termination = lookup(ebs_block_device.value, "delete_on_termination", null)
      device_name           = ebs_block_device.value.device_name
      encrypted             = lookup(ebs_block_device.value, "encrypted", null)
      iops                  = lookup(ebs_block_device.value, "iops", null)
      kms_key_id            = lookup(ebs_block_device.value, "kms_key_id", null)
      snapshot_id           = lookup(ebs_block_device.value, "snapshot_id", null)
      volume_size           = lookup(ebs_block_device.value, "volume_size", null)
      volume_type           = lookup(ebs_block_device.value, "volume_type", null)
    }
  }

  dynamic "ephemeral_block_device" {
    for_each = var.ephemeral_block_device
    content {
      device_name  = ephemeral_block_device.value.device_name
      no_device    = lookup(ephemeral_block_device.value, "no_device", null)
      virtual_name = lookup(ephemeral_block_device.value, "virtual_name", null)
    }
  }

  dynamic "network_interface" {
    for_each = var.network_interface
    content {
      device_index          = network_interface.value.device_index
      network_interface_id  = lookup(network_interface.value, "network_interface_id", null)
      delete_on_termination = lookup(network_interface.value, "delete_on_termination", false)
    }
  }

  source_dest_check                    = length(var.network_interface) > 0 ? null : var.source_dest_check
  disable_api_termination              = var.disable_api_termination
  instance_initiated_shutdown_behavior = var.instance_initiated_shutdown_behavior
  placement_group                      = var.placement_group
  tenancy                              = var.tenancy

  tags = merge(
    {
      "Name" = var.instance_count > 1 || var.use_num_suffix ? format("%s-%d", var.name, count.index + 1) : var.name
    },
    var.tags,
  )

  volume_tags = merge(
    {
      "Name" = var.instance_count > 1 || var.use_num_suffix ? format("%s-%d", var.name, count.index + 1) : var.name
    },
    var.volume_tags,
  )

  credit_specification {
    cpu_credits = local.is_t_instance_type ? var.cpu_credits : null
  }
}

# Default cko-amzn2 packer image from mgmt
data "aws_ami" "default_ami" {
  most_recent = true
  owners      = ["791259062566"]

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "image-type"
    values = ["machine"]
  }

  filter {
    name   = "name"
    values = ["cko-amzn2-*"]
  }
}

## ---------------------------------------------------------------------------------------------------------------------
## Security Groups
## ---------------------------------------------------------------------------------------------------------------------
resource "aws_security_group" "ec2_instance_sg" {
  name        = "${var.name}-sg"
  description = "Security group for EC2 instances"
  vpc_id      = var.vpc_id
  tags        = merge({ Name = "${var.name}-sg" }, var.tags)
}

# ---------------------------------------------------------------------------------------------------------------------
# instance role
# ---------------------------------------------------------------------------------------------------------------------
resource "aws_iam_role" "ec2_instance_role" {
  name               = "${var.name}-instance"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  description        = "Instance role for ${var.name}."

  provisioner "local-exec" {
    command = "echo 'Sleeping for 15 seconds to wait for IAM role to be created'; sleep 15"
  }
}

# Hey im ec2 im trusted
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# To assign an IAM Role to an EC2 instance, we need to create the intermediate concept of an "IAM Instance Profile".
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name       = aws_iam_role.ec2_instance_role.name
  role       = aws_iam_role.ec2_instance_role.name
  depends_on = [aws_iam_role.ec2_instance_role]
}

resource "aws_security_group_rule" "allow_all_traffic_from_cidr_range" {
  count             = length(var.allow_inbound_from_cidr)
  type              = "ingress"
  from_port         = var.allow_inbound_from_cidr[count.index]["from_port"]
  to_port           = var.allow_inbound_from_cidr[count.index]["to_port"]
  protocol          = "tcp"
  security_group_id = aws_security_group.ec2_instance_sg.id
  cidr_blocks       = var.allow_inbound_from_cidr[count.index]["cidr"]
  description       = var.allow_inbound_from_cidr[count.index]["description"]
  depends_on        = [aws_security_group.ec2_instance_sg]
}

resource "aws_security_group_rule" "allow_all_traffic_from_security_groups" {
  count                    = length(var.allow_inbound_from_security_groups)
  type                     = "ingress"
  from_port                = var.allow_inbound_from_security_groups[count.index]["from_port"]
  to_port                  = var.allow_inbound_from_security_groups[count.index]["to_port"]
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ec2_instance_sg.id
  security_group_id        = var.allow_inbound_from_security_groups[count.index]["security_group_id"]
  description              = var.allow_inbound_from_security_groups[count.index]["description"]
  depends_on               = [aws_security_group.ec2_instance_sg]
}

resource "aws_security_group_rule" "ingress_with_self" {
  count             = length(var.allow_inbound_from_self)
  type              = "ingress"
  from_port         = var.allow_inbound_from_self[count.index]["from_port"]
  to_port           = var.allow_inbound_from_self[count.index]["to_port"]
  protocol          = "tcp"
  security_group_id = aws_security_group.ec2_instance_sg.id
  description       = "Self"
  self              = true
  depends_on        = [aws_security_group.ec2_instance_sg]
}

resource "aws_security_group_rule" "allow_outbound_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.ec2_instance_sg.id
  depends_on        = [aws_security_group.ec2_instance_sg]
}