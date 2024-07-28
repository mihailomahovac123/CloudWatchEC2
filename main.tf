terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.60.0"
    }
  }



    #preinstalled
    backend "s3" {
        bucket="tfstatemihailo"
        key="terraform3.state"
        region = "eu-central-1"
      
    }

}

provider "aws" {
  region="eu-central-1"
}

resource "aws_iam_role" "cloud_watch_access_role" {
  name="CloudWatchAccessForEC2Instance"
  assume_role_policy = jsonencode(


    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Principal": {
                "Service": [
                    "ec2.amazonaws.com"
                ]
            }
        }
    ]
}
)
}

resource "aws_iam_role_policy" "cloud_watch_full_access_policy" {
    name="cw_full_access_policy"
    role = aws_iam_role.cloud_watch_access_role.id

    policy=jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "autoscaling:Describe*",
                "cloudwatch:*",
                "logs:*",
                "sns:*",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRole",
                "oam:ListSinks"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "arn:aws:iam::*:role/aws-service-role/events.amazonaws.com/AWSServiceRoleForCloudWatchEvents*",
            "Condition": {
                "StringLike": {
                    "iam:AWSServiceName": "events.amazonaws.com"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "oam:ListAttachedLinks"
            ],
            "Resource": "arn:aws:oam:*:*:sink/*"
        }
    ]
})
}


#profil za ec2 instancu od date role

resource "aws_iam_instance_profile" "cloud_watch_instance_profile" {
    name="cloud_watch_instance_profile"
    role = aws_iam_role.cloud_watch_access_role.name #OVDE SE DODAJE ROLE, NE POLICY. NA POLICY BLOK SE DODAJE ROLE. ROLE SE ISPISUJE U INSTANCE PROFILE ROLE
}


#ec2 instanca i njena SG

resource "aws_security_group" "ec2_cw_agent_sg" {
    name = "ec2_cw_agent_sg"
    vpc_id = "vpc-0769af89e3dff6849"

    ingress {
        from_port = 22
        to_port = 22
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
  
}

#Amazon Linux 2 EC2 with preinstalled agent

resource "aws_instance" "ec2_with_cw_agent" {
  ami="ami-0dd35f81b9eeeddb1"
  subnet_id = "subnet-0c988bbc1a2d11109"
  instance_type = "t2.micro"
  associate_public_ip_address = true
  key_name = "first_key"

  iam_instance_profile = aws_iam_instance_profile.cloud_watch_instance_profile.name
  security_groups = [aws_security_group.ec2_cw_agent_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              sudo yum update -y 
              sudo yum install -y awslogs
              EOF
}
#promeni regiju i konfiguracionom fajlu: /etc/awslogs/awscli.conf na eu-central-1
#promeni log grupu u konfiguraciji cw-a: sudo vi /etc/awslogs/awslogs.conf da ti loggroup bude npr: var/log/messages1, a da se tu pusta samo ono sto na ec2 instanci imas na /var/log/messages
#sudo systemctl start awslogsd
#sudo systemctl enable awslogsd.serviceaws_iam_role_policy

#ssh -i first_key.pem ec2-user@<public-ip>
