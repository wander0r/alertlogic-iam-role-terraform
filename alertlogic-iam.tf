resource "aws_iam_role" "alertlogic_access" {
  name               = module.label.id
  assume_role_policy = data.aws_iam_policy_document.alertlogic_assume_role.json
  tags               = module.label.tags
}

data "aws_iam_policy_document" "alertlogic_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type = "AWS"

      identifiers = [
        local.alertlogic_account, # in a locals.tf - add your AlertLogic Account ID
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [local.alertlogic_external_id] # in a locals.tf - add your AlertLogic external ID
    }
  }

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type = "AWS"

      identifiers = [
        local.alertlogic_application_registry_account,
        local.alertlogic_s3_collector
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [local.alertlogic_external_id] # in a locals.tf - add your AlertLogic external ID
    }
  }
}

data "aws_iam_policy_document" "alertlogic_access" {

  statement {
    sid = "S3RetrieveObjects"
    actions = [
      "s3:GetObject",
      "s3:ListBucketMultipartUploads",
      "s3:GetBucketTagging",
      "s3:GetBucketLogging",
      "s3:ListBucketVersions",
      "s3:GetObjectTagging",
      "s3:ListBucket",
      "s3:GetBucketAcl",
      "s3:GetBucketNotification",
      "s3:GetBucketLocation",
      "s3:ListMultipartUploadParts",
    ]
    resources = [
      "arn:aws:s3:::*",
    ]
    effect = "Allow"
  }

  statement {
    sid       = "S3ListBuckets"
    actions   = ["s3:ListAllMyBuckets"]
    resources = ["*"]
    effect    = "Allow"
  }

  statement {
    sid       = "ReadExistingCloudTrailsTopic"
    resources = ["*"]
    effect    = "Allow"
    actions = [
      "sns:gettopicattributes",
      "sns:listtopics",
      "sns:settopicattributes",
      "sns:subscribe",
    ]
  }

  statement {
    sid       = "BeAbleToListSQS"
    resources = ["*"]
    effect    = "Allow"
    actions = [
      "sqs:ListQueues",
    ]
  }

  statement {
    sid       = "CreateAlertLogicSqsQueueToSubscribeToCloudTrailsSnsTopicNotifications"
    resources = ["arn:aws:sqs:*:*:outcomesbucket*"]
    effect    = "Allow"
    actions = [
      "sqs:CreateQueue",
      "sqs:DeleteQueue",
      "sqs:SetQueueAttributes",
      "sqs:GetQueueAttributes",
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueUrl",
    ]
  }
  statement {
    sid       = "ReadExistingCloudTrailS3Bucket"
    resources = ["*"]
    effect    = "Allow"
    actions = [
      "s3:GetBucketPolicy",
      "s3:ListBucket",
      "s3:GetBucketLocation",
      "s3:GetObject",
    ]
  }

  statement {
    sid       = "CreateCloudTrailsTopicTfOneWasntAlreadySetupForCloudTrails"
    resources = ["arn:aws:sns:*:*:outcomestopic"]
    effect    = "Allow"
    actions = [
      "sns:CreateTopic",
      "sns:DeleteTopic",
    ]
  }
  statement {
    sid       = "BeAbleToValidateOurRoleAndDiscoverIAM"
    resources = ["*"]
    effect    = "Allow"
    actions = [
      "iam:List*",
      "iam:Get*",
    ]
  }

  statement {
    sid = "AllowDecryptOfCloudTrailKey"
    resources = [
        # Provide any KMS keys to decrypt (AlertLogic doesn't support AWS Default Keys)
    ]
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
  }
}

resource "aws_iam_policy" "alertlogic_access" {
  name        = module.label.id
  description = "AlertLogic Cross Account Role"
  policy      = data.aws_iam_policy_document.alertlogic_access.json
}

resource "aws_iam_role_policy_attachment" "alertlogic_access" {
  role       = aws_iam_role.alertlogic_access.name
  policy_arn = aws_iam_policy.alertlogic_access.arn
}


data "aws_iam_policy_document" "console_alertlogic_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type = "AWS"

      identifiers = [
        local.alertlogic_account, # in a locals.tf - add your AlertLogic Account ID
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [local.alertlogic_external_id] # in a locals.tf - add your AlertLogic external ID
    }
  }
}

data "aws_iam_policy_document" "console_alertlogic_access" {
  statement {
    sid       = "EnabledDiscoveryOfVariousAWSServices"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "autoscaling:Describe*",
      "cloudformation:DescribeStack*",
      "cloudformation:GetTemplate",
      "cloudformation:ListStack*",
      "cloudfront:Get*",
      "cloudfront:List*",
      "cloudwatch:Describe*",
      "config:DeliverConfigSnapshot",
      "config:Describe*",
      "config:Get*",
      "config:ListDiscoveredResources",
      "cur:DescribeReportDefinitions",
      "directconnect:Describe*",
      "dynamodb:ListTables",
      "ec2:Describe*",
      "ecs:Describe*",
      "ecs:List*",
      "elasticbeanstalk:Describe*",
      "elasticache:Describe*",
      "elasticloadbalancing:Describe*",
      "elasticmapreduce:DescribeJobFlows",
      "events:Describe*",
      "events:List*",
      "glacier:ListVaults",
      "guardduty:Get*",
      "guardduty:List*",
      "kinesis:Describe*",
      "kinesis:List*",
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListAliases",
      "kms:ListGrants",
      "kms:ListKeys",
      "kms:ListKeyPolicies",
      "kms:ListResourceTags",
      "lambda:List*",
      "logs:Describe*",
      "rds:Describe*",
      "rds:ListTagsForResource",
      "redshift:Describe*",
      "route53:GetHostedZone",
      "route53:ListHostedZones",
      "route53:ListResourceRecordSets",
      "sdb:DomainMetadata",
      "sdb:ListDomains",
      "sns:ListSubscriptions",
      "sns:ListSubscriptionsByTopic",
      "sns:ListTopics",
      "sns:GetEndpointAttributes",
      "sns:GetSubscriptionAttributes",
      "sns:GetTopicAttributes",
      "s3:ListAllMyBuckets",
      "s3:ListBucket",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:GetBucket*",
      "s3:GetLifecycleConfiguration",
      "s3:GetObjectAcl",
      "s3:GetObjectVersionAcl",
      "tag:GetResources",
      "tag:GetTagKeys",
      "workspaces:Describe*",
      "workspaces:List*",
    ]
  }

  statement {
    sid       = "EnableInsightDiscovery"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "iam:Get*",
      "iam:List*",
      "iam:GenerateCredentialReport",
    ]
  }

  statement {
    sid       = "EnableCloudTrailIfAccountDoesntHaveCloudTrailsEnabled"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetEventSelectors",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:ListPublicKeys",
      "cloudtrail:ListTags",
      "cloudtrail:LookupEvents",
      "cloudtrail:StartLogging",
      "cloudtrail:UpdateTrail",
    ]
  }

  statement {
    sid       = "CreateCloudTrailS3BucketIfCloudTrailsAreBeingSetupByAlertLogic"
    effect    = "Allow"
    resources = ["arn:aws:s3:::outcomesbucket-*"]

    actions = [
      "s3:CreateBucket",
      "s3:PutBucketPolicy",
      "s3:DeleteBucket",
    ]
  }

  statement {
    sid       = "CreateCloudTrailsTopicTfOneWasntAlreadySetupForCloudTrails"
    effect    = "Allow"
    resources = ["arn:aws:sns:*:*:outcomestopic"]

    actions = [
      "sns:CreateTopic",
      "sns:DeleteTopic",
    ]
  }

  statement {
    sid       = "MakeSureThatCloudTrailsSnsTopicIsSetupCorrectlyForCloudTrailPublishingAndSqsSubsription"
    effect    = "Allow"
    resources = ["arn:aws:sns:*:*:*"]

    actions = [
      "sns:AddPermission",
      "sns:GetTopicAttributes",
      "sns:ListTopics",
      "sns:SetTopicAttributes",
      "sns:Subscribe",
    ]
  }

  statement {
    sid       = "CreateAlertLogicSqsQueueToSubscribeToCloudTrailsSnsTopicNotifications"
    effect    = "Allow"
    resources = ["arn:aws:sqs:*:*:outcomesbucket*"]

    actions = [
      "sqs:CreateQueue",
      "sqs:DeleteQueue",
      "sqs:SetQueueAttributes",
      "sqs:GetQueueAttributes",
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueUrl",
    ]
  }

  statement {
    sid       = "BeAbleToListSQSForCloudTrail"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["sqs:ListQueues"]
  }

  statement {
    sid       = "EnableAlertLogicApplianceStateManagement"
    effect    = "Allow"
    resources = ["arn:aws:ec2:*:*:instance/*"]

    actions = [
      "ec2:GetConsoleOutput",
      "ec2:GetConsoleScreenShot",
      "ec2:StartInstances",
      "ec2:StopInstances",
      "ec2:TerminateInstances",
    ]

    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/AlertLogic"
      values   = ["Security"]
    }
  }

  statement {
    sid       = "EnableAlertLogicAutoScalingGroupManagement"
    effect    = "Allow"
    resources = ["arn:aws:autoscaling:*:*:autoScalingGroup:*:autoScalingGroupName/*"]
    actions   = ["autoscaling:UpdateAutoScalingGroup"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/AlertLogic"
      values   = ["Security"]
    }
  }

}

resource "aws_iam_policy" "console_alertlogic_access" {
  name        = module.console_access_label.id
  description = "AlertLogic Cross Account Role"
  policy      = data.aws_iam_policy_document.console_alertlogic_access.json
}

resource "aws_iam_role_policy_attachment" "console_alertlogic_access" {
  role       = aws_iam_role.console_alertlogic_access.name
  policy_arn = aws_iam_policy.console_alertlogic_access.arn
}