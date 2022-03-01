


resource "aws_config_config_rule" "ACCESS_KEYS_ROTATED" {
  name        = "access-keys-rotated"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }
  input_parameters = jsonencode({
    maxAccessKeyAge = {
      value = var.AccessKeysRotatedParamMaxAccessKeyAge
    }
  })
}


resource "aws_config_config_rule" "ACM_CERTIFICATE_EXPIRATION_CHECK" {
  name        = "acm-certificate-expiration-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ACM_CERTIFICATE_EXPIRATION_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::ACM::Certificate"]
  }
  input_parameters = jsonencode({
    daysToExpiration = {
      value = var.AcmCertificateExpirationCheckParamDaysToExpiration
    }
  })
}


resource "aws_config_config_rule" "ALB_HTTP_DROP_INVALID_HEADER_ENABLED" {
  name        = "alb-http-drop-invalid-header-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ALB_HTTP_DROP_INVALID_HEADER_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
  }
}

resource "aws_config_config_rule" "ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK" {
  name        = "alb-http-to-https-redirection-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK"
  }
}

## NOT IN GOVCLOUD
# resource "aws_config_config_rule" "ALB_WAF_ENABLED" {
#   name        = "alb-waf-enabled"
#   description = ""
#   source {
#     owner             = "AWS"
#     source_identifier = "ALB_WAF_ENABLED"
#   }
#   scope {
#     compliance_resource_types = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
#   }
# }


resource "aws_config_config_rule" "API_GW_CACHE_ENABLED_AND_ENCRYPTED" {
  name        = "api-gw-cache-enabled-and-encrypted"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "API_GW_CACHE_ENABLED_AND_ENCRYPTED"
  }
  scope {
    compliance_resource_types = ["AWS::ApiGateway::Stage"]
  }
}

resource "aws_config_config_rule" "API_GW_EXECUTION_LOGGING_ENABLED" {
  name        = "api-gw-execution-logging-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "API_GW_EXECUTION_LOGGING_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::ApiGateway::Stage", "AWS::ApiGatewayV2::Stage"]
  }
}


resource "aws_config_config_rule" "AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED" {
  name        = "autoscaling-group-elb-healthcheck-required"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED"
  }
  scope {
    compliance_resource_types = ["AWS::AutoScaling::AutoScalingGroup"]
  }
}

resource "aws_config_config_rule" "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED" {
  name        = "cloud-trail-cloud-watch-logs-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED"
  }
}

resource "aws_config_config_rule" "CLOUD_TRAIL_ENABLED" {
  name        = "cloudtrail-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
}

resource "aws_config_config_rule" "CLOUD_TRAIL_ENCRYPTION_ENABLED" {
  name        = "cloud-trail-encryption-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
  }
}

resource "aws_config_config_rule" "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED" {
  name        = "cloud-trail-log-file-validation-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }
}

resource "aws_config_config_rule" "CLOUDTRAIL_S3_DATAEVENTS_ENABLED" {
  name        = "cloudtrail-s3-dataevents-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "CLOUDTRAIL_S3_DATAEVENTS_ENABLED"
  }
}


resource "aws_config_config_rule" "CLOUDTRAIL_SECURITY_TRAIL_ENABLED" {
  name        = "cloudtrail-security-trail-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "CLOUDTRAIL_SECURITY_TRAIL_ENABLED"
  }
}

variable "CWAlarmParams" {
  type = object({
    alarmActionRequired            = string
    insufficientDataActionRequired = string
    okActionRequired               = string
  })
  default = {
    "alarmActionRequired"            = "TRUE"
    "insufficientDataActionRequired" = "TRUE"
    "okActionRequired"               = "FALSE"
  }
}

resource "aws_config_config_rule" "CLOUDWATCH_ALARM_ACTION_CHECK" {
  name        = "cloudwatch-alarm-action-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_ALARM_ACTION_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::CloudWatch::Alarm"]
  }
  input_parameters = jsonencode(var.CWAlarmParams)
}

resource "aws_config_config_rule" "CLOUDWATCH_LOG_GROUP_ENCRYPTED" {
  name        = "cloudwatch-log-group-encrypted"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_LOG_GROUP_ENCRYPTED"
  }
}


resource "aws_config_config_rule" "CMK_BACKING_KEY_ROTATION_ENABLED" {
  name        = "cmk-backing-key-rotation-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }
}

resource "aws_config_config_rule" "CODEBUILD_PROJECT_ENVVAR_AWSCRED_CHECK" {
  name        = "codebuild-project-envvar-awscred-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "CODEBUILD_PROJECT_ENVVAR_AWSCRED_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::CodeBuild::Project"]
  }
}

resource "aws_config_config_rule" "CODEBUILD_PROJECT_SOURCE_REPO_URL_CHECK" {
  name        = "codebuild-project-source-repo-url-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "CODEBUILD_PROJECT_SOURCE_REPO_URL_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::CodeBuild::Project"]
  }
}

resource "aws_config_config_rule" "CW_LOGGROUP_RETENTION_PERIOD_CHECK" {
  name        = "cw-loggroup-retention-period-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "CW_LOGGROUP_RETENTION_PERIOD_CHECK"
  }
}

resource "aws_config_config_rule" "DB_INSTANCE_BACKUP_ENABLED" {
  name        = "db-instance-backup-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "DB_INSTANCE_BACKUP_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::RDS::DBInstance"]
  }
}

resource "aws_config_config_rule" "DMS_REPLICATION_NOT_PUBLIC" {
  name        = "dms-replication-not-public"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "DMS_REPLICATION_NOT_PUBLIC"
  }
}


## NOT IN GOVCLOUD
# resource "aws_config_config_rule" "DYNAMODB_AUTOSCALING_ENABLED" {
#   name        = "dynamodb-autoscaling-enabled"
#   description = ""
#   source {
#     owner             = "AWS"
#     source_identifier = "DYNAMODB_AUTOSCALING_ENABLED"
#   }
#   scope {
#     compliance_resource_types = ["AWS::DynamoDB::Table"]
#   }
# }


## NOT IN GOVLCOUD
# resource "aws_config_config_rule" "DYNAMODB_IN_BACKUP_PLAN" {
#   name        = "dynamodb-in-backup-plan"
#   description = ""
#   source {
#     owner             = "AWS"
#     source_identifier = "DYNAMODB_IN_BACKUP_PLAN"
#   }
# }


resource "aws_config_config_rule" "DYNAMODB_PITR_ENABLED" {
  name        = "dynamodb-pitr-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_PITR_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::DynamoDB::Table"]
  }
}

resource "aws_config_config_rule" "DYNAMODB_TABLE_ENCRYPTED_KMS" {
  name        = "dynamodb-table-encrypted-kms"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_TABLE_ENCRYPTED_KMS"
  }
  scope {
    compliance_resource_types = ["AWS::DynamoDB::Table"]
  }
}

## NOT IN GOVLCOUD
# resource "aws_config_config_rule" "EBS_IN_BACKUP_PLAN" {
#   name        = "ebs-in-backup-plan"
#   description = ""
#   source {
#     owner             = "AWS"
#     source_identifier = "EBS_IN_BACKUP_PLAN"
#   }
# }

resource "aws_config_config_rule" "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK" {
  name        = "ebs-snapshot-public-restorable-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"
  }
}

resource "aws_config_config_rule" "EC2_EBS_ENCRYPTION_BY_DEFAULT" {
  name        = "ec2-ebs-encryption-by-default"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
  }
}


resource "aws_config_config_rule" "EC2_IMDSV2_CHECK" {
  name        = "ec2-imdsv2-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::Instance"]
  }
}

resource "aws_config_config_rule" "EC2_INSTANCE_DETAILED_MONITORING_ENABLED" {
  name        = "ec2-instance-detailed-monitoring-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_DETAILED_MONITORING_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::Instance"]
  }
}

resource "aws_config_config_rule" "EC2_INSTANCE_MANAGED_BY_SSM" {
  name        = "ec2-instance-managed-by-systems-manager"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_MANAGED_BY_SSM"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::Instance", "AWS::SSM::ManagedInstanceInventory"]
  }
}

resource "aws_config_config_rule" "EC2_INSTANCE_NO_PUBLIC_IP" {
  name        = "ec2-instance-no-public-ip"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_NO_PUBLIC_IP"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::Instance"]
  }
}

resource "aws_config_config_rule" "EC2_MANAGEDINSTANCE_ASSOCIATION_COMPLIANCE_STATUS_CHECK" {
  name        = "ec2-managedinstance-association-compliance-status-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_ASSOCIATION_COMPLIANCE_STATUS_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::SSM::AssociationCompliance"]
  }
}

resource "aws_config_config_rule" "EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS_CHECK" {
  name        = "ec2-managedinstance-patch-compliance-status-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::SSM::PatchCompliance"]
  }
}

resource "aws_config_config_rule" "EC2_STOPPED_INSTANCE" {
  name        = "ec2-stopped-instance"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "EC2_STOPPED_INSTANCE"
  }
}

resource "aws_config_config_rule" "EC2_VOLUME_INUSE_CHECK" {
  name        = "ec2-volume-inuse-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "EC2_VOLUME_INUSE_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::Volume"]
  }
  input_parameters = jsonencode({
    deleteOnTermination = {
      value = var.Ec2VolumeInuseCheckParamDeleteOnTermination
    }
  })
}


resource "aws_config_config_rule" "EFS_ENCRYPTED_CHECK" {
  name        = "efs-encrypted-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "EFS_ENCRYPTED_CHECK"
  }
}

## NOT IN GOVLCOUD
# resource "aws_config_config_rule" "EFS_IN_BACKUP_PLAN" {
#   name        = "efs-in-backup-plan"
#   description = ""
#   source {
#     owner             = "AWS"
#     source_identifier = "EFS_IN_BACKUP_PLAN"
#   }
# }

resource "aws_config_config_rule" "ELASTICACHE_REDIS_CLUSTER_AUTOMATIC_BACKUP_CHECK" {
  name        = "elasticache-redis-cluster-automatic-backup-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ELASTICACHE_REDIS_CLUSTER_AUTOMATIC_BACKUP_CHECK"
  }
}

resource "aws_config_config_rule" "ELASTICSEARCH_ENCRYPTED_AT_REST" {
  name        = "elasticsearch-encrypted-at-rest"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ELASTICSEARCH_ENCRYPTED_AT_REST"
  }
}

resource "aws_config_config_rule" "ELASTICSEARCH_IN_VPC_ONLY" {
  name        = "elasticsearch-in-vpc-only"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ELASTICSEARCH_IN_VPC_ONLY"
  }
}

resource "aws_config_config_rule" "ELASTICSEARCH_NODE_TO_NODE_ENCRYPTION_CHECK" {
  name        = "elasticsearch-node-to-node-encryption-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ELASTICSEARCH_NODE_TO_NODE_ENCRYPTION_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::Elasticsearch::Domain"]
  }
}

resource "aws_config_config_rule" "ELB_ACM_CERTIFICATE_REQUIRED" {
  name        = "elb-acm-certificate-required"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ELB_ACM_CERTIFICATE_REQUIRED"
  }
  scope {
    compliance_resource_types = ["AWS::ElasticLoadBalancing::LoadBalancer"]
  }
}

resource "aws_config_config_rule" "ELB_CROSS_ZONE_LOAD_BALANCING_ENABLED" {
  name        = "elb-cross-zone-load-balancing-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ELB_CROSS_ZONE_LOAD_BALANCING_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::ElasticLoadBalancing::LoadBalancer"]
  }
}

resource "aws_config_config_rule" "ELB_DELETION_PROTECTION_ENABLED" {
  name        = "elb-deletion-protection-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ELB_DELETION_PROTECTION_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
  }
}

resource "aws_config_config_rule" "ELB_LOGGING_ENABLED" {
  name        = "elb-logging-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ELB_LOGGING_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::ElasticLoadBalancing::LoadBalancer", "AWS::ElasticLoadBalancingV2::LoadBalancer"]
  }
}

resource "aws_config_config_rule" "ELB_TLS_HTTPS_LISTENERS_ONLY" {
  name        = "elb-tls-https-listeners-only"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ELB_TLS_HTTPS_LISTENERS_ONLY"
  }
  scope {
    compliance_resource_types = ["AWS::ElasticLoadBalancing::LoadBalancer"]
  }
}

resource "aws_config_config_rule" "EMR_KERBEROS_ENABLED" {
  name        = "emr-kerberos-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "EMR_KERBEROS_ENABLED"
  }
}

resource "aws_config_config_rule" "EMR_MASTER_NO_PUBLIC_IP" {
  name        = "emr-master-no-public-ip"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "EMR_MASTER_NO_PUBLIC_IP"
  }
}

resource "aws_config_config_rule" "ENCRYPTED_VOLUMES" {
  name        = "encrypted-volumes"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::Volume"]
  }
}

resource "aws_config_config_rule" "GUARDDUTY_ENABLED_CENTRALIZED" {
  name        = "guardduty-enabled-centralized"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }
}

variable "GUARDDUTY_NA_FINDINGS_PARAMS" {
  type = object({
    daysHighSev   = string
    daysMediumSev = string
    daysLowSev    = string
  })
  default = {
    "daysHighSev"   = var.GuarddutyNonArchivedFindingsParamDaysHighSev
    "daysMediumSev" = var.GuarddutyNonArchivedFindingsParamDaysMediumSev
    "daysLowSev"    = var.GuarddutyNonArchivedFindingsParamDaysLowSev
  }
}

resource "aws_config_config_rule" "GUARDDUTY_NON_ARCHIVED_FINDINGS" {
  name        = "guardduty-non-archived-findings"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_NON_ARCHIVED_FINDINGS"
  }
  input_parameters = jsonencode(var.GUARDDUTY_NA_FINDINGS_PARAMS)
}


resource "aws_config_config_rule" "IAM_GROUP_HAS_USERS_CHECK" {
  name        = "iam-group-has-users-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "IAM_GROUP_HAS_USERS_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::IAM::Group"]
  }
}

resource "aws_config_config_rule" "IAM_NO_INLINE_POLICY_CHECK" {
  name        = "iam-no-inline-policy-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "IAM_NO_INLINE_POLICY_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::Group"]
  }
}



variable "IamPasswordPolicyParams" {
  type = object({
    MaxPasswordAge             = string
    MinimumPasswordLength      = string
    PasswordReusePrevention    = string
    RequireLowercaseCharacters = string
    RequireNumbers             = string
    RequireSymbols             = string
    RequireUppercaseCharacters = string

  })
  default = {
    "MaxPasswordAge"             = var.IamPasswordPolicyParamMaxPasswordAge
    "MinimumPasswordLength"      = var.IamPasswordPolicyParamMinimumPasswordLength
    "PasswordReusePrevention"    = var.IamPasswordPolicyParamPasswordReusePrevention
    "RequireLowercaseCharacters" = var.IamPasswordPolicyParamRequireLowercaseCharacters
    "RequireNumbers"             = var.IamPasswordPolicyParamRequireNumbers
    "RequireSymbols"             = var.IamPasswordPolicyParamRequireSymbols
    "RequireUppercaseCharacters" = var.IamPasswordPolicyParamRequireUppercaseCharacters
  }
}

resource "aws_config_config_rule" "IAM_PASSWORD_POLICY" {
  name        = "iam-password-policy"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }
  input_parameters = jsonencode(var.IamPasswordPolicyParams)
}


resource "aws_config_config_rule" "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS" {
  name        = "iam-policy-no-statements-with-admin-access"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }
  scope {
    compliance_resource_types = ["AWS::IAM::Policy"]
  }
}

resource "aws_config_config_rule" "IAM_ROOT_ACCESS_KEY_CHECK" {
  name        = "iam-root-access-key-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }
}

resource "aws_config_config_rule" "IAM_USER_GROUP_MEMBERSHIP_CHECK" {
  name        = "iam-user-group-membership-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_GROUP_MEMBERSHIP_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::IAM::User"]
  }
}

resource "aws_config_config_rule" "IAM_USER_MFA_ENABLED" {
  name        = "iam-user-mfa-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }
}

resource "aws_config_config_rule" "IAM_USER_NO_POLICIES_CHECK" {
  name        = "iam-user-no-policies-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_NO_POLICIES_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::IAM::User"]
  }
}

resource "aws_config_config_rule" "IAM_USER_UNUSED_CREDENTIALS_CHECK" {
  name        = "iam-user-unused-credentials-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  }
  input_parameters = jsonencode({
    maxCredentialUsageAge = {
      value = var.IamUserUnusedCredentialsCheckParamMaxCredentialUsageAge
    }
  })
}

resource "aws_config_config_rule" "INCOMING_SSH_DISABLED" {
  name        = "restricted-ssh"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::SecurityGroup"]
  }
}

resource "aws_config_config_rule" "INSTANCES_IN_VPC" {
  name        = "ec2-instances-in-vpc"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "INSTANCES_IN_VPC"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::Instance"]
  }
}

resource "aws_config_config_rule" "INTERNET_GATEWAY_AUTHORIZED_VPC_ONLY" {
  name        = "internet-gateway-authorized-vpc-only"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "INTERNET_GATEWAY_AUTHORIZED_VPC_ONLY"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::InternetGateway"]
  }
}

resource "aws_config_config_rule" "KMS_CMK_NOT_SCHEDULED_FOR_DELETION" {
  name        = "kms-cmk-not-scheduled-for-deletion"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "KMS_CMK_NOT_SCHEDULED_FOR_DELETION"
  }
  scope {
    compliance_resource_types = ["AWS::KMS::Key"]
  }
}

resource "aws_config_config_rule" "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED" {
  name        = "lambda-function-public-access-prohibited"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
  }
  scope {
    compliance_resource_types = ["AWS::Lambda::Function"]
  }
}

resource "aws_config_config_rule" "LAMBDA_INSIDE_VPC" {
  name        = "lambda-inside-vpc"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_INSIDE_VPC"
  }
  scope {
    compliance_resource_types = ["AWS::Lambda::Function"]
  }
}

resource "aws_config_config_rule" "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS" {
  name        = "mfa-enabled-for-iam-console-access"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }
}

resource "aws_config_config_rule" "MULTI_REGION_CLOUD_TRAIL_ENABLED" {
  name        = "multi-region-cloudtrail-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
  }
}

resource "aws_config_config_rule" "RDS_ENHANCED_MONITORING_ENABLED" {
  name        = "rds-enhanced-monitoring-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "RDS_ENHANCED_MONITORING_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::RDS::DBInstance"]
  }
}

## NOT IN GOVLCOUD
# resource "aws_config_config_rule" "RDS_IN_BACKUP_PLAN" {
#   name        = "rds-in-backup-plan"
#   description = ""
#   source {
#     owner             = "AWS"
#     source_identifier = "RDS_IN_BACKUP_PLAN"
#   }
# }

resource "aws_config_config_rule" "RDS_INSTANCE_DELETION_PROTECTION_ENABLED" {
  name        = "rds-instance-deletion-protection-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_DELETION_PROTECTION_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::RDS::DBInstance"]
  }
}

resource "aws_config_config_rule" "RDS_INSTANCE_PUBLIC_ACCESS_CHECK" {
  name        = "rds-instance-public-access-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::RDS::DBInstance"]
  }
}

resource "aws_config_config_rule" "RDS_LOGGING_ENABLED" {
  name        = "rds-logging-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "RDS_LOGGING_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::RDS::DBInstance"]
  }
}

resource "aws_config_config_rule" "RDS_MULTI_AZ_SUPPORT" {
  name        = "rds-multi-az-support"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "RDS_MULTI_AZ_SUPPORT"
  }
  scope {
    compliance_resource_types = ["AWS::RDS::DBInstance"]
  }
}

resource "aws_config_config_rule" "RDS_SNAPSHOT_ENCRYPTED" {
  name        = "rds-snapshot-encrypted"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "RDS_SNAPSHOT_ENCRYPTED"
  }
  scope {
    compliance_resource_types = ["AWS::RDS::DBSnapshot", "AWS::RDS::DBClusterSnapshot"]
  }
}


resource "aws_config_config_rule" "RDS_SNAPSHOTS_PUBLIC_PROHIBITED" {
  name        = "rds-snapshots-public-prohibited"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"
  }
  scope {
    compliance_resource_types = ["AWS::RDS::DBSnapshot", "AWS::RDS::DBClusterSnapshot"]
  }
}


resource "aws_config_config_rule" "RDS_STORAGE_ENCRYPTED" {
  name        = "rds-storage-encrypted"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }
  scope {
    compliance_resource_types = ["AWS::RDS::DBInstance"]
  }
}

variable "RedshiftClusterConfigurationCheckParams" {
  type = object({
    clusterDbEncrypted = string
    loggingEnabled     = string
  })
  default = {
    "clusterDbEncrypted" = "TRUE"
    "loggingEnabled"     = "TRUE"
  }
}

resource "aws_config_config_rule" "REDSHIFT_CLUSTER_CONFIGURATION_CHECK" {
  name        = "redshift-cluster-configuration-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_CLUSTER_CONFIGURATION_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::Redshift::Cluster"]
  }
  input_parameters = jsonencode(var.RedshiftClusterConfigurationCheckParams)
}


resource "aws_config_config_rule" "REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK" {
  name        = "redshift-cluster-public-access-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::Redshift::Cluster"]
  }
}

resource "aws_config_config_rule" "REDSHIFT_REQUIRE_TLS_SSL" {
  name        = "redshift-require-tls-ssl"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_REQUIRE_TLS_SSL"
  }
  scope {
    compliance_resource_types = ["AWS::Redshift::Cluster"]
  }
}

variable "RestrictedIncomingTrafficParams" {
  type = object({
    blockedPort1 = string
    blockedPort2 = string
    blockedPort3 = string
    blockedPort4 = string
    blockedPort5 = string

  })
  default = {
    "blockedPort1" = var.RestrictedIncomingTrafficParamBlockedPort1
    "blockedPort2" = var.RestrictedIncomingTrafficParamBlockedPort2
    "blockedPort3" = var.RestrictedIncomingTrafficParamBlockedPort3
    "blockedPort4" = var.RestrictedIncomingTrafficParamBlockedPort4
    "blockedPort5" = var.RestrictedIncomingTrafficParamBlockedPort5
  }
}

resource "aws_config_config_rule" "RESTRICTED_INCOMING_TRAFFIC" {
  name        = "restricted-common-ports"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }
  scope {
    compliance_resource_types = ["WS::EC2::SecurityGroup"]
  }
  input_parameters = jsonencode(var.RestrictedIncomingTrafficParams)
}


## NOT IN GOVLCOUD
# RootAccountHardwareMfaEnabled:
#   Properties:
#     ConfigRuleName: root-account-hardware-mfa-enabled
#     Source:
#       Owner: AWS
#       SourceIdentifier: ROOT_ACCOUNT_HARDWARE_MFA_ENABLED
#   Type: AWS::Config::ConfigRule

## NOT IN GOVLCOUD
# RootAccountMfaEnabled:
#   Properties:
#     ConfigRuleName: root-account-mfa-enabled
#     Source:
#       Owner: AWS
#       SourceIdentifier: ROOT_ACCOUNT_MFA_ENABLED
#   Type: AWS::Config::ConfigRule

## NOT IN GOVLCOUD
# S3AccountLevelPublicAccessBlocks:
#   Properties:
#     ConfigRuleName: s3-account-level-public-access-blocks
#     InputParameters:
#       BlockPublicAcls:
#         Fn::If:
#         - s3AccountLevelPublicAccessBlocksParamBlockPublicAcls
#         - Ref: S3AccountLevelPublicAccessBlocksParamBlockPublicAcls
#         - Ref: AWS::NoValue
#       BlockPublicPolicy:
#         Fn::If:
#         - s3AccountLevelPublicAccessBlocksParamBlockPublicPolicy
#         - Ref: S3AccountLevelPublicAccessBlocksParamBlockPublicPolicy
#         - Ref: AWS::NoValue
#       IgnorePublicAcls:
#         Fn::If:
#         - s3AccountLevelPublicAccessBlocksParamIgnorePublicAcls
#         - Ref: S3AccountLevelPublicAccessBlocksParamIgnorePublicAcls
#         - Ref: AWS::NoValue
#       RestrictPublicBuckets:
#         Fn::If:
#         - s3AccountLevelPublicAccessBlocksParamRestrictPublicBuckets
#         - Ref: S3AccountLevelPublicAccessBlocksParamRestrictPublicBuckets
#         - Ref: AWS::NoValue
#     Scope:
#       ComplianceResourceTypes:
#       - AWS::S3::AccountPublicAccessBlock
#     Source:
#       Owner: AWS
#       SourceIdentifier: S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS
#   Type: AWS::Config::ConfigRule

resource "aws_config_config_rule" "S3_BUCKET_DEFAULT_LOCK_ENABLED" {
  name        = "s3-bucket-default-lock-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_DEFAULT_LOCK_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
}

resource "aws_config_config_rule" "S3_BUCKET_LOGGING_ENABLED" {
  name        = "s3-bucket-logging-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LOGGING_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
}

resource "aws_config_config_rule" "S3_BUCKET_POLICY_GRANTEE_CHECK" {
  name        = "s3-bucket-policy-grantee-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_POLICY_GRANTEE_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
}

resource "aws_config_config_rule" "S3_BUCKET_PUBLIC_READ_PROHIBITED" {
  name        = "s3-bucket-public-read-prohibited"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
}

resource "aws_config_config_rule" "S3_BUCKET_PUBLIC_WRITE_PROHIBITED" {
  name        = "s3-bucket-public-write-prohibited"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
}

resource "aws_config_config_rule" "S3_BUCKET_REPLICATION_ENABLED" {
  name        = "s3-bucket-replication-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_REPLICATION_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
}

resource "aws_config_config_rule" "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED" {
  name        = "s3-bucket-server-side-encryption-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
}

resource "aws_config_config_rule" "S3_BUCKET_SSL_REQUESTS_ONLY" {
  name        = "s3-bucket-ssl-requests-only"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
}

resource "aws_config_config_rule" "S3_BUCKET_VERSIONING_ENABLED" {
  name        = "s3-bucket-versioning-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
}

resource "aws_config_config_rule" "SAGEMAKER_ENDPOINT_CONFIGURATION_KMS_KEY_CONFIGURED" {
  name        = "sagemaker-endpoint-configuration-kms-key-configured"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "SAGEMAKER_ENDPOINT_CONFIGURATION_KMS_KEY_CONFIGURED"
  }
}
resource "aws_config_config_rule" "SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED" {
  name        = "sagemaker-notebook-instance-kms-key-configured"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED"
  }
}

resource "aws_config_config_rule" "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS" {
  name        = "sagemaker-notebook-no-direct-internet-access"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS"
  }
}

resource "aws_config_config_rule" "SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK" {
  name        = "secretsmanager-scheduled-rotation-success-check"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK"
  }
  scope {
    compliance_resource_types = ["AWS::SecretsManager::Secret"]
  }
}

resource "aws_config_config_rule" "SECURITYHUB_ENABLED" {
  name        = "securityhub-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "SECURITYHUB_ENABLED"
  }
}

resource "aws_config_config_rule" "SNS_ENCRYPTED_KMS" {
  name        = "sns-encrypted-kms"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "SNS_ENCRYPTED_KMS"
  }
  scope {
    compliance_resource_types = ["AWS::SNS::Topic"]
  }
}

resource "aws_config_config_rule" "VPC_DEFAULT_SECURITY_GROUP_CLOSED" {
  name        = "vpc-default-security-group-closed"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::SecurityGroup"]
  }
}

resource "aws_config_config_rule" "VPC_FLOW_LOGS_ENABLED" {
  name        = "vpc-flow-logs-enabled"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }
}

variable "VpcSgOpenOnlyToAuthorizedPortsParams" {
  type = object({
    authorizedTcpPorts = string
    authorizedUdpPorts = string

  })
  default = {
    "authorizedTcpPorts" = var.VpcSgOpenOnlyToAuthorizedPortsParamAuthorizedTcpPorts
    "authorizedUdpPorts" = var.VpcSgOpenOnlyToAuthorizedPortsParamAuthorizedUdpPorts
  }
}

resource "aws_config_config_rule" "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS" {
  name        = "vpc-sg-open-only-to-authorized-ports"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS"
  }
  scope {
    compliance_resource_types = ["WS::EC2::SecurityGroup"]
  }
  input_parameters = jsonencode(var.VpcSgOpenOnlyToAuthorizedPortsParams)
}


resource "aws_config_config_rule" "VPC_VPN_2_TUNNELS_UP" {
  name        = "vpc-vpn-2-tunnels-up"
  description = ""
  source {
    owner             = "AWS"
    source_identifier = "VPC_VPN_2_TUNNELS_UP"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::VPNConnection"]
  }
}


## NOT IN GOVLCOUD
# Wafv2LoggingEnabled:
#   Properties:
#     ConfigRuleName: wafv2-logging-enabled
#     Source:
#       Owner: AWS
#       SourceIdentifier: WAFV2_LOGGING_ENABLED
#   Type: AWS::Config::ConfigRule