variable "AccessKeysRotatedParamMaxAccessKeyAge" {
  type    = string
  default = "90"
}

variable "AcmCertificateExpirationCheckParamDaysToExpiration" {
  type    = string
  default = "90"
}

variable "Ec2VolumeInuseCheckParamDeleteOnTermination" {
  type    = string
  default = "TRUE"
}

variable "GUARDDUTY_NA_FINDINGS_PARAMS" {
  type = object({
    daysHighSev   = string
    daysMediumSev = string
    daysLowSev    = string
  })
  default = {
    "daysHighSev"   = "1"
    "daysMediumSev" = "7"
    "daysLowSev"    = "30"
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
    "MaxPasswordAge"             = "90"
    "MinimumPasswordLength"      = "14"
    "PasswordReusePrevention"    = "24"
    "RequireLowercaseCharacters" = "true"
    "RequireNumbers"             = "true"
    "RequireSymbols"             = "true"
    "RequireUppercaseCharacters" = "true"
  }
}

variable "IamUserUnusedCredentialsCheckParamMaxCredentialUsageAge" {
  type    = string
  default = "90"
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
    "blockedPort1" = "20"
    "blockedPort2" = "21"
    "blockedPort3" = "3389"
    "blockedPort4" = "3306"
    "blockedPort5" = "4333"
  }
}

variable "S3AccountLevelPublicAccessBlocksParamBlockPublicAcls" {
  type    = string
  default = "True"
}

variable "S3AccountLevelPublicAccessBlocksParamBlockPublicPolicy" {
  type    = string
  default = "True"
}

variable "S3AccountLevelPublicAccessBlocksParamIgnorePublicAcls" {
  type    = string
  default = "True"
}

variable "S3AccountLevelPublicAccessBlocksParamRestrictPublicBuckets" {
  type    = string
  default = "True"
}

variable "VpcSgOpenOnlyToAuthorizedPortsParams" {
  type = object({
    authorizedTcpPorts = string
    authorizedUdpPorts = string

  })
  default = {
    "authorizedTcpPorts" = "443"
    "authorizedUdpPorts" = "1020-1025"
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