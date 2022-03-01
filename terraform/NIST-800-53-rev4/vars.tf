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

variable "GuarddutyNonArchivedFindingsParamDaysHighSev" {
  type    = string
  default = "1"
}

variable "GuarddutyNonArchivedFindingsParamDaysLowSev" {
  type    = string
  default = "30"
}

variable "GuarddutyNonArchivedFindingsParamDaysMediumSev" {
  type    = string
  default = "7"
}

variable "IamPasswordPolicyParamMaxPasswordAge" {
  type    = string
  default = "90"
}

variable "IamPasswordPolicyParamMinimumPasswordLength" {
  type    = string
  default = "14"
}

variable "IamPasswordPolicyParamPasswordReusePrevention" {
  type    = string
  default = "24"
}

variable "IamPasswordPolicyParamRequireLowercaseCharacters" {
  type    = string
  default = "true"
}

variable "IamPasswordPolicyParamRequireNumbers" {
  type    = string
  default = "true"
}

variable "IamPasswordPolicyParamRequireSymbols" {
  type    = string
  default = "true"
}

variable "IamPasswordPolicyParamRequireUppercaseCharacters" {
  type    = string
  default = "true"
}

variable "IamUserUnusedCredentialsCheckParamMaxCredentialUsageAge" {
  type    = string
  default = "90"
}

variable "RestrictedIncomingTrafficParamBlockedPort1" {
  type    = string
  default = "20"
}

variable "RestrictedIncomingTrafficParamBlockedPort2" {
  type    = string
  default = "21"
}

variable "RestrictedIncomingTrafficParamBlockedPort3" {
  type    = string
  default = "3389"
}

variable "RestrictedIncomingTrafficParamBlockedPort4" {
  type    = string
  default = "3306"
}

variable "RestrictedIncomingTrafficParamBlockedPort5" {
  type    = string
  default = "4333"
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

variable "VpcSgOpenOnlyToAuthorizedPortsParamAuthorizedTcpPorts" {
  type    = string
  default = "443"
}

variable "VpcSgOpenOnlyToAuthorizedPortsParamAuthorizedUdpPorts" {
  type    = string
  default = "1020-1025"
}