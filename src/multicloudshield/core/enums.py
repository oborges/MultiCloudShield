from enum import StrEnum


class CloudProvider(StrEnum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    IBM = "ibm"
    DEMO = "demo"


class CredentialMechanism(StrEnum):
    AWS_DEFAULT_CHAIN = "aws_default_chain"
    AWS_ASSUME_ROLE = "aws_assume_role"
    AWS_SSO_PROFILE = "aws_sso_profile"
    AZURE_DEFAULT_CREDENTIAL = "azure_default_credential"
    AZURE_WORKLOAD_IDENTITY = "azure_workload_identity"
    AZURE_MANAGED_IDENTITY = "azure_managed_identity"
    GCP_ADC = "gcp_adc"
    GCP_IMPERSONATION = "gcp_impersonation"
    GCP_WORKLOAD_IDENTITY = "gcp_workload_identity"
    IBM_API_KEY_ENV = "ibm_api_key_env"
    IBM_TRUSTED_PROFILE = "ibm_trusted_profile"
    DEMO_NONE = "demo_none"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanErrorCategory(StrEnum):
    AUTHENTICATION = "authentication"
    PERMISSION_DENIED = "permission_denied"
    THROTTLED = "throttled"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    SERVICE_DISABLED = "service_disabled"
    UNSUPPORTED_REGION = "unsupported_region"
    API_ERROR = "api_error"
    PARSE_ERROR = "parse_error"
    INTERNAL = "internal"


class NormalizedResourceType(StrEnum):
    OBJECT_STORAGE_BUCKET = "object_storage.bucket"
    OBJECT_STORAGE_ACCOUNT = "object_storage.account"
    NETWORK_FIREWALL_RULESET = "network.firewall_ruleset"
    NETWORK_FIREWALL_RULE = "network.firewall_rule"
    IDENTITY_PRINCIPAL = "identity.principal"
    IDENTITY_POLICY_BINDING = "identity.policy_binding"
    LOGGING_AUDIT_TRAIL = "logging.audit_trail"
    LOGGING_DIAGNOSTIC_SETTING = "logging.diagnostic_setting"
    KMS_KEY = "kms.key"
    KMS_VAULT = "kms.vault"
    ACCOUNT_SCOPE = "account.scope"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def rank(self) -> int:
        return {
            Severity.INFORMATIONAL: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class FindingStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"


class EvaluationResult(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    INSUFFICIENT_DATA = "insufficient_data"
    ERROR = "error"
