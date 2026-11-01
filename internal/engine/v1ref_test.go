package engine_test

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// v1Decision is a test-only, line-faithful port of v1 FilterRecords
// (main.go v0.4.0). It is the oracle for the golden parity tests: it returns
// whether v1 would emit the record, and the userName v1 would report.
//
// v1's Title() uses x/text cases.Title with NoLower; for single-token event
// names that reduces to upper-casing the first rune.
func v1Decision(record map[string]any) (emit bool, userName string) {
	userIdentity, _ := record["userIdentity"].(map[string]any)

	if userIdentity["invokedBy"] == "AWS Internal" {
		return false, ""
	}

	userName = fmt.Sprintf("%s", userIdentity["principalId"])
	if strings.Contains(userName, ":") {
		userName = strings.Split(userName, ":")[1]
	}
	if userIdentity["userName"] != nil {
		userName = fmt.Sprintf("%s", userIdentity["userName"])
	}

	eventName := record["eventName"].(string)

	if record["eventSource"] == "ssm.amazonaws.com" {
		if eventName == "OpenDataChannel" {
			if rps, ok := record["requestParameters"].(map[string]any); ok {
				if k, ok := rps["sessionId"].(string); ok {
					userName = k
				}
			}
		}
	}

	if record["eventSource"] == "codecommit.amazonaws.com" {
		return false, ""
	}

	if record["eventSource"] == "cognito-idp.amazonaws.com" {
		if _, ok := userIdentity["accountId"]; (len(userIdentity) == 1 && ok) ||
			userIdentity["type"] == "Unknown" {
			return false, ""
		}
	}

	if record["eventSource"] == "billingconsole.amazonaws.com" {
		eventName = strings.TrimPrefix(eventName, "AWSPaymentPortalService.")
		if eventName == "AssessSorChangeImpact" || eventName == "ConvertCurrencies" {
			return false, ""
		}
	}

	if record["eventSource"] == "support-console.amazonaws.com" {
		if strings.HasPrefix(eventName, "Check") {
			return false, ""
		}
		if eventName == "CreateCaseDraft" {
			return false, ""
		}
	}

	if record["eventSource"] == "payments.amazonaws.com" {
		if strings.Contains(eventName, "_Get") ||
			strings.Contains(eventName, "_BatchGet") ||
			strings.Contains(eventName, "_List") {
			return false, ""
		}
	}

	if record["eventSource"] == "q.amazonaws.com" {
		if ec, ok := record["errorCode"].(string); ok {
			if ec == "AccessDenied" || ec == "ThrottlingException" {
				if eventName == "StartConversation" || eventName == "SendMessage" {
					return false, ""
				}
			}
		}
	}

	switch en := eventName; {
	case strings.HasPrefix(title(en), "Get"):
		return false, ""
	case strings.HasPrefix(title(en), "List"):
		return false, ""
	case strings.HasPrefix(title(en), "View"):
		return false, ""
	case strings.HasPrefix(en, "Head"):
		return false, ""
	case strings.HasPrefix(en, "Describe"):
		return false, ""
	case strings.HasPrefix(en, "Test"):
		return false, ""
	case strings.HasPrefix(en, "Download"):
		return false, ""
	case strings.HasPrefix(en, "Report"):
		return false, ""
	case strings.HasPrefix(en, "Refresh"):
		return false, ""
	case strings.HasPrefix(en, "Poll"):
		return false, ""
	case strings.HasPrefix(en, "Verify"):
		return false, ""
	case strings.HasPrefix(en, "Skip"):
		return false, ""
	case strings.HasPrefix(en, "Select"):
		return false, ""
	case strings.HasPrefix(en, "Count"):
		return false, ""
	case strings.HasPrefix(en, "Detect"):
		return false, ""
	case strings.HasPrefix(en, "Lookup"):
		return false, ""

	case strings.HasPrefix(en, "AdminList"):
		if record["eventSource"] == "cognito-idp.amazonaws.com" {
			return false, ""
		}
	case strings.HasSuffix(strings.ToLower(en), "get"):
		if record["eventSource"] == "cognito-idp.amazonaws.com" {
			return false, ""
		}
	case en == "ConsoleLogin":
		if userIdentity["type"] != "Root" {
			return false, ""
		}
	case strings.HasSuffix(en, "VirtualMFADevice"):
		return false, ""
	case en == "CheckMfa":
		return false, ""
	case en == "InitiateAuth":
		if userIdentity["principalId"] == "Anonymous" {
			return false, ""
		}
	case en == "CheckDomainAvailability":
		return false, ""
	case en == "AccessKubernetesApi":
		if record["readOnly"] == true {
			return false, ""
		}
	case en == "Decrypt":
		return false, ""
	case en == "SetTaskStatus":
		return false, ""
	case en == "BatchGetQueryExecution":
		return false, ""
	case en == "QueryObjects":
		return false, ""
	case en == "ValidatePolicy":
		return false, ""
	case strings.HasPrefix(en, "StartQuery"):
		return false, ""
	case strings.HasPrefix(en, "StopQuery"):
		return false, ""
	case strings.HasPrefix(en, "CancelQuery"):
		return false, ""
	case strings.HasPrefix(en, "BatchGet"):
		return false, ""
	case strings.HasPrefix(en, "Search"):
		return false, ""
	case en == "GenerateServiceLastAccessedDetails":
		return false, ""
	case en == "REST.GET.OBJECT_LOCK_CONFIGURATION":
		return false, ""
	case en == "AssumeRoleWithWebIdentity":
		return false, ""

	case strings.HasPrefix(en, "CreateLog"):
		if rps, ok := record["requestParameters"].(map[string]any); ok {
			if k, ok := rps["logGroupName"].(string); ok {
				if k == "RDSOSMetrics" {
					return false, ""
				}
			}
		}

	case strings.HasPrefix(en, "CreateNetworkInterface"):
		if rps, ok := record["requestParameters"].(map[string]any); ok {
			if k, ok := rps["description"].(string); ok {
				if strings.HasPrefix(k, "AWS Lambda VPC ENI-") {
					return false, ""
				}
			}
		}

	case en == "NewClientConnection":
		if record["eventSource"] == "elasticfilesystem.amazonaws.com" {
			return false, ""
		}
		if record["eventSource"] == "s3files.amazonaws.com" {
			return false, ""
		}

	case en == "QueryDatabase":
		if record["eventSource"] == "quicksight.amazonaws.com" {
			return false, ""
		}

	case en == "Federate":
		if record["eventSource"] == "sso.amazonaws.com" {
			return false, ""
		}
	case en == "Authenticate":
		if record["eventSource"] == "sso.amazonaws.com" {
			return false, ""
		}
	case en == "Logout":
		if record["eventSource"] == "sso.amazonaws.com" {
			return false, ""
		}

	case en == "CredentialChallenge":
		if record["eventSource"] == "signin.amazonaws.com" {
			return false, ""
		}
	case en == "CredentialVerification":
		if record["eventSource"] == "signin.amazonaws.com" {
			return false, ""
		}
	case en == "UserAuthentication":
		if record["eventSource"] == "signin.amazonaws.com" {
			if aed, ok := record["additionalEventData"].(map[string]any); ok {
				if k, ok := aed["CredentialType"].(string); ok {
					if k == "EXTERNAL_IDP" {
						return false, ""
					}
				}
			}
		}

	case en == "SendHeartBeat":
		return false, ""
	case en == "CreateEnvironment":
		return false, ""
	case en == "CreateSession":
		return false, ""
	case en == "DeleteEnvironment":
		return false, ""
	case en == "RedeemCode":
		return false, ""
	case en == "startEnvironment":
		return false, ""
	case en == "stopEnvironment":
		return false, ""
	case en == "PutCredentials":
		return false, ""

	case strings.HasSuffix(en, "Session"):
		if record["eventSource"] == "ssm.amazonaws.com" {
			return false, ""
		}

	case en == "CancelConnection":
		if record["eventSource"] == "ssm-guiconnect.amazonaws.com" {
			return false, ""
		}

	case en == "FilterLogEvents":
		if record["eventSource"] == "logs.amazonaws.com" {
			return false, ""
		}
	case en == "PutQueryDefinition":
		if record["eventSource"] == "logs.amazonaws.com" {
			return false, ""
		}

	case en == "PutObject":
		if userIdentity["type"] == "AWSAccount" {
			if rps, ok := record["requestParameters"].(map[string]any); ok {
				if k, ok := rps["key"].(string); ok {
					if strings.Contains(k, "AWSLogs/") && strings.Contains(k, "/elasticloadbalancing/") {
						return false, ""
					}
				}
			}
		}

	case strings.HasPrefix(en, "AssumeRole"):
		if record["userAgent"] == "Coral/Netty4" {
			switch userIdentity["invokedBy"] {
			case
				"ecs-tasks.amazonaws.com",
				"ec2.amazonaws.com",
				"monitoring.rds.amazonaws.com",
				"lambda.amazonaws.com":
				return false, ""
			}
		}
		if userIdentity["type"] == "SAMLUser" {
			return false, ""
		}
		if userIdentity["type"] == "AWSAccount" {
			return false, ""
		}

	case en == "SendTelemetryEvent":
		if record["eventSource"] == "inspector2-telemetry.amazonaws.com" {
			return false, ""
		}

	case en == "SubmitJob":
		if len(userName) == 32 {
			matched, _ := regexp.MatchString(`^[a-zA-Z]+$`, userName)
			if matched {
				return false, ""
			}
		}
	}

	if usa, ok := record["userAgent"]; ok {
		switch ua := usa.(string); {
		case ua == "console.amazonaws.com":
		case ua == "signin.amazonaws.com":
		case ua == "Coral/Jakarta":
		case ua == "Coral/Netty4":
		case ua == "AWS CloudWatch Console":
		case strings.HasPrefix(ua, "AWS Signin"):
		case strings.HasPrefix(ua, "S3Console/"):
		case strings.HasPrefix(ua, "[S3Console"):
		case strings.HasPrefix(ua, "Mozilla/"):
		case strings.HasPrefix(ua, "[Mozilla/"):
		case matchString("console.*.amazonaws.com", ua):
		case matchString("signin.*.amazonaws.com", ua):
		case matchString("(?i)aws[\\s-]internal", ua):
			if matchString("^aws-vpc-flow-logs", ua) {
				return false, ""
			}
		default:
			return false, ""
		}
	}

	return true, userName
}

func matchString(m, s string) bool {
	v, _ := regexp.MatchString(m, s)
	return v
}

func title(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}
