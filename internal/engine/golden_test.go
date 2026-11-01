package engine_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/Techcadia/cloudtrail-console-actions/internal/engine"
	"github.com/Techcadia/cloudtrail-console-actions/internal/policy"
)

// The golden parity suite proves the embedded v2 policy reproduces the v1
// FilterRecords EMIT/DROP decision (and userName derivation) over a corpus of
// realistic records: every (eventSource, eventName) pair a v1 rule cares
// about, crossed with user agents, identities, request parameters and error
// codes.
//
// The single agreed divergence is the keep: block — security-critical writes
// are emitted even when v1 would have dropped them — asserted explicitly.

// keepListed are the preprocess.eventName values the default keep rule vetoes.
var keepListed = map[string]bool{
	"DeleteTrail":    true,
	"StopLogging":    true,
	"PutUserPolicy":  true,
	"DeleteFlowLogs": true,
	"UpdateTrail":    true,
}

type pair struct{ source, name string }

// pairs covers every branch of v1 FilterRecords plus emit controls. Names are
// kept realistic for their source: v1's first-match-wins switch and v2's
// union semantics only diverge on pathological combinations (e.g. an
// "AdminList*Session" event on ssm) that CloudTrail does not produce.
var pairs = []pair{
	// early source-level drops
	{"codecommit.amazonaws.com", "GitPush"},
	{"codecommit.amazonaws.com", "CreateRepository"},
	{"billingconsole.amazonaws.com", "AWSPaymentPortalService.AssessSorChangeImpact"},
	{"billingconsole.amazonaws.com", "AWSPaymentPortalService.ConvertCurrencies"},
	{"billingconsole.amazonaws.com", "AWSPaymentPortalService.GetAccountEDPStatus"},
	{"billingconsole.amazonaws.com", "AWSPaymentPortalService.UpdatePaymentPreferences"},
	{"billingconsole.amazonaws.com", "ConvertCurrencies"},
	{"support-console.amazonaws.com", "CheckServiceHealth"},
	{"support-console.amazonaws.com", "CreateCaseDraft"},
	{"support-console.amazonaws.com", "ResolveCase"},
	{"payments.amazonaws.com", "Payments_GetPaymentInstrument"},
	{"payments.amazonaws.com", "Payments_BatchGetInvoices"},
	{"payments.amazonaws.com", "Payments_ListPaymentPreferences"},
	{"payments.amazonaws.com", "MakePayment"},
	{"q.amazonaws.com", "StartConversation"},
	{"q.amazonaws.com", "SendMessage"},
	{"q.amazonaws.com", "PassRequest"},

	// read-only verb ladder
	{"s3.amazonaws.com", "GetObject"},
	{"s3.amazonaws.com", "getObject"},
	{"s3.amazonaws.com", "GETOBJECT"}, // Title() only case-folds the first rune
	{"s3.amazonaws.com", "ListBuckets"},
	{"iam.amazonaws.com", "listAccountAliases"},
	{"billing.amazonaws.com", "ViewBilling"},
	{"health.amazonaws.com", "viewEventDetails"},
	{"s3.amazonaws.com", "HeadObject"},
	{"ec2.amazonaws.com", "DescribeInstances"},
	{"elasticache.amazonaws.com", "TestFailover"},
	{"rds.amazonaws.com", "DownloadDBLogFilePortion"},
	{"datapipeline.amazonaws.com", "ReportTaskProgress"},
	{"storagegateway.amazonaws.com", "RefreshCache"},
	{"datapipeline.amazonaws.com", "PollForTask"},
	{"ses.amazonaws.com", "VerifyEmailIdentity"},
	{"transfer.amazonaws.com", "SkipCertificateValidation"},
	{"config.amazonaws.com", "SelectResourceConfig"},
	{"swf.amazonaws.com", "CountOpenWorkflowExecutions"},
	{"rekognition.amazonaws.com", "DetectFaces"},
	{"cloudtrail.amazonaws.com", "LookupEvents"},
	{"athena.amazonaws.com", "StartQueryExecution"},
	{"athena.amazonaws.com", "StopQueryExecution"},
	{"redshift-data.amazonaws.com", "CancelQueryExecution"},
	{"dynamodb.amazonaws.com", "BatchGetItem"},
	{"athena.amazonaws.com", "BatchGetQueryExecution"},
	{"resource-explorer-2.amazonaws.com", "SearchResources"},

	// exact-name drops
	{"signin.amazonaws.com", "CheckMfa"},
	{"route53domains.amazonaws.com", "CheckDomainAvailability"},
	{"kms.amazonaws.com", "Decrypt"},
	{"datapipeline.amazonaws.com", "SetTaskStatus"},
	{"s3.amazonaws.com", "QueryObjects"},
	{"accessanalyzer.amazonaws.com", "ValidatePolicy"},
	{"iam.amazonaws.com", "GenerateServiceLastAccessedDetails"},
	{"s3.amazonaws.com", "REST.GET.OBJECT_LOCK_CONFIGURATION"},
	{"sts.amazonaws.com", "AssumeRoleWithWebIdentity"},
	{"iam.amazonaws.com", "CreateVirtualMFADevice"},
	{"iam.amazonaws.com", "DeleteVirtualMFADevice"},

	// guarded cases
	{"signin.amazonaws.com", "ConsoleLogin"},
	{"cognito-idp.amazonaws.com", "AdminListUserAuthEvents"},
	{"cognito-idp.amazonaws.com", "AdminConfirmSignUp"},
	{"cognito-idp.amazonaws.com", "TokenGet"},
	{"cognito-idp.amazonaws.com", "InitiateAuth"},
	{"cognito-idp.amazonaws.com", "RespondToAuthChallenge"},
	{"cognito-idp.amazonaws.com", "SignUp"},
	{"eks.amazonaws.com", "AccessKubernetesApi"},
	{"logs.amazonaws.com", "CreateLogGroup"},
	{"logs.amazonaws.com", "CreateLogStream"},
	{"ec2.amazonaws.com", "CreateNetworkInterface"},
	{"elasticfilesystem.amazonaws.com", "NewClientConnection"},
	{"s3files.amazonaws.com", "NewClientConnection"},
	{"iam.amazonaws.com", "NewClientConnection"},
	{"quicksight.amazonaws.com", "QueryDatabase"},
	{"glue.amazonaws.com", "QueryDatabase"},
	{"sso.amazonaws.com", "Federate"},
	{"sso.amazonaws.com", "Authenticate"},
	{"sso.amazonaws.com", "Logout"},
	{"iam.amazonaws.com", "Federate"},
	{"signin.amazonaws.com", "UserAuthentication"},
	{"signin.amazonaws.com", "CredentialChallenge"},
	{"signin.amazonaws.com", "CredentialVerification"},
	{"iam.amazonaws.com", "CredentialChallenge"},
	{"cloudshell.amazonaws.com", "SendHeartBeat"},
	{"cloudshell.amazonaws.com", "CreateEnvironment"},
	{"cloudshell.amazonaws.com", "CreateSession"},
	{"cloudshell.amazonaws.com", "DeleteEnvironment"},
	{"cloudshell.amazonaws.com", "RedeemCode"},
	{"cloudshell.amazonaws.com", "startEnvironment"},
	{"cloudshell.amazonaws.com", "stopEnvironment"},
	{"cloudshell.amazonaws.com", "PutCredentials"},
	{"ssm.amazonaws.com", "StartSession"},
	{"ssm.amazonaws.com", "ResumeSession"},
	{"ssm.amazonaws.com", "TerminateSession"},
	{"ssm.amazonaws.com", "OpenDataChannel"},
	{"ec2.amazonaws.com", "StartSession"},
	{"ssm-guiconnect.amazonaws.com", "CancelConnection"},
	{"iam.amazonaws.com", "CancelConnection"},
	{"logs.amazonaws.com", "FilterLogEvents"},
	{"logs.amazonaws.com", "PutQueryDefinition"},
	{"s3.amazonaws.com", "PutObject"},
	{"sts.amazonaws.com", "AssumeRole"},
	{"sts.amazonaws.com", "AssumeRoleWithSAML"},
	{"inspector2-telemetry.amazonaws.com", "SendTelemetryEvent"},
	{"iam.amazonaws.com", "SendTelemetryEvent"},
	{"batch.amazonaws.com", "SubmitJob"},

	// keep-listed security writes (agreed v2 divergence)
	{"cloudtrail.amazonaws.com", "DeleteTrail"},
	{"cloudtrail.amazonaws.com", "StopLogging"},
	{"cloudtrail.amazonaws.com", "UpdateTrail"},
	{"iam.amazonaws.com", "PutUserPolicy"},
	{"ec2.amazonaws.com", "DeleteFlowLogs"},

	// emit controls
	{"ec2.amazonaws.com", "RunInstances"},
	{"s3.amazonaws.com", "CreateBucket"},
	{"iam.amazonaws.com", "DeleteUser"},
	{"ec2.amazonaws.com", "ModifyInstanceAttribute"},
	{"ec2.amazonaws.com", "CreateTags"},
}

var userAgents = []string{
	"", // no userAgent key at all
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
	"console.amazonaws.com",
	"Coral/Netty4",
	"AWS Signin, aws-internal/3",
	"S3Console/0.4",
	"console.ec2.amazonaws.com",
	"aws-internal/3 aws-sdk-java/1.11.1030",
	"aws-vpc-flow-logs.amazonaws.com",
	"aws-cli/2.13.0 Python/3.11.4",
	"APN/1.0 HashiCorp/1.0 Terraform/1.5.7",
	// edge cases for v1's unescaped "console.*.amazonaws.com"-style regexes
	"console-v2.amazonaws.com",
	"signin-proxy.amazonaws.com",
	"aws-sdk-js/3 consoleXamazonawsYcom",
	"[S3Console/0.4]",
	"AWS-Internal/3 aws-vpc-flow-logs",
	"aws-vpc-flow-logs aws-internal/3",
}

// identities: userIdentity variants v1 branches on.
var identities = []map[string]any{
	{"type": "IAMUser", "principalId": "AIDAEXAMPLE", "userName": "jane.doe", "accountId": "111111111111"},
	{"type": "AssumedRole", "principalId": "AROAEXAMPLE:jane@example.com", "accountId": "111111111111"},
	{"type": "Root", "principalId": "111111111111", "accountId": "111111111111"},
	{"type": "SAMLUser", "principalId": "AROASAML:saml.user", "accountId": "222222222222"},
	{"type": "AWSAccount", "principalId": "AIDAACCT:cross-acct", "accountId": "333333333333"},
	{"type": "AWSService", "principalId": "Anonymous"},
	{"type": "AssumedRole", "principalId": "AROAINT:internal", "invokedBy": "AWS Internal", "accountId": "111111111111"},
	{"type": "AssumedRole", "principalId": "AROAECS:svc", "invokedBy": "ecs-tasks.amazonaws.com", "accountId": "111111111111"},
	// 32 alphabetic chars after the colon: the Step Functions SubmitJob fingerprint
	{"type": "AssumedRole", "principalId": "AROASFN:abcdefghijklmnopqrstuvwxyzabcdef", "accountId": "111111111111"},
	// cognito-idp identities v1 cannot attribute to a user (v0.4.0)
	{"accountId": "111111111111"},
	{"type": "Unknown", "principalId": "Anonymous"},
}

// extras merge extra top-level fields into the record.
var extras = []map[string]any{
	{},
	{"readOnly": true},
	{"readOnly": false},
	{"requestParameters": map[string]any{"logGroupName": "RDSOSMetrics"}},
	{"requestParameters": map[string]any{"logGroupName": "/aws/lambda/foo"}},
	{"requestParameters": map[string]any{"description": "AWS Lambda VPC ENI-abc123"}},
	{"requestParameters": map[string]any{"key": "prefix/AWSLogs/111111111111/elasticloadbalancing/us-east-1/x.log"}},
	{"requestParameters": map[string]any{"key": "uploads/report.pdf"}},
	{"requestParameters": map[string]any{"sessionId": "jane.doe-0e95d1a239405ca7b"}},
	{"additionalEventData": map[string]any{"CredentialType": "EXTERNAL_IDP"}},
	{"additionalEventData": map[string]any{"CredentialType": "PASSWORD"}},
}

var errorCodes = []string{"", "AccessDenied", "ThrottlingException"}

func buildRecord(p pair, ua string, id map[string]any, extra map[string]any, errorCode string) map[string]any {
	rec := map[string]any{
		"eventSource":        p.source,
		"eventName":          p.name,
		"eventTime":          "2026-07-07T12:00:00Z",
		"eventID":            "b2f7f7a1-0000-4711-9d2e-example",
		"awsRegion":          "us-east-1",
		"recipientAccountId": "111111111111",
		"userIdentity":       maps.Clone(id),
	}
	if ua != "" {
		rec["userAgent"] = ua
	}
	if errorCode != "" {
		rec["errorCode"] = errorCode
	}
	maps.Copy(rec, extra)
	return rec
}

func compileDefault(t *testing.T) *engine.Engine {
	t.Helper()
	eng, err := engine.Compile(policy.Default())
	if err != nil {
		t.Fatalf("compiling default policy: %v", err)
	}
	return eng
}

func assertParity(t *testing.T, eng *engine.Engine, rec map[string]any) {
	t.Helper()
	v1Emit, v1User := v1Decision(rec)
	d := eng.Evaluate(rec)
	// v1 formats an absent principalId as fmt's "%!s(<nil>)"; v2 leaves it nil.
	if v1User == "%!s(<nil>)" {
		v1User = "<nil>"
	}

	// The keep block is the one agreed divergence: keep-listed writes must
	// always emit, even when v1 dropped them.
	if name, _ := d.Preprocess["eventName"].(string); keepListed[name] {
		if !d.Emit {
			t.Errorf("keep-listed %q must emit, dropped by %q\nrecord: %s", name, d.DroppedBy, recordJSON(rec))
		}
		if v1Emit && fmt.Sprint(d.Preprocess["userName"]) != v1User {
			t.Errorf("userName = %q, v1 = %q\nrecord: %s", d.Preprocess["userName"], v1User, recordJSON(rec))
		}
		return
	}

	if d.Emit != v1Emit {
		_, lines := eng.Explain(rec)
		t.Errorf("emit = %v, v1 = %v\nrecord: %s\ntrace:\n  %s",
			d.Emit, v1Emit, recordJSON(rec), joinLines(lines))
		return
	}
	if d.Emit && fmt.Sprint(d.Preprocess["userName"]) != v1User {
		t.Errorf("userName = %q, v1 = %q\nrecord: %s", d.Preprocess["userName"], v1User, recordJSON(rec))
	}
}

func TestGoldenParityCorpus(t *testing.T) {
	eng := compileDefault(t)
	count := 0
	for _, p := range pairs {
		for _, ua := range userAgents {
			for _, id := range identities {
				for _, extra := range extras {
					for _, ec := range errorCodes {
						assertParity(t, eng, buildRecord(p, ua, id, extra, ec))
						count++
					}
				}
			}
		}
	}
	t.Logf("corpus size: %d records", count)
}

// TestGoldenParityExamples runs the real CloudTrail sample files through both
// implementations.
func TestGoldenParityExamples(t *testing.T) {
	eng := compileDefault(t)

	files, err := filepath.Glob("../../examples/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no example files found: %v", err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Records []map[string]any `json:"Records"`
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			for _, rec := range doc.Records {
				assertParity(t, eng, rec)
			}
		})
	}
}

func recordJSON(rec map[string]any) string {
	b, _ := json.Marshal(rec)
	return string(b)
}

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n  "
	}
	return out
}
