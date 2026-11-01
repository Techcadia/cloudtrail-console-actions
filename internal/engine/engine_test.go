package engine

import (
	"strings"
	"testing"

	"github.com/Techcadia/cloudtrail-console-actions/v2/internal/policy"
)

func compileYAML(t *testing.T, src string) *Engine {
	t.Helper()
	p, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	e, err := Compile(p)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return e
}

const testPolicy = `
apiVersion: cca/v1
kind: FilterPolicy
preprocess:
  eventName:
    - when:
        all:
          - { key: "{{ eventSource }}", operator: Equals, value: billingconsole.amazonaws.com }
      value: "{{ trimPrefix(eventName, 'AWSPaymentPortalService.') }}"
    - value: "{{ eventName }}"
  userName:
    - when:
        all:
          - { key: "{{ userIdentity.userName || '' }}", operator: NotEquals, value: "" }
      value: "{{ userIdentity.userName }}"
    - when:
        all:
          - { key: "{{ contains(userIdentity.principalId, ':') }}", operator: Equals, value: true }
      value: "{{ split(userIdentity.principalId, ':')[1] }}"
    - value: "{{ userIdentity.principalId }}"
keep:
  - name: always-surface-security-writes
    match:
      any:
        - { key: "{{ preprocess.eventName }}", operator: AnyIn, value: [DeleteTrail, StopLogging] }
filters:
  - name: drop-reads
    action: skip
    match:
      all:
        - { key: "{{ preprocess.eventName }}", operator: AnyIn, value: ["Get*", "List*"] }
  - name: drop-billing-noise
    action: skip
    match:
      all:
        - { key: "{{ eventSource }}", operator: Equals, value: billingconsole.amazonaws.com }
        - { key: "{{ preprocess.eventName }}", operator: AnyIn, value: [ConvertCurrencies] }
  - name: drop-non-console-user-agent
    action: skip
    match:
      all:
        - { key: "{{ userAgent || '' }}", operator: NotEquals, value: "" }
    exclude:
      any:
        - { key: "{{ userAgent }}", operator: AnyIn, value: ["Mozilla/*", console.amazonaws.com] }
outputs:
  event_name: "{{ eventName }}"
  user_name: "{{ preprocess.userName }}"
  account_id:
    - when:
        all:
          - { key: "{{ recipientAccountId || '' }}", operator: NotEquals, value: "" }
      value: "{{ recipientAccountId }}"
    - value: "{{ userIdentity.accountId || '' }}"
`

func consoleRecord(eventName string) map[string]any {
	return map[string]any{
		"eventSource": "iam.amazonaws.com",
		"eventName":   eventName,
		"userAgent":   "Mozilla/5.0",
		"userIdentity": map[string]any{
			"principalId": "AIDAEXAMPLE:jane",
			"accountId":   "111111111111",
		},
	}
}

func TestEvaluateSkip(t *testing.T) {
	e := compileYAML(t, testPolicy)
	d := e.Evaluate(consoleRecord("GetUser"))
	if d.Emit {
		t.Fatal("GetUser emitted, want drop")
	}
	if d.DroppedBy != "drop-reads" {
		t.Errorf("DroppedBy = %q, want drop-reads", d.DroppedBy)
	}
}

func TestEvaluateExcludeCarveOut(t *testing.T) {
	e := compileYAML(t, testPolicy)

	// Console-like user agent is carved out by exclude.
	if d := e.Evaluate(consoleRecord("PutUserPolicy")); !d.Emit {
		t.Errorf("console UA dropped by %q", d.DroppedBy)
	}

	// CLI user agent matches and is not excluded.
	rec := consoleRecord("PutUserPolicy")
	rec["userAgent"] = "aws-cli/2.13"
	if d := e.Evaluate(rec); d.Emit {
		t.Error("CLI UA emitted, want drop")
	}

	// Missing user agent never matches the rule at all.
	rec = consoleRecord("PutUserPolicy")
	delete(rec, "userAgent")
	if d := e.Evaluate(rec); !d.Emit {
		t.Errorf("missing UA dropped by %q, want emit", d.DroppedBy)
	}
}

func TestEvaluateKeepVetoesSkip(t *testing.T) {
	e := compileYAML(t, testPolicy)
	rec := consoleRecord("DeleteTrail")
	rec["userAgent"] = "aws-cli/2.13" // would be dropped by the UA gate
	d := e.Evaluate(rec)
	if !d.Emit {
		t.Fatalf("DeleteTrail dropped by %q despite keep rule", d.DroppedBy)
	}
	if d.KeptBy != "always-surface-security-writes" {
		t.Errorf("KeptBy = %q", d.KeptBy)
	}
}

func TestPreprocessNormalization(t *testing.T) {
	e := compileYAML(t, testPolicy)

	// billingconsole names are trimmed for matching...
	rec := consoleRecord("AWSPaymentPortalService.ConvertCurrencies")
	rec["eventSource"] = "billingconsole.amazonaws.com"
	d := e.Evaluate(rec)
	if d.Emit {
		t.Fatal("trimmed ConvertCurrencies emitted, want drop")
	}
	if d.DroppedBy != "drop-billing-noise" {
		t.Errorf("DroppedBy = %q", d.DroppedBy)
	}

	// ...but the raw record field is what outputs project.
	rec = consoleRecord("AWSPaymentPortalService.SetPaymentInstrument")
	rec["eventSource"] = "billingconsole.amazonaws.com"
	d = e.Evaluate(rec)
	if !d.Emit {
		t.Fatalf("dropped by %q", d.DroppedBy)
	}
	if got := d.Outputs["event_name"]; got != "AWSPaymentPortalService.SetPaymentInstrument" {
		t.Errorf("event_name = %#v, want raw name", got)
	}
	if got := d.Preprocess["eventName"]; got != "SetPaymentInstrument" {
		t.Errorf("preprocess.eventName = %#v, want trimmed name", got)
	}
}

func TestPreprocessUserNamePrecedence(t *testing.T) {
	e := compileYAML(t, testPolicy)

	// userIdentity.userName wins when present.
	rec := consoleRecord("PutUserPolicy")
	rec["userIdentity"].(map[string]any)["userName"] = "jane.doe"
	if got := e.Evaluate(rec).Preprocess["userName"]; got != "jane.doe" {
		t.Errorf("userName = %#v, want jane.doe", got)
	}

	// principalId after the colon otherwise.
	rec = consoleRecord("PutUserPolicy")
	if got := e.Evaluate(rec).Preprocess["userName"]; got != "jane" {
		t.Errorf("userName = %#v, want jane", got)
	}

	// bare principalId as the last resort.
	rec = consoleRecord("PutUserPolicy")
	rec["userIdentity"].(map[string]any)["principalId"] = "AROAEXAMPLE"
	if got := e.Evaluate(rec).Preprocess["userName"]; got != "AROAEXAMPLE" {
		t.Errorf("userName = %#v, want AROAEXAMPLE", got)
	}
}

func TestOutputsProjection(t *testing.T) {
	e := compileYAML(t, testPolicy)

	rec := consoleRecord("PutUserPolicy")
	rec["recipientAccountId"] = "222222222222"
	d := e.Evaluate(rec)
	if got := d.Outputs["account_id"]; got != "222222222222" {
		t.Errorf("account_id = %#v, want recipientAccountId", got)
	}

	rec = consoleRecord("PutUserPolicy")
	d = e.Evaluate(rec)
	if got := d.Outputs["account_id"]; got != "111111111111" {
		t.Errorf("account_id = %#v, want userIdentity.accountId", got)
	}
}

func TestEvaluateDoesNotMutateRecord(t *testing.T) {
	e := compileYAML(t, testPolicy)
	rec := consoleRecord("GetUser")
	e.Evaluate(rec)
	if _, ok := rec["preprocess"]; ok {
		t.Error("Evaluate leaked preprocess into the input record")
	}
}

func TestExplain(t *testing.T) {
	e := compileYAML(t, testPolicy)

	// A dropped record explains which rule and condition dropped it.
	d, lines := e.Explain(consoleRecord("GetUser"))
	if d.Emit {
		t.Fatal("want drop")
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"drop-reads", "matched", "preprocess.eventName"} {
		if !strings.Contains(joined, want) {
			t.Errorf("explanation missing %q:\n%s", want, joined)
		}
	}

	// Rules that did not apply say why they were skipped.
	if !strings.Contains(joined, "drop-billing-noise") {
		t.Errorf("explanation does not cover non-matching rules:\n%s", joined)
	}
	if !strings.Contains(joined, "eventSource") {
		t.Errorf("explanation does not name the failing condition key:\n%s", joined)
	}

	// An excluded rule says it was carved out.
	d, lines = e.Explain(consoleRecord("PutUserPolicy"))
	if !d.Emit {
		t.Fatal("want emit")
	}
	joined = strings.Join(lines, "\n")
	if !strings.Contains(joined, "exclude") {
		t.Errorf("explanation does not mention the exclude carve-out:\n%s", joined)
	}

	// A keep veto is called out.
	rec := consoleRecord("DeleteTrail")
	rec["userAgent"] = "aws-cli/2.13"
	_, lines = e.Explain(rec)
	joined = strings.Join(lines, "\n")
	if !strings.Contains(joined, "always-surface-security-writes") || !strings.Contains(joined, "veto") {
		t.Errorf("explanation does not mention keep veto:\n%s", joined)
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr string
	}{
		{
			name: "bad key template",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
filters:
  - name: f
    action: skip
    match:
      all:
        - { key: "{{ frobnicate(eventName) }}", operator: Equals, value: x }
`,
			wantErr: "frobnicate",
		},
		{
			name: "operator value shape mismatch",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
filters:
  - name: f
    action: skip
    match:
      all:
        - { key: "{{ eventName }}", operator: AnyIn, value: x }
`,
			wantErr: "AnyIn",
		},
		{
			name: "bad regex",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
filters:
  - name: f
    action: skip
    match:
      all:
        - { key: "{{ eventName }}", operator: Matches, value: ["("] }
`,
			wantErr: "Matches",
		},
		{
			name: "bad output template",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
filters:
  - name: f
    action: skip
    match:
      all:
        - { key: "{{ eventName }}", operator: Equals, value: x }
outputs:
  broken: "{{ eventName"
`,
			wantErr: "broken",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := policy.Parse([]byte(tt.src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if _, err := Compile(p); err == nil {
				t.Fatalf("Compile succeeded, want error containing %q", tt.wantErr)
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

// An unquoted YAML literal keeps its type, so a preprocess flag compares
// against a boolean condition value.
func TestPreprocessTypedLiteral(t *testing.T) {
	e := compileYAML(t, `
apiVersion: cca/v1
kind: FilterPolicy
preprocess:
  flag: true
  label: "true"
filters:
  - name: drop-flagged
    action: skip
    match:
      all:
        - { key: "{{ preprocess.flag }}", operator: Equals, value: true }
`)
	d := e.Evaluate(map[string]any{})
	if d.Emit || d.DroppedBy != "drop-flagged" {
		t.Errorf("flag: true should match Equals true; decision = %+v", d)
	}
	if d.Preprocess["label"] != "true" {
		t.Errorf(`quoted "true" must stay a string, got %#v`, d.Preprocess["label"])
	}
}
