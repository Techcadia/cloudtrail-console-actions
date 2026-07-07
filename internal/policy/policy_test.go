package policy

import (
	"strings"
	"testing"
)

const minimalPolicy = `
apiVersion: cca/v1
kind: FilterPolicy
filters:
  - name: drop-aws-internal
    action: skip
    match:
      all:
        - { key: "{{ userIdentity.invokedBy || '' }}", operator: Equals, value: "AWS Internal" }
`

func TestParseMinimal(t *testing.T) {
	p, err := Parse([]byte(minimalPolicy))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if p.APIVersion != "cca/v1" || p.Kind != "FilterPolicy" {
		t.Errorf("header = %q/%q", p.APIVersion, p.Kind)
	}
	if len(p.Filters) != 1 {
		t.Fatalf("filters = %d, want 1", len(p.Filters))
	}
	f := p.Filters[0]
	if f.Name != "drop-aws-internal" || f.Action != "skip" {
		t.Errorf("rule = %+v", f)
	}
	if len(f.Match.All) != 1 || f.Match.All[0].Operator != "Equals" {
		t.Errorf("match = %+v", f.Match)
	}
}

func TestParseFullShape(t *testing.T) {
	src := `
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
    - value: "{{ userIdentity.principalId }}"
keep:
  - name: always-surface-security-writes
    match:
      any:
        - { key: "{{ preprocess.eventName }}", operator: AnyIn, value: [DeleteTrail, StopLogging] }
filters:
  - name: drop-noise
    action: skip
    match:
      all:
        - { key: "{{ userAgent || '' }}", operator: NotEquals, value: "" }
    exclude:
      any:
        - { key: "{{ userAgent }}", operator: AnyIn, value: ["Mozilla/*"] }
outputs:
  event_source: "{{ eventSource }}"
  account_id:
    - when:
        all:
          - { key: "{{ recipientAccountId || '' }}", operator: NotEquals, value: "" }
      value: "{{ recipientAccountId }}"
    - value: "{{ userIdentity.accountId || '' }}"
`
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// preprocess keeps document order and desugars.
	if got := len(p.Preprocess); got != 2 {
		t.Fatalf("preprocess fields = %d, want 2", got)
	}
	if p.Preprocess[0].Name != "eventName" || p.Preprocess[1].Name != "userName" {
		t.Errorf("preprocess order = %q, %q", p.Preprocess[0].Name, p.Preprocess[1].Name)
	}
	if got := len(p.Preprocess[0].Rules); got != 2 {
		t.Errorf("eventName rules = %d, want 2", got)
	}
	if p.Preprocess[0].Rules[0].When == nil || p.Preprocess[0].Rules[1].When != nil {
		t.Errorf("eventName rule guards wrong: %+v", p.Preprocess[0].Rules)
	}

	// bare-string output desugars to one unconditional rule.
	var eventSource, accountID *Field
	for i := range p.Outputs {
		switch p.Outputs[i].Name {
		case "event_source":
			eventSource = &p.Outputs[i]
		case "account_id":
			accountID = &p.Outputs[i]
		}
	}
	if eventSource == nil || accountID == nil {
		t.Fatalf("outputs missing: %+v", p.Outputs)
	}
	if len(eventSource.Rules) != 1 || eventSource.Rules[0].When != nil ||
		eventSource.Rules[0].Value != "{{ eventSource }}" {
		t.Errorf("event_source = %+v", eventSource.Rules)
	}
	if len(accountID.Rules) != 2 {
		t.Errorf("account_id rules = %d, want 2", len(accountID.Rules))
	}

	if len(p.Keep) != 1 || p.Keep[0].Name != "always-surface-security-writes" {
		t.Errorf("keep = %+v", p.Keep)
	}
	if p.Filters[0].Exclude == nil || len(p.Filters[0].Exclude.Any) != 1 {
		t.Errorf("exclude = %+v", p.Filters[0].Exclude)
	}

	// AnyIn list values arrive as []any.
	if _, ok := p.Keep[0].Match.Any[0].Value.([]any); !ok {
		t.Errorf("list value type = %T, want []any", p.Keep[0].Match.Any[0].Value)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name:    "wrong apiVersion",
			mutate:  func(s string) string { return strings.Replace(s, "cca/v1", "cca/v2", 1) },
			wantErr: "apiVersion",
		},
		{
			name:    "wrong kind",
			mutate:  func(s string) string { return strings.Replace(s, "FilterPolicy", "NetworkPolicy", 1) },
			wantErr: "kind",
		},
		{
			name:    "action other than skip",
			mutate:  func(s string) string { return strings.Replace(s, "action: skip", "action: keep", 1) },
			wantErr: "action",
		},
		{
			name:    "unknown field rejected",
			mutate:  func(s string) string { return s + "\nbogus: true\n" },
			wantErr: "bogus",
		},
		{
			name: "missing rule name",
			mutate: func(s string) string {
				return strings.Replace(s, "name: drop-aws-internal", "name: \"\"", 1)
			},
			wantErr: "name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.mutate(minimalPolicy)))
			if err == nil {
				t.Fatalf("Parse succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseStructuralErrors(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr string
	}{
		{
			name: "no filters",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
filters: []
`,
			wantErr: "filters",
		},
		{
			name: "duplicate rule names",
			src: minimalPolicy + `
  - name: drop-aws-internal
    action: skip
    match:
      all:
        - { key: "{{ eventSource }}", operator: Equals, value: codecommit.amazonaws.com }
`,
			wantErr: "duplicate",
		},
		{
			name: "keep rule with exclude",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
keep:
  - name: veto
    match:
      all:
        - { key: "{{ eventName }}", operator: Equals, value: DeleteTrail }
    exclude:
      all:
        - { key: "{{ eventName }}", operator: Equals, value: DeleteTrail }
filters:
  - name: f
    action: skip
    match:
      all:
        - { key: "{{ eventName }}", operator: Equals, value: x }
`,
			wantErr: "exclude",
		},
		{
			name: "match without any or all",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
filters:
  - name: f
    action: skip
    match: {}
`,
			wantErr: "match",
		},
		{
			name: "condition missing operator",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
filters:
  - name: f
    action: skip
    match:
      all:
        - { key: "{{ eventName }}", value: x }
`,
			wantErr: "operator",
		},
		{
			name: "preprocess name not an identifier",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
preprocess:
  "bad name": "{{ eventName }}"
filters:
  - name: f
    action: skip
    match:
      all:
        - { key: "{{ eventName }}", operator: Equals, value: x }
`,
			wantErr: "identifier",
		},
		{
			name: "output rule missing value",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
preprocess:
  userName:
    - when:
        all:
          - { key: "{{ eventName }}", operator: Equals, value: x }
filters:
  - name: f
    action: skip
    match:
      all:
        - { key: "{{ eventName }}", operator: Equals, value: x }
`,
			wantErr: "value",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.src))
			if err == nil {
				t.Fatalf("Parse succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}
