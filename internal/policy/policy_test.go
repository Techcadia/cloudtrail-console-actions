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
		{
			// when: blocks are decoded from a node, outside KnownFields
			// mode, so unknown keys must be rejected explicitly.
			name: "unknown key in when block",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
preprocess:
  x:
    - when:
        any:
          - { key: "{{ a }}", operator: Equals, value: 1 }
        alll:
          - { key: "{{ b }}", operator: Equals, value: 2 }
      value: hit
filters:
  - name: f
    action: skip
    match:
      all:
        - { key: "{{ eventName }}", operator: Equals, value: x }
`,
			wantErr: `unknown key "alll"`,
		},
		{
			name: "unknown key in condition",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
filters:
  - name: f
    action: skip
    match:
      all:
        - { key: "{{ eventName }}", operator: Equals, value: x, negate: true }
`,
			wantErr: `unknown key "negate"`,
		},
		{
			name: "duplicate output field",
			src: minimalPolicy + `
outputs:
  user_name: "{{ a }}"
  user_name: "{{ b }}"
`,
			wantErr: `duplicate field "user_name"`,
		},
		{
			// 012345670123 would be read as octal 1402433619.
			name: "unquoted zero-padded account id",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
filters:
  - name: f
    action: skip
    match:
      all:
        - { key: "{{ recipientAccountId }}", operator: AnyIn, value: [111111111111, 012345670123] }
`,
			wantErr: "leading zero",
		},
		{
			name: "unquoted zero-padded number that is not octal",
			src: `
apiVersion: cca/v1
kind: FilterPolicy
filters:
  - name: f
    action: skip
    match:
      all:
        - { key: "{{ recipientAccountId }}", operator: Equals, value: 012345678901 }
`,
			wantErr: "leading zero",
		},
		{
			name: "null field value",
			src: minimalPolicy + `
outputs:
  user_name: ~
`,
			wantErr: "value is required",
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

func TestParseQuotedZeroPaddedAccepted(t *testing.T) {
	p, err := Parse([]byte(`
apiVersion: cca/v1
kind: FilterPolicy
filters:
  - name: f
    action: skip
    match:
      all:
        - { key: "{{ recipientAccountId }}", operator: Equals, value: "012345670123" }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := p.Filters[0].Match.All[0].Value; got != "012345670123" {
		t.Errorf("value = %#v, want the string", got)
	}
}

func TestParseFieldLiteralTypes(t *testing.T) {
	p, err := Parse([]byte(minimalPolicy + `
preprocess:
  flag: true
  quoted: "true"
  count: 3
  name: "{{ eventName }}"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Fields keep document order: later preprocess fields may read earlier ones.
	var names []string
	for _, f := range p.Preprocess {
		names = append(names, f.Name)
	}
	if got := strings.Join(names, ","); got != "flag,quoted,count,name" {
		t.Errorf("preprocess order = %s", got)
	}

	want := map[string]any{"flag": true, "quoted": nil, "count": 3, "name": nil}
	for _, f := range p.Preprocess {
		if got := f.Rules[0].Literal; got != want[f.Name] {
			t.Errorf("%s: Literal = %#v, want %#v", f.Name, got, want[f.Name])
		}
	}
}
