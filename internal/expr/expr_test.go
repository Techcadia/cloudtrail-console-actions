package expr

import (
	"testing"
)

// record returns a scope shaped like a CloudTrail record, matching the
// structures the policy templates address.
func record() map[string]any {
	return map[string]any{
		"eventSource": "billingconsole.amazonaws.com",
		"eventName":   "AWSPaymentPortalService.GetAccountPreferences",
		"readOnly":    true,
		"userIdentity": map[string]any{
			"principalId": "AIDA123456789EXAMPLE:john.doe@example.com",
			"userName":    "john.doe",
			"invokedBy":   "AWS Internal",
		},
		"requestParameters": map[string]any{
			"sessionId": "john.doe-0e95d1a239405ca7b",
		},
		"preprocess": map[string]any{
			"eventName": "GetAccountPreferences",
		},
	}
}

func TestCompileAndEval(t *testing.T) {
	tests := []struct {
		name     string
		template string
		want     any
	}{
		{
			name:     "literal string passes through untouched",
			template: "billingconsole.amazonaws.com",
			want:     "billingconsole.amazonaws.com",
		},
		{
			name:     "top-level field",
			template: "{{ eventSource }}",
			want:     "billingconsole.amazonaws.com",
		},
		{
			name:     "nested field",
			template: "{{ userIdentity.userName }}",
			want:     "john.doe",
		},
		{
			name:     "boolean field keeps its type",
			template: "{{ readOnly }}",
			want:     true,
		},
		{
			name:     "missing top-level field is nil",
			template: "{{ errorCode }}",
			want:     nil,
		},
		{
			name:     "missing nested field is nil",
			template: "{{ userIdentity.accountId }}",
			want:     nil,
		},
		{
			name:     "path through a non-map is nil",
			template: "{{ eventSource.bucket }}",
			want:     nil,
		},
		{
			name:     "fallback replaces missing value",
			template: "{{ errorCode || '' }}",
			want:     "",
		},
		{
			name:     "fallback replaces empty string",
			template: "{{ emptyString || 'fallback' }}",
			want:     "fallback",
		},
		{
			name:     "fallback not taken when value present",
			template: "{{ userIdentity.invokedBy || '' }}",
			want:     "AWS Internal",
		},
		{
			name:     "preprocess scope lookup",
			template: "{{ preprocess.eventName }}",
			want:     "GetAccountPreferences",
		},
		{
			name:     "trimPrefix removes prefix",
			template: "{{ trimPrefix(eventName, 'AWSPaymentPortalService.') }}",
			want:     "GetAccountPreferences",
		},
		{
			name:     "trimPrefix leaves non-matching value alone",
			template: "{{ trimPrefix(eventSource, 'AWSPaymentPortalService.') }}",
			want:     "billingconsole.amazonaws.com",
		},
		{
			name:     "trimPrefix of missing value is nil",
			template: "{{ trimPrefix(errorCode, 'x') }}",
			want:     nil,
		},
		{
			name:     "contains true",
			template: "{{ contains(userIdentity.principalId, ':') }}",
			want:     true,
		},
		{
			name:     "contains false",
			template: "{{ contains(userIdentity.userName, ':') }}",
			want:     false,
		},
		{
			name:     "contains on missing value is nil",
			template: "{{ contains(errorCode, ':') }}",
			want:     nil,
		},
		{
			name:     "split and index",
			template: "{{ split(userIdentity.principalId, ':')[1] }}",
			want:     "john.doe@example.com",
		},
		{
			name:     "split index out of range is nil",
			template: "{{ split(userIdentity.userName, ':')[1] }}",
			want:     nil,
		},
		{
			name:     "quoted literal expression",
			template: "{{ 'hello' }}",
			want:     "hello",
		},
		{
			name:     "boolean literal expression",
			template: "{{ true }}",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := Compile(tt.template)
			if err != nil {
				t.Fatalf("Compile(%q) error: %v", tt.template, err)
			}
			got := e.Eval(record())
			if got != tt.want {
				t.Errorf("Eval(%q) = %#v, want %#v", tt.template, got, tt.want)
			}
		})
	}
}

func TestEvalEmptyStringInScope(t *testing.T) {
	e, err := Compile("{{ emptyString || 'fallback' }}")
	if err != nil {
		t.Fatal(err)
	}
	got := e.Eval(map[string]any{"emptyString": ""})
	if got != "fallback" {
		t.Errorf("got %#v, want %q", got, "fallback")
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name     string
		template string
	}{
		{"mixed text and expression", "prefix {{ eventSource }}"},
		{"unclosed braces", "{{ eventSource"},
		{"empty expression", "{{ }}"},
		{"unknown function", "{{ frobnicate(eventName) }}"},
		{"unterminated string literal", "{{ trimPrefix(eventName, 'x) }}"},
		{"dangling or", "{{ eventSource || }}"},
		{"missing close paren", "{{ contains(eventName, ':' }}"},
		{"non-integer index", "{{ split(eventName, ':')[x] }}"},
		{"trailing garbage", "{{ eventSource eventName }}"},
		{"wrong arity", "{{ contains(eventName) }}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Compile(tt.template); err == nil {
				t.Errorf("Compile(%q) succeeded, want error", tt.template)
			}
		})
	}
}

func TestString(t *testing.T) {
	src := "{{ split(userIdentity.principalId, ':')[1] }}"
	e, err := Compile(src)
	if err != nil {
		t.Fatal(err)
	}
	if e.String() != src {
		t.Errorf("String() = %q, want %q", e.String(), src)
	}
}

func TestEvalNilScopeValues(t *testing.T) {
	// A scope value that is explicitly nil behaves like a missing key.
	e, err := Compile("{{ userIdentity.invokedBy || '' }}")
	if err != nil {
		t.Fatal(err)
	}
	got := e.Eval(map[string]any{"userIdentity": map[string]any{"invokedBy": nil}})
	if got != "" {
		t.Errorf("got %#v, want empty string", got)
	}
}
