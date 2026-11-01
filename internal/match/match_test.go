package match

import "testing"

func mustCompile(t *testing.T, op Operator, value any) *Comparison {
	t.Helper()
	c, err := Compile(op, value)
	if err != nil {
		t.Fatalf("Compile(%s, %#v) error: %v", op, value, err)
	}
	return c
}

func TestEquals(t *testing.T) {
	tests := []struct {
		name  string
		op    Operator
		value any
		key   any
		want  bool
	}{
		{"string equal", Equals, "AWS Internal", "AWS Internal", true},
		{"string not equal", Equals, "AWS Internal", "aws internal", false},
		{"no wildcard expansion in Equals", Equals, "Get*", "GetObject", false},
		{"bool equal", Equals, true, true, true},
		{"bool not equal", Equals, true, false, false},
		{"bool vs string is not equal", Equals, true, "true", false},
		{"nil key never equals a value", Equals, "x", nil, false},
		{"nil key does not equal empty string", Equals, "", nil, false},
		{"int value vs json float64 key", Equals, 32, float64(32), true},
		{"number vs numeric string", Equals, 32, "32", true},
		{"strings compare exactly, not numerically", Equals, "1", "1.0", false},
		{"zero-padded strings stay distinct", Equals, "012345678901", "12345678901", false},
		{"identical numeric strings", Equals, "012345678901", "012345678901", true},
		{"NotEquals inverts", NotEquals, "AWS Internal", "console", true},
		{"NotEquals equal value", NotEquals, "AWS Internal", "AWS Internal", false},
		{"NotEquals nil key", NotEquals, "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mustCompile(t, tt.op, tt.value).Eval(tt.key); got != tt.want {
				t.Errorf("%s(%#v).Eval(%#v) = %v, want %v", tt.op, tt.value, tt.key, got, tt.want)
			}
		})
	}
}

func TestSetOperators(t *testing.T) {
	consoleAgents := []any{"console.amazonaws.com", "signin.amazonaws.com", "Coral/Jakarta"}

	tests := []struct {
		name  string
		op    Operator
		value any
		key   any
		want  bool
	}{
		{"AnyIn exact member", AnyIn, consoleAgents, "Coral/Jakarta", true},
		{"AnyIn non-member", AnyIn, consoleAgents, "aws-cli/2.0", false},
		{"AnyIn zero-padded member stays exact", AnyIn, []any{"0123"}, "123", false},
		{"AnyIn prefix wildcard", AnyIn, []any{"Check*", "CreateCaseDraft"}, "CheckServiceHealth", true},
		{"AnyIn suffix wildcard", AnyIn, []any{"*VirtualMFADevice"}, "CreateVirtualMFADevice", true},
		{"AnyIn contains wildcard", AnyIn, []any{"*_Get*"}, "Payments_GetPreferences", true},
		{"AnyIn contains wildcard no match", AnyIn, []any{"*_Get*"}, "GetPreferences", false},
		{"AnyIn question mark", AnyIn, []any{"Get?"}, "GetX", true},
		{"AnyIn question mark wrong length", AnyIn, []any{"Get?"}, "GetXY", false},
		{"AnyIn wildcard is case sensitive", AnyIn, []any{"Get*"}, "getObject", false},
		{"AnyIn nil key", AnyIn, consoleAgents, nil, false},
		{"AnyIn array key any member", AnyIn, []any{"a", "b"}, []any{"z", "b"}, true},
		{"AnyIn array key no member", AnyIn, []any{"a", "b"}, []any{"z", "y"}, false},

		{"AllIn all members", AllIn, []any{"a*", "b"}, []any{"aa", "b"}, true},
		{"AllIn one missing", AllIn, []any{"a*", "b"}, []any{"aa", "c"}, false},
		{"AllIn nil key", AllIn, []any{"a"}, nil, false},

		{"AnyNotIn one outside", AnyNotIn, []any{"a", "b"}, []any{"a", "z"}, true},
		{"AnyNotIn all inside", AnyNotIn, []any{"a", "b"}, []any{"a", "b"}, false},
		{"AnyNotIn nil key", AnyNotIn, []any{"a"}, nil, true},

		{"AllNotIn none inside", AllNotIn, []any{"a", "b"}, "z", true},
		{"AllNotIn member inside", AllNotIn, []any{"a", "b"}, "a", false},
		{"AllNotIn nil key", AllNotIn, []any{"a"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mustCompile(t, tt.op, tt.value).Eval(tt.key); got != tt.want {
				t.Errorf("%s(%#v).Eval(%#v) = %v, want %v", tt.op, tt.value, tt.key, got, tt.want)
			}
		})
	}
}

func TestMatches(t *testing.T) {
	tests := []struct {
		name  string
		op    Operator
		value any
		key   any
		want  bool
	}{
		{"anchored prefix", Matches, []any{"^[Gg]et"}, "getObject", true},
		{"anchored prefix title", Matches, []any{"^[Gg]et"}, "GetObject", true},
		{"anchored prefix upper rest not matched", Matches, []any{"^[Gg]et"}, "GETOBJECT", false},
		{"any of several patterns", Matches, []any{"^[Gg]et", "^[Ll]ist", "^[Vv]iew"}, "ListBuckets", true},
		{"none of several patterns", Matches, []any{"^[Gg]et", "^[Ll]ist"}, "PutObject", false},
		{"case insensitive suffix", Matches, []any{"(?i)get$"}, "AdminSomethingGET", true},
		{"unanchored substring", Matches, []any{"AWSLogs/"}, "prefix/AWSLogs/123/elb.log", true},
		{"aws internal flavors", Matches, []any{`(?i)aws[\s-]internal`}, "aws-sdk-ruby aws-internal (v3)", true},
		{"nil key", Matches, []any{".*"}, nil, false},
		{"non-string key", Matches, []any{".*"}, float64(5), false},
		{"NotMatches inverts", NotMatches, []any{"^Get"}, "PutObject", true},
		{"NotMatches match", NotMatches, []any{"^Get"}, "GetObject", false},
		{"NotMatches nil key", NotMatches, []any{".*"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mustCompile(t, tt.op, tt.value).Eval(tt.key); got != tt.want {
				t.Errorf("%s(%#v).Eval(%#v) = %v, want %v", tt.op, tt.value, tt.key, got, tt.want)
			}
		})
	}
}

func TestNumericComparisons(t *testing.T) {
	tests := []struct {
		name  string
		op    Operator
		value any
		key   any
		want  bool
	}{
		{"gt true", GreaterThan, 5, float64(6), true},
		{"gt false when equal", GreaterThan, 5, float64(5), false},
		{"gte true when equal", GreaterThanOrEquals, 5, float64(5), true},
		{"lt true", LessThan, 5, float64(4), true},
		{"lte false", LessThanOrEquals, 5, float64(6), false},
		{"numeric string key coerces", GreaterThan, 5, "6", true},
		{"non-numeric key is false", GreaterThan, 5, "six", false},
		{"nil key is false", GreaterThan, 5, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mustCompile(t, tt.op, tt.value).Eval(tt.key); got != tt.want {
				t.Errorf("%s(%#v).Eval(%#v) = %v, want %v", tt.op, tt.value, tt.key, got, tt.want)
			}
		})
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name  string
		op    Operator
		value any
	}{
		{"unknown operator", Operator("Fuzzy"), "x"},
		{"Equals rejects list", Equals, []any{"a"}},
		{"AnyIn rejects scalar", AnyIn, "a"},
		{"AnyIn rejects empty list", AnyIn, []any{}},
		{"Matches rejects scalar", Matches, "^Get"},
		{"Matches rejects invalid regex", Matches, []any{"("}},
		{"Matches rejects non-string pattern", Matches, []any{5}},
		{"GreaterThan rejects non-numeric", GreaterThan, "abc"},
		{"nil value", Equals, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Compile(tt.op, tt.value); err == nil {
				t.Errorf("Compile(%s, %#v) succeeded, want error", tt.op, tt.value)
			}
		})
	}
}

func TestWildcardMatch(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"Get*", "Get", true},
		{"Get*", "GetObject", true},
		{"Get*", "AdminGet", false},
		{"*Session", "StartSession", true},
		{"*Session", "SessionStart", false},
		{"*_Get*", "Foo_GetBar", true},
		{"*", "", true},
		{"*", "anything", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXcYYb", false},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		{"?", "", false},
		{"?", "x", true},
		{"S3Console/*", "S3Console/0.4", true},
		{"[S3Console*", "[S3Console 0.4]", true},
	}
	for _, tt := range tests {
		if got := wildcardMatch(tt.pattern, tt.s); got != tt.want {
			t.Errorf("wildcardMatch(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}
