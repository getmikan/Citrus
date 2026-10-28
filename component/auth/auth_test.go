package auth

import "testing"

func TestInMemoryAuthenticatorVerify(t *testing.T) {
	au := NewAuthenticator([]AuthUser{{User: "alice", Pass: "secret"}, {User: "bob", Pass: ""}})
	for _, tt := range []struct {
		user, pass string
		want       bool
	}{
		{"alice", "secret", true},
		{"alice", "secreT", false},
		{"alice", "secret2", false},
		{"alice", "", false},
		{"bob", "", true},
		{"bob", "x", false},
		{"carol", "", false},
		{"carol", "secret", false},
	} {
		if got := au.Verify(tt.user, tt.pass); got != tt.want {
			t.Errorf("Verify(%q, %q) = %v, want %v", tt.user, tt.pass, got, tt.want)
		}
	}
}

func TestSameCredentials(t *testing.T) {
	a := NewAuthenticator([]AuthUser{{User: "alice", Pass: "secret"}, {User: "bob", Pass: "one"}})
	b := NewAuthenticator([]AuthUser{{User: "alice", Pass: "secret"}, {User: "bob", Pass: "two"}})
	if !SameCredentials(a, b, "alice") {
		t.Error("alice kept her password")
	}
	if SameCredentials(a, b, "bob") {
		t.Error("bob changed his password")
	}
	if SameCredentials(a, b, "carol") {
		t.Error("carol is in neither")
	}
}
