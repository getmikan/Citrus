package secureargs

import (
	"flag"
	"testing"
)

func parsedFlags(t *testing.T, args ...string) *flag.FlagSet {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("config", "", "")
	fs.String("age-secret-key", "", "")
	fs.String("secret", "", "")
	fs.String("secret-file", "", "")
	fs.String("age-secret-key-file", "", "")
	fs.String("f", "", "")
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return fs
}

func TestSecretBearingFlag(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-secret", "value"}, "secret"},
		{[]string{"-age-secret-key=value"}, "age-secret-key"},
		{[]string{"-config", "c2VjcmV0"}, "config"},
		{[]string{"-secret-file", "secret.txt"}, ""},
		{[]string{"-age-secret-key-file", "key.txt"}, ""},
		{[]string{"-f", "config.yaml"}, ""},
		{[]string{"-f", "-"}, ""},
	} {
		if got := SecretBearingFlag(parsedFlags(t, tc.args...)); got != tc.want {
			t.Errorf("%v: got %q, want %q", tc.args, got, tc.want)
		}
	}
}
