package secureargs

import "flag"

// SecretBearingFlag returns a secret-bearing flag explicitly set by argv.
// Environment-derived defaults are not visited by flag.FlagSet.Visit.
func SecretBearingFlag(fs *flag.FlagSet) string {
	secretFlag := ""
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "config", "age-secret-key", "secret":
			secretFlag = f.Name
		}
	})
	return secretFlag
}
