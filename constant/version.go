package constant

var (
	Meta          = true
	Version       = "dev"
	BuildTime     = "unknown time"
	BuildSequence = "0"
	MihomoName    = "citrus"
)

// UserAgent is the default User-Agent of the core's own HTTP requests
// (global-ua): subscriptions, proxy and rule providers, geodata. "clash.meta/"
// comes first because panels detect the client by the start of the string;
// "citrus/" follows as a second product token (RFC 9110).
func UserAgent() string {
	return "clash.meta/" + Version + " citrus/" + Version
}
