package route

import (
	"encoding/json"
	"strings"

	"github.com/metacubex/mihomo/config"
)

// redacted replaces a credential in a controller response.
const redacted = "******"

// redactGeneral removes the credentials of the built-in TUIC and ShadowSocks
// servers from GET /configs: they are independent of the controller secret
// and would outlive its rotation in the hands of whoever read them. The
// configuration file stays the place to read them.
func redactGeneral(g *config.General) {
	tuic := &g.TuicServer
	if len(tuic.Token) > 0 {
		tokens := make([]string, len(tuic.Token))
		for i := range tokens {
			tokens[i] = redacted
		}
		tuic.Token = tokens
	}
	if len(tuic.Users) > 0 {
		users := make(map[string]string, len(tuic.Users))
		for id := range tuic.Users {
			users[id] = redacted
		}
		tuic.Users = users
	}
	if tuic.PrivateKey != "" {
		tuic.PrivateKey = redacted
	}
	if tuic.EchKey != "" {
		tuic.EchKey = redacted
	}
	g.ShadowSocksConfig = redactJSONString(g.ShadowSocksConfig)
}

// redactJSONString redacts the credentials of a JSON document; a document
// that does not parse is redacted as a whole.
func redactJSONString(s string) string {
	if s == "" {
		return s
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return redacted
	}
	b, err := json.Marshal(redactValue(v, false))
	if err != nil {
		return redacted
	}
	return string(b)
}

func isSecretKey(key string) bool {
	switch strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(key)) {
	case "password", "passwd", "psk", "key", "token", "secret", "privatekey", "echkey", "uuid":
		return true
	}
	return false
}

func redactValue(v any, secret bool) any {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			v[k] = redactValue(e, secret || isSecretKey(k))
		}
		return v
	case []any:
		for i, e := range v {
			v[i] = redactValue(e, secret)
		}
		return v
	case string:
		if secret && v != "" {
			return redacted
		}
		return v
	default:
		return v
	}
}
