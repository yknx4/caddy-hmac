package hmac

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m HMAC) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.Body == nil {
		// nothing to do
		return next.ServeHTTP(w, r)
	}
	_, remainingPath, query, err := extractHMACAndPath(r)
	if err != nil {
		return err
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	toSign := remainingPath + query

	secret := repl.ReplaceAll(m.Secret, "")
	signature := generateSignature(m.hasher, secret, []byte(toSign))
	if err != nil {
		return err
	}

	repl.Set(m.replacerKey(), signature)
	return next.ServeHTTP(w, r)
}

