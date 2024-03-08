package hmac

import (
	"fmt"
	"net/http"
	"strings"
)

func extractHMACAndPath(r *http.Request) (string, string, string, error) {
	// Get the path from the URL
	urlPath := r.URL.Path

	// Extract the HMAC signature and the remaining path
	parts := strings.SplitN(urlPath, "/", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid URL format")
	}

	hmacSignature := parts[1]
	remainingPath := "/" + parts[2]

	query := r.URL.Query().Encode()

	return hmacSignature, remainingPath, query, nil
}
