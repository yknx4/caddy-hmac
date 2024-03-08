package hmac

import (
	"net/http"
	"testing"
)

func TestExtractHMACAndPath(t *testing.T) {
	testCases := []struct {
		name           string
		urlPath        string
		expectedHMAC   string
		expectedPath   string
		expectedQuery  string
		expectedError  string
	}{
		{
			name:           "Valid URL",
			urlPath:        "/someSignature/some/path?foo=bar",
			expectedHMAC:   "someSignature",
			expectedPath:   "/some/path",
			expectedQuery:  "foo=bar",
			expectedError:  "",
		},
		{
			name:           "Invalid URL format",
			urlPath:        "/invalid-path",
			expectedHMAC:   "",
			expectedPath:   "",
			expectedQuery:  "",
			expectedError:  "invalid URL format",
		},
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://example.com"+tc.urlPath, nil)
			if err != nil {
				t.Fatal(err)
			}

			hmacSignature, remainingPath, query, err := extractHMACAndPath(req)

			if err != nil && err.Error() != tc.expectedError {
				t.Fatalf("Expected error: %s, got: %s", tc.expectedError, err.Error())
			}

			if hmacSignature != tc.expectedHMAC {
				t.Errorf("Expected HMAC: %s, got: %s", tc.expectedHMAC, hmacSignature)
			}

			if remainingPath != tc.expectedPath {
				t.Errorf("Expected path: %s, got: %s", tc.expectedPath, remainingPath)
			}

			if query != tc.expectedQuery {
				t.Errorf("Expected query: %s, got: %s", tc.expectedQuery, query)
			}
		})
	}
}
