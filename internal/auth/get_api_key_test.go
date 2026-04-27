package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		expectedKey string
		expectErr   bool
	}{
		{
			name:        "valid API key",
			header:      "ApiKey abc123",
			expectedKey: "abc123",
			expectErr:   false,
		},
		{
			name:      "missing authorization header",
			header:    "",
			expectErr: true,
		},
		{
			name:      "wrong scheme",
			header:    "Bearer abc123",
			expectErr: true,
		},
		{
			name:      "scheme only, no key value",
			header:    "ApiKey",
			expectErr: true,
		},
		{
			name:      "lowercase scheme rejected",
			header:    "apikey abc123",
			expectErr: true,
		},
		{
			name:        "extra parts returns second token",
			header:      "ApiKey abc123 extra",
			expectedKey: "abc123",
			expectErr:   false,
		},
		{
			name:        "extra spaces produce empty second token",
			header:      "ApiKey   abc123",
			expectedKey: "",
			expectErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}

			key, err := GetAPIKey(headers)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}
