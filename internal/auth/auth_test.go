package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestAuth(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			expectedKey:   "abc123",
			expectedError: nil,
		},
		{
			name:          "Missing Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - Wrong Format",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - Missing Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if (err == nil && tt.expectedError != nil) ||
				(err != nil && tt.expectedError == nil) ||
				(err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error()) {
				t.Errorf("Expected error: %v, got: %v", tt.expectedError, err)
			}

			if key != tt.expectedKey {
				t.Errorf("Expected key: %v, got: %v", tt.expectedKey, key)
			}
		})
	}
}
