package main

import (
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		addr     string
		expected string
	}{
		{
			name:     "CF-Connecting-IP",
			headers:  map[string]string{"CF-Connecting-IP": "1.2.3.4"},
			addr:     "10.0.0.1:1234",
			expected: "1.2.3.4",
		},
		{
			name:     "X-Forwarded-For",
			headers:  map[string]string{"X-Forwarded-For": "5.6.7.8, 1.2.3.4"},
			addr:     "10.0.0.1:1234",
			expected: "5.6.7.8",
		},
		{
			name:     "RemoteAddr",
			headers:  map[string]string{},
			addr:     "9.9.9.9:1234",
			expected: "9.9.9.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			req.RemoteAddr = tt.addr

			got := getClientIP(req)
			if got != tt.expected {
				t.Errorf("getClientIP() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestWhitelistStore(t *testing.T) {
	// Use a temp file for testing
	tmpfile, err := os.CreateTemp("", "whitelist_store_test.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	storeFile = tmpfile.Name()
	store = &WhitelistStore{
		Entries: make(map[string]time.Time),
	}

	// Test Add
	expiry := time.Now().Add(1 * time.Hour)
	store.Add("1.1.1.1", expiry)

	if _, ok := store.Entries["1.1.1.1"]; !ok {
		t.Error("Add failed: IP not found in memory")
	}

	// Test Save/Load
	// Re-create store to test loading
	newStore := &WhitelistStore{
		Entries: make(map[string]time.Time),
	}
	if err := newStore.Load(); err != nil {
		t.Errorf("Load failed: %v", err)
	}

	if _, ok := newStore.Entries["1.1.1.1"]; !ok {
		t.Error("Load failed: IP not found in file")
	}

	// Test Remove
	store.Remove("1.1.1.1")
	if _, ok := store.Entries["1.1.1.1"]; ok {
		t.Error("Remove failed: IP still in memory")
	}

	// Verify persistence of removal
	finalStore := &WhitelistStore{
		Entries: make(map[string]time.Time),
	}
	finalStore.Load()
	if _, ok := finalStore.Entries["1.1.1.1"]; ok {
		t.Error("Remove persistence failed: IP still in file")
	}
}
