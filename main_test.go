package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSecurityMiddleware(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test"))
	})

	handler := securityMiddleware(testHandler)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
	}

	for header, expected := range headers {
		if got := resp.Header.Get(header); got != expected {
			t.Errorf("Header %s = %q, want %q", header, got, expected)
		}
	}
}

func TestLogMiddleware(t *testing.T) {
	var logOutput strings.Builder
	logger := log.New(&logOutput, "", 0)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test"))
	})

	handler := logMiddleware(logger)(testHandler)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	_, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}

	logStr := logOutput.String()
	if !strings.Contains(logStr, "GET") {
		t.Error("Log output doesn't contain HTTP method")
	}
	if !strings.Contains(logStr, "/") {
		t.Error("Log output doesn't contain path")
	}
}

func TestGetOutboundIP(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	GetOutboundIP("invalid_interface", "8000", true)

	w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = oldStdout

	if !strings.Contains(string(out), "Invalid interface name") {
		t.Error("Expected error message for invalid interface")
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("GetOutboundIP panicked with valid interface: %v", r)
			}
		}()

		_, w, _ := os.Pipe()
		os.Stdout = w
		defer func() {
			w.Close()
			os.Stdout = oldStdout
		}()

		GetOutboundIP(*iFlag, "8000", true)
	}()
}

func TestMainServerSetup(t *testing.T) {
	*portFlag = "0"
	*dirFlag = "."

	done := make(chan bool)

	go func() {
		server := &http.Server{
			Addr:    ":" + *portFlag,
			Handler: http.FileServer(http.Dir(*dirFlag)),
		}

		go func() {
			time.Sleep(1 * time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.Shutdown(ctx)
			done <- true
		}()

		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			t.Errorf("Server error: %v", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Server didn't shut down in time")
	}
}
