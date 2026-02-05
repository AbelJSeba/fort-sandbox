package fort

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerateTextUsesResponsesForCodexModels(t *testing.T) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output_text":"{\"ok\":true}"}`)
	}))
	defer server.Close()

	client := NewOpenAILLMClientWithBaseURL("test-key", "gpt-5.2-codex", server.URL+"/v1")
	out, err := client.generateText(context.Background(), "system", "user", false)
	if err != nil {
		t.Fatalf("generateText returned error: %v", err)
	}
	if !strings.Contains(out, `"ok":true`) {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestGenerateTextUsesChatForNonCodexChatModels(t *testing.T) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"id":"chatcmpl-test",
			"object":"chat.completion",
			"created":1700000000,
			"model":"gpt-4o-mini",
			"choices":[
				{
					"index":0,
					"message":{"role":"assistant","content":"{\"ok\":true}"},
					"finish_reason":"stop"
				}
			]
		}`)
	}))
	defer server.Close()

	client := NewOpenAILLMClientWithBaseURL("test-key", "gpt-4o-mini", server.URL+"/v1")
	out, err := client.generateText(context.Background(), "system", "user", false)
	if err != nil {
		t.Fatalf("generateText returned error: %v", err)
	}
	if !strings.Contains(out, `"ok":true`) {
		t.Fatalf("unexpected output: %s", out)
	}
}
