package fort

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLLMDumpWritesJSONFileWhenConfigured(t *testing.T) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output_text":"{\"ok\":true}"}`)
	}))
	defer server.Close()

	dumpDir := filepath.Join(t.TempDir(), "llm-dumps")
	client := NewOpenAILLMClientWithBaseURL("test-key", "gpt-5.2-codex", server.URL+"/v1")
	client.SetDebugOptions(false, dumpDir)

	if _, err := client.generateText(context.Background(), "system", "user", false); err != nil {
		t.Fatalf("generateText returned error: %v", err)
	}

	entries, err := os.ReadDir(dumpDir)
	if err != nil {
		t.Fatalf("failed to read dump dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("expected at least one dump file, got none")
	}

	raw, err := os.ReadFile(filepath.Join(dumpDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("failed to read dump file: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("dump file is not valid JSON: %v", err)
	}

	kind, ok := parsed["kind"].(string)
	if !ok || kind == "" {
		t.Fatalf("expected non-empty kind in dump file, got: %#v", parsed["kind"])
	}
}
