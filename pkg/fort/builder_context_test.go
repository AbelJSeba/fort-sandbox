package fort

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"
)

func TestCreateBuildContextAddsDockerfileCopySourceAliases(t *testing.T) {
	t.Helper()

	builder := &Builder{}
	req := &Request{
		SourceType:    SourceInline,
		SourceContent: "print('hello')",
	}
	synthesis := &SynthesisResult{
		BaseImage: "python:3.11-slim-bookworm",
		Dockerfile: `FROM python:3.11-slim-bookworm
WORKDIR /app
COPY --chown=appuser:appuser app.py /app/app.py
CMD ["python", "app.py"]`,
		RunCommand: []string{"python", "main.py"},
	}

	reader, err := builder.createBuildContext(req, synthesis)
	if err != nil {
		t.Fatalf("createBuildContext returned error: %v", err)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read build context: %v", err)
	}

	files := tarEntryNames(data)
	if _, ok := files["main.py"]; !ok {
		t.Fatalf("expected main.py in build context, got files: %#v", files)
	}
	if _, ok := files["app.py"]; !ok {
		t.Fatalf("expected app.py alias in build context, got files: %#v", files)
	}
}

func TestExtractDockerfileCopySourcesSkipsUnsafePaths(t *testing.T) {
	t.Helper()

	dockerfile := `
FROM python:3.11-slim
COPY --chown=app:app app.py /app/app.py
COPY ./module/helper.py /app/module/helper.py
COPY ../secret.txt /app/secret.txt
COPY *.py /app/
`
	sources := extractDockerfileCopySources(dockerfile)
	expected := map[string]bool{
		"app.py":           true,
		"module/helper.py": true,
	}

	got := map[string]bool{}
	for _, s := range sources {
		if isSafeContextPath(s) {
			got[s] = true
		}
	}

	for want := range expected {
		if !got[want] {
			t.Fatalf("expected source %q, got %v", want, got)
		}
	}
	if got["../secret.txt"] {
		t.Fatalf("unsafe source path should not be included: %v", got)
	}
}

func tarEntryNames(data []byte) map[string]struct{} {
	out := make(map[string]struct{})
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if hdr != nil {
			out[hdr.Name] = struct{}{}
		}
	}
	return out
}
