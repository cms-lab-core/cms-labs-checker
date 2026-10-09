package checker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestWriteResultSupportsLargeJSON(t *testing.T) {
	message := strings.Repeat("Диагностика MAC learning: ", 500)
	result := NewResult(NewTask("capture", "large detail").AddLog(message).SetCompleted(true))

	var out bytes.Buffer
	if err := WriteResult(&out, result); err != nil {
		t.Fatalf("WriteResult(): %v", err)
	}
	var chunks []string
	var checksum string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if !strings.HasPrefix(line, ResultLogPrefix) {
			t.Fatalf("unexpected log record: %q", line)
		}
		rest := strings.TrimPrefix(line, ResultLogPrefix)
		hash, chunk, ok := strings.Cut(rest, " ")
		if !ok || len(chunk) == 0 || len(chunk) > resultLogChunkSize {
			t.Fatalf("invalid result record: %q", line)
		}
		if checksum != "" && checksum != hash {
			t.Fatal("checksum differs between chunks")
		}
		checksum = hash
		chunks = append(chunks, chunk)
	}
	if len(chunks) < 2 {
		t.Fatal("large result was not divided into log records")
	}
	payload, err := base64.StdEncoding.DecodeString(strings.Join(chunks, ""))
	if err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(payload) <= 4096 {
		t.Fatalf("expected a result exceeding termination message limit, got %d", len(payload))
	}
	digest := sha256.Sum256(payload)
	if checksum != hex.EncodeToString(digest[:]) {
		t.Fatal("result checksum does not match")
	}
	var got Result
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("result JSON invalid: %v", err)
	}
	if got.CurrentScore != 1 || got.Tasks[0].Logs[0].Message != message {
		t.Fatal("result lost scoring data or logs")
	}
}

func TestWriteResultRejectsOversizedJSON(t *testing.T) {
	var out bytes.Buffer
	result := NewResult(NewTask("huge", "").AddLog(strings.Repeat("x", MaxPodLogsResultBytes)))
	if err := WriteResult(&out, result); err == nil {
		t.Fatal("transport accepted JSON over 1 MiB")
	}
	if out.Len() != 0 {
		t.Fatal("oversized result must not emit partial records")
	}
}

func TestWriteResultAcceptsMaximumJSON(t *testing.T) {
	result := NewResult(NewTask("ok", "").SetCompleted(true))
	result.Report = "x"
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	result.Report = strings.Repeat("x", MaxPodLogsResultBytes-len(payload)+1)
	var out bytes.Buffer
	if err := WriteResult(&out, result); err != nil {
		t.Fatal(err)
	}
	if out.Len() > 2*1024*1024 {
		t.Fatal("maximum result exceeds Clabgate log retrieval budget")
	}
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) / 2, nil }

func TestWriteResultRejectsShortWrite(t *testing.T) {
	result := NewResult(NewTask("ok", "").SetCompleted(true))
	if err := WriteResult(shortWriter{}, result); err != io.ErrShortWrite &&
		(err == nil || !strings.Contains(err.Error(), io.ErrShortWrite.Error())) {
		t.Fatalf("expected short-write error, got %v", err)
	}
}
