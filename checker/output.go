package checker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// Each result chunk is a separate container log line. One prefix is enough:
// a full-payload SHA-256 repeated in every line detects incomplete results
// without BEGIN/END markers or relying on termination messages.
const (
	ResultLogPrefix       = "CMS_LABS_CHECKER_RESULT_V1 "
	MaxPodLogsResultBytes = 1024 * 1024
	resultLogChunkSize    = 2048
)

// WriteResult emits one self-checking result via stdout-compatible log lines.
// Small chunks avoid container runtime log-line truncation; the checksum
// detects lost, reordered, duplicated, or corrupted chunks.
func WriteResult(w io.Writer, result *Result) error {
	if err := result.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal checker result: %w", err)
	}
	if len(payload) > MaxPodLogsResultBytes {
		return fmt.Errorf("checker result is %d bytes; Pod-log result limit is %d", len(payload), MaxPodLogsResultBytes)
	}

	encoded := base64.StdEncoding.EncodeToString(payload)
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	var out bytes.Buffer
	for offset := 0; offset < len(encoded); offset += resultLogChunkSize {
		end := offset + resultLogChunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		fmt.Fprintf(&out, "%s%s %s\n", ResultLogPrefix, digest, encoded[offset:end])
	}
	n, err := w.Write(out.Bytes())
	if err != nil {
		return fmt.Errorf("write checker result: %w", err)
	}
	if n != out.Len() {
		return fmt.Errorf("write checker result: %w", io.ErrShortWrite)
	}
	return nil
}
