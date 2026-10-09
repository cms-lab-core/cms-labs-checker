package cn004

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cms-lab-core/cms-labs-checker/checker"
)

func TestTerminationPayloadFitsForCompleteAndFailedChecks(t *testing.T) {
	tests := []struct {
		name     string
		runner   commandRunner
		expected float64
	}{
		{name: "all checks pass", runner: healthyRunner, expected: 12},
		{name: "eth2 detached", runner: detachedEth2Runner, expected: 9},
		{name: "every SSH operation fails with long errors", runner: failingRunner, expected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject := &Checker{run: tt.runner}
			result, err := subject.Check(context.Background(), checker.Environment{
				SessionNamespace: "lab-" + strings.Repeat("n", 59),
			})
			if err != nil {
				t.Fatalf("Check(): %v", err)
			}
			if len(result.Tasks) != 12 {
				t.Fatalf("got %d tasks; want 12", len(result.Tasks))
			}
			if result.MaxScore != 12 || result.CurrentScore != tt.expected {
				t.Fatalf("score %g/%g; want %g/12", result.CurrentScore, result.MaxScore, tt.expected)
			}
			payload, err := checker.MarshalResult(result)
			if err != nil {
				t.Fatalf("MarshalResult(): %v", err)
			}
			if len(payload) > checker.MaxTerminationMessageBytes {
				t.Fatalf("payload %d exceeds %d", len(payload), checker.MaxTerminationMessageBytes)
			}
		})
	}
}

func TestBriefBoundsUTF8Bytes(t *testing.T) {
	value := strings.Repeat("ошибка соединения ", 200)
	short := brief(value)
	if len(short) > maxDiagnosticBytes || !utf8.ValidString(short) {
		t.Fatalf("brief text has %d bytes or invalid UTF-8", len(short))
	}
	if !strings.HasSuffix(short, "…") {
		t.Fatal("truncated message has no ellipsis")
	}
}

func healthyRunner(_ context.Context, host, command string) (string, error) {
	if strings.HasPrefix(command, "ip -o link show dev ") {
		return "3: eth2: <BROADCAST,UP> mtu 1500 master br0 state UP", nil
	}
	if command == "ip -4 -o addr show dev eth1" {
		ips := map[string]string{"pc1": "10.4.0.10/24", "pc2": "10.4.0.20/24", "pc3": "10.4.0.30/24"}
		return "3: eth1 inet " + ips[host] + " brd 10.4.0.255", nil
	}
	if command == "cat /sys/class/net/eth1/address" {
		macs := map[string]string{
			"pc1": "02:00:00:00:04:01", "pc2": "02:00:00:00:04:02", "pc3": "02:00:00:00:04:03",
		}
		return macs[host], nil
	}
	if strings.HasPrefix(command, "ping ") {
		return "2 packets transmitted, 2 received", nil
	}
	if command == "bridge fdb show br br0 dynamic" {
		return strings.Join([]string{
			"02:00:00:00:04:01 dev eth1 master br0",
			"02:00:00:00:04:02 dev eth2 master br0",
			"02:00:00:00:04:03 dev eth3 master br0",
		}, "\n"), nil
	}
	return "", fmt.Errorf("unexpected command %s on %s", command, host)
}

func detachedEth2Runner(ctx context.Context, host, command string) (string, error) {
	if host == "sw1" && command == "ip -o link show dev eth2" {
		return "3: eth2: <BROADCAST,UP> mtu 1500 state UP", nil
	}
	if host == "pc1" && strings.HasPrefix(command, "ping ") && strings.HasSuffix(command, "10.4.0.20") {
		return "2 packets transmitted, 0 received, 100% packet loss", errors.New("exit status 1")
	}
	if host == "sw1" && command == "bridge fdb show br br0 dynamic" {
		return "02:00:00:00:04:01 dev eth1 master br0\n02:00:00:00:04:03 dev eth3 master br0", nil
	}
	return healthyRunner(ctx, host, command)
}

func failingRunner(_ context.Context, _, _ string) (string, error) {
	message := strings.Repeat("SSH error: connection refused; подробная диагностика. ", 150)
	return message, errors.New(message)
}
