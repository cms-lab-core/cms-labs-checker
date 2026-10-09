package cn004

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/cms-lab-core/cms-labs-checker/checker"
)

const (
	sshUser            = "admin"
	sshPassword        = "admin"
	maxDiagnosticBytes = 128
)

type commandRunner func(context.Context, string, string) (string, error)

type Checker struct {
	run commandRunner
}

func New() *Checker { return &Checker{run: runSSH} }

func (*Checker) Name() string { return "cn004" }

func (*Checker) Aliases() []string {
	return []string{"computer_network_004", "lab-computer-network-004"}
}

func (c *Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	run := c.run
	if run == nil {
		run = runSSH
	}

	tasks := []*checker.Task{
		checkBridgePort(ctx, run, "eth1"),
		checkBridgePort(ctx, run, "eth2"),
		checkBridgePort(ctx, run, "eth3"),
		checkHost(ctx, run, "pc1", "10.4.0.10/24", "02:00:00:00:04:01"),
		checkHost(ctx, run, "pc2", "10.4.0.20/24", "02:00:00:00:04:02"),
		checkHost(ctx, run, "pc3", "10.4.0.30/24", "02:00:00:00:04:03"),
		checkPing(ctx, run, "pc1", "10.4.0.20", "PC1 → PC2"),
		checkPing(ctx, run, "pc1", "10.4.0.30", "PC1 → PC3"),
		checkPing(ctx, run, "pc3", "10.4.0.10", "PC3 → PC1"),
		checkLearnedMAC(ctx, run, "02:00:00:00:04:01", "eth1"),
		checkLearnedMAC(ctx, run, "02:00:00:00:04:02", "eth2"),
		checkLearnedMAC(ctx, run, "02:00:00:00:04:03", "eth3"),
	}

	// The result is sent as a Kubernetes termination message (4 KiB max).
	// Keep titles descriptive, omit redundant success logs and namespaces,
	// and bound errors. This preserves all 12 independent checks and scores.
	result := checker.NewResult(tasks...)
	result.Report = "CN004: Ethernet switch / MAC learning"
	return result, nil
}

func checkBridgePort(ctx context.Context, run commandRunner, port string) *checker.Task {
	task := checker.NewTask("SW1: "+port+" → br0", "")
	output, err := run(ctx, "sw1", fmt.Sprintf("ip -o link show dev %s", port))
	if err != nil {
		return task.AddLog(brief("ошибка чтения "+port+": "+err.Error()), "sw1")
	}
	if strings.Contains(output, "master br0") {
		return task.SetCompleted(true)
	}
	return task.AddLog(port+" не входит в br0; проверьте bridge link", "sw1")
}

func checkHost(ctx context.Context, run commandRunner, node, cidr, mac string) *checker.Task {
	task := checker.NewTask(strings.ToUpper(node)+": IPv4 / MAC", "")
	var problems []string

	address, err := run(ctx, node, "ip -4 -o addr show dev eth1")
	if err != nil {
		problems = append(problems, "IPv4: "+brief(err.Error()))
	} else if !strings.Contains(address, "inet "+cidr) {
		problems = append(problems, "ожидается IPv4 "+cidr+" на eth1")
	}

	actualMAC, err := run(ctx, node, "cat /sys/class/net/eth1/address")
	if err != nil {
		problems = append(problems, "MAC: "+brief(err.Error()))
	} else if !strings.EqualFold(strings.TrimSpace(actualMAC), mac) {
		problems = append(problems, "ожидается MAC "+mac+" на eth1")
	}

	if len(problems) == 0 {
		return task.SetCompleted(true)
	}
	return task.AddLog(brief(strings.Join(problems, "; ")), node)
}

func checkPing(ctx context.Context, run commandRunner, node, target, name string) *checker.Task {
	task := checker.NewTask(name, "")
	output, err := run(ctx, node, fmt.Sprintf("ping -c 2 -W 1 %s", target))
	if err != nil {
		// Command output can be arbitrarily long on failures; retain only the
		// diagnostic tail and leave full diagnostics to the Pod logs.
		detail := lastLine(output)
		if detail == "" {
			detail = err.Error()
		}
		return task.AddLog(brief("ping не прошёл: "+detail), node)
	}
	return task.SetCompleted(true)
}

func checkLearnedMAC(ctx context.Context, run commandRunner, mac, port string) *checker.Task {
	task := checker.NewTask("SW1 FDB: "+mac+" → "+port, "")
	output, err := run(ctx, "sw1", "bridge fdb show br br0 dynamic")
	if err != nil {
		return task.AddLog(brief("FDB недоступна: "+err.Error()), "sw1")
	}

	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(strings.ToLower(line), strings.ToLower(mac)) &&
			strings.Contains(line, "dev "+port) {
			return task.SetCompleted(true)
		}
	}
	return task.AddLog("нет dynamic FDB "+mac+" → "+port+"; нужен трафик от хоста", "sw1")
}

// brief is bounded in *UTF-8 bytes*, not runes: the kubelet limit is bytes.
func brief(value string) string {
	clean := strings.Join(strings.Fields(value), " ")
	if len(clean) <= maxDiagnosticBytes {
		return clean
	}
	const suffix = "…"
	limit := maxDiagnosticBytes - len(suffix)
	for limit > 0 && !utf8.RuneStart(clean[limit]) {
		limit--
	}
	return clean[:limit] + suffix
}

func runSSH(ctx context.Context, host, command string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	config := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            []ssh.AuthMethod{ssh.Password(sshPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // ephemeral per-attempt lab nodes
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(host, "22"), config)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case <-commandCtx.Done():
		_ = session.Close()
		return stdout.String(), commandCtx.Err()
	case err := <-done:
		output := strings.TrimSpace(stdout.String())
		if stderr.Len() > 0 {
			if output != "" {
				output += "\n"
			}
			output += strings.TrimSpace(stderr.String())
		}
		return output, err
	}
}

func lastLine(value string) string {
	lines := strings.Split(strings.TrimSpace(value), "\n")
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}
