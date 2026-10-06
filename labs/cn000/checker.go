package cn000

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/cms-lab-core/cms-labs-checker/checker"
)

const (
	sshUser     = "admin"
	sshPassword = "admin"
)

type Checker struct{}

func New() *Checker           { return &Checker{} }
func (*Checker) Name() string { return "cn000" }

func (*Checker) Aliases() []string {
	return []string{
		"computer_network_000",
		"lab-computer-network-000",
	}
}

func (*Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	tasks := []*checker.Task{
		checkAddress(ctx, environment, "pc1", "192.0.2.10/24"),
		checkAddress(ctx, environment, "pc2", "192.0.2.20/24"),
		checkPing(ctx, environment, "pc1", "192.0.2.20"),
		checkMarker(ctx, environment),
	}

	result := checker.NewResult(tasks...)
	result.Report = "Computer Networks 000: notebook, terminal, capture и CHECK"
	return result, nil
}

func checkAddress(ctx context.Context, environment checker.Environment, node, address string) *checker.Task {
	task := checker.NewTask(
		fmt.Sprintf("%s: учебный интерфейс eth1", strings.ToUpper(node)),
		fmt.Sprintf("На eth1 должен быть исходный адрес %s", address),
	)

	output, err := runSSH(ctx, node, "ip -4 -o addr show dev eth1")
	if err != nil {
		return task.AddLog("не удалось прочитать адрес eth1: "+err.Error(), node, environment.SessionNamespace)
	}

	expected := "inet " + address
	if strings.Contains(output, expected) {
		return task.
			AddLog(fmt.Sprintf("eth1: %s найден", address), node, environment.SessionNamespace).
			SetCompleted(true)
	}

	return task.AddLog(
		fmt.Sprintf("%s: на eth1 нет ожидаемого адреса %s", strings.ToUpper(node), address),
		node,
		environment.SessionNamespace,
	)
}

func checkPing(ctx context.Context, environment checker.Environment, node, destination string) *checker.Task {
	task := checker.NewTask(
		"PC1 → PC2: учебный data plane",
		"Заранее настроенные pc1 и pc2 должны обмениваться ICMP по eth1",
	)

	output, err := runSSH(ctx, node, fmt.Sprintf("ping -c 1 -W 1 %s", destination))
	if err != nil {
		if strings.TrimSpace(output) != "" {
			task.AddLog(lastLine(output), node, environment.SessionNamespace)
		}
		return task.AddLog(
			"PC1: 192.0.2.20 недоступен; проверьте состояние eth1 и линка pc1—pc2",
			node,
			environment.SessionNamespace,
		)
	}

	return task.
		AddLog("PC1 → 192.0.2.20: ping успешен", node, environment.SessionNamespace).
		SetCompleted(true)
}

func checkMarker(ctx context.Context, environment checker.Environment) *checker.Task {
	task := checker.NewTask(
		"PC1: onboarding marker",
		"/tmp/cms-lab-ready должен содержать ready",
	)

	output, err := runSSH(ctx, "pc1", "sh -lc 'test -f /tmp/cms-lab-ready && cat /tmp/cms-lab-ready || true'")
	if err != nil {
		return task.AddLog(
			"PC1: не удалось проверить /tmp/cms-lab-ready: "+err.Error(),
			"pc1",
			environment.SessionNamespace,
		)
	}

	if strings.TrimSpace(output) == "ready" {
		return task.
			AddLog("/tmp/cms-lab-ready содержит ready", "pc1", environment.SessionNamespace).
			SetCompleted(true)
	}

	if strings.TrimSpace(output) == "" {
		return task.AddLog(
			"PC1: /tmp/cms-lab-ready отсутствует или пуст",
			"pc1",
			environment.SessionNamespace,
		)
	}

	return task.AddLog(
		fmt.Sprintf("PC1: ожидалось ready, получено %q", strings.TrimSpace(output)),
		"pc1",
		environment.SessionNamespace,
	)
}

func runSSH(ctx context.Context, host, command string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	config := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{ssh.Password(sshPassword)},
		// Lab nodes are ephemeral and regenerate host keys for every attempt.
		// Connections stay inside the isolated namespace-local lab management plane.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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
