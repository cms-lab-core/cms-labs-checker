package cn014

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
func (*Checker) Name() string { return "cn014" }
func (*Checker) Aliases() []string {
	return []string{"computer_network_014", "lab-computer-network-014"}
}

func (*Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	tasks := []*checker.Task{
		checkContains(ctx, environment, "pc1", "ip -4 route show 10.14.20.0/24", "via 10.14.1.1 dev eth1", "PC1 → DNS LAN", "Добавьте route к DNS LAN через R1"),
		checkContains(ctx, environment, "pc1", "ip -4 route show 10.14.30.0/24", "via 10.14.1.1 dev eth1", "PC1 → WEB LAN", "Добавьте route к WEB LAN через R1"),
		checkContains(ctx, environment, "r1", "show ip route 10.14.20.0/24", "10.14.12.2", "R1 → DNS LAN", "Добавьте static route через R2"),
		checkContains(ctx, environment, "r1", "show ip route 10.14.30.0/24", "10.14.12.2", "R1 → WEB LAN", "Добавьте static route через R2"),
		checkContains(ctx, environment, "r2", "show ip route 10.14.1.0/24", "10.14.12.1", "R2: обратный route", "Добавьте route к client LAN через R1"),
		checkContains(ctx, environment, "pc1", "sh -lc \"grep -E '^nameserver[[:space:]]+10\\.14\\.20\\.53([[:space:]]|$)' /etc/resolv.conf || true\"", "10.14.20.53", "PC1: resolver", "Системный resolver должен использовать dns1"),
		checkContains(ctx, environment, "pc1", "dig +short @10.14.20.53 app.lab.example A", "10.14.30.80", "DNS app.lab.example", "DNS должен вернуть адрес web1"),
		checkContains(ctx, environment, "web1", "ss -ltn", ":8080", "WEB1: HTTP listener", "Запустите HTTP server на TCP/8080"),
		checkContains(ctx, environment, "pc1", "curl -fsS --max-time 3 http://app.lab.example:8080/", "cms-network-capstone-ok", "URL → HTTP body", "Полная цепочка DNS → routing → TCP → HTTP должна работать"),
	}
	result := checker.NewResult(tasks...)
	result.Report = "Computer Networks 014: От URL до страницы — итоговая сеть"
	return result, nil
}

func checkContains(ctx context.Context, environment checker.Environment, node, command, expected, name, description string) *checker.Task {
	task := checker.NewTask(name, description)
	output, err := runSSH(ctx, node, command)
	if err != nil {
		return task.AddLog("command failed: "+err.Error(), node, environment.SessionNamespace)
	}
	if strings.Contains(output, expected) {
		return task.AddLog(fmt.Sprintf("found %q", expected), node, environment.SessionNamespace).SetCompleted(true)
	}
	if output == "" {
		output = "<empty>"
	}
	return task.AddLog("expected "+expected+", got: "+output, node, environment.SessionNamespace)
}

func runSSH(ctx context.Context, host, command string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	config := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            []ssh.AuthMethod{ssh.Password(sshPassword)},
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
