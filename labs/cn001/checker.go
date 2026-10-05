package cn001

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

func New() *Checker { return &Checker{} }

func (*Checker) Name() string { return "cn001" }

func (*Checker) Aliases() []string {
	return []string{
		"computer_network_001",
		"lab-computer-network-001",
	}
}

func (*Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	tasks := []*checker.Task{
		checkRoute(ctx, environment, "r1", "192.168.20.0/24", "10.0.12.2"),
		checkRoute(ctx, environment, "r2", "192.168.10.0/24", "10.0.12.1"),
		checkPing(ctx, environment, "pc1", "192.168.20.10"),
		checkPing(ctx, environment, "pc2", "192.168.10.10"),
	}

	result := checker.NewResult(tasks...)
	result.Report = "Computer Networks 001: статическая маршрутизация и end-to-end связность"
	return result, nil
}

func checkRoute(ctx context.Context, environment checker.Environment, node, prefix, nextHop string) *checker.Task {
	task := checker.NewTask(
		fmt.Sprintf("%s: маршрут %s", strings.ToUpper(node), prefix),
		fmt.Sprintf("В таблице маршрутизации должен быть статический маршрут через %s", nextHop),
	)

	output, err := runSSH(ctx, node, fmt.Sprintf("show ip route %s", prefix))
	if err != nil {
		return task.AddLog("SSH/route check failed: "+err.Error(), node, environment.SessionNamespace)
	}

	if strings.Contains(output, prefix) && strings.Contains(output, nextHop) && strings.Contains(strings.ToLower(output), "static") {
		return task.
			AddLog(fmt.Sprintf("маршрут %s через %s найден", prefix, nextHop), node, environment.SessionNamespace).
			SetCompleted(true)
	}

	return task.AddLog("ожидаемый статический маршрут не найден", node, environment.SessionNamespace)
}

func checkPing(ctx context.Context, environment checker.Environment, node, destination string) *checker.Task {
	task := checker.NewTask(
		fmt.Sprintf("%s → %s", strings.ToUpper(node), destination),
		"ICMP должен проходить через оба маршрутизатора",
	)

	output, err := runSSH(ctx, node, fmt.Sprintf("ping -c 2 -W 1 %s", destination))
	if err != nil {
		if strings.TrimSpace(output) != "" {
			task.AddLog(lastLine(output), node, environment.SessionNamespace)
		}
		return task.AddLog("ping failed: "+err.Error(), node, environment.SessionNamespace)
	}

	return task.
		AddLog("ping успешен", node, environment.SessionNamespace).
		SetCompleted(true)
}

func runSSH(ctx context.Context, host, command string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	address := net.JoinHostPort(host, "22")
	config := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            []ssh.AuthMethod{ssh.Password(sshPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // ephemeral lab namespace; node keys are recreated per attempt
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", address, config)
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
