package cn008

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
func (*Checker) Name() string { return "cn008" }
func (*Checker) Aliases() []string {
	return []string{"computer_network_008", "lab-computer-network-008"}
}

func (*Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	tasks := []*checker.Task{
		checkContains(ctx, environment, "pc1", "ip -4 route show 10.8.2.0/24", "via 10.8.1.1 dev eth1", "PC1: route к pc2", "Преднастроенный lab route должен идти через R1"),
		checkContains(ctx, environment, "r1", "show ip route 10.8.2.0/24", "10.8.12.2", "R1: route к LAN-B", "R1 должен маршрутизировать через R2"),
		checkContains(ctx, environment, "r2", "show ip route 10.8.1.0/24", "10.8.12.1", "R2: обратный route", "R2 должен иметь обратный путь через R1"),
		checkSuccess(ctx, environment, "pc1", "ping -c 2 -W 1 10.8.2.10", "End-to-end ICMP", "Маршрутизируемый путь должен быть исправен для TTL/traceroute эксперимента"),
	}
	result := checker.NewResult(tasks...)
	result.Report = "Computer Networks 008: ICMP и traceroute: сеть рассказывает о себе"
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

func checkSuccess(ctx context.Context, environment checker.Environment, node, command, name, description string) *checker.Task {
	task := checker.NewTask(name, description)
	output, err := runSSH(ctx, node, command)
	if err != nil {
		if strings.TrimSpace(output) != "" {
			task.AddLog(strings.TrimSpace(output), node, environment.SessionNamespace)
		}
		return task.AddLog("command failed: "+err.Error(), node, environment.SessionNamespace)
	}
	if strings.TrimSpace(output) != "" {
		task.AddLog(strings.TrimSpace(output), node, environment.SessionNamespace)
	}
	return task.SetCompleted(true)
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
