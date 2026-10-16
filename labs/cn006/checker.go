package cn006

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
func (*Checker) Name() string { return "cn006" }
func (*Checker) Aliases() []string {
	return []string{"computer_network_006", "lab-computer-network-006"}
}

func (*Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	tasks := []*checker.Task{
		checkContains(ctx, environment, "pc1", "ip -4 -o addr show dev eth1", "192.168.50.10/24", "PC1: адрес /24", "Восстановите IPv4 на eth1 после эксперимента"),
		checkContains(ctx, environment, "pc2", "ip -4 -o addr show dev eth1", "192.168.50.130/24", "PC2: адрес /24", "IPv4 на eth1 должен остаться /24"),
		checkContains(ctx, environment, "pc1", "ip -4 route show dev eth1", "192.168.50.0/24 dev eth1", "PC1: connected /24", "Проверьте connected route на eth1"),
		checkContains(ctx, environment, "pc2", "ip -4 route show dev eth1", "192.168.50.0/24 dev eth1", "PC2: connected /24", "Проверьте connected route на eth1"),
		checkDirectRoute(ctx, environment, "pc1", "192.168.50.130", "192.168.50.10"),
		checkDirectRoute(ctx, environment, "pc2", "192.168.50.10", "192.168.50.130"),
		checkSuccess(ctx, environment, "pc1", "ping -c 2 -W 1 192.168.50.130", "PC1 → PC2", "ICMP должен проходить через учебный eth1"),
		checkSuccess(ctx, environment, "pc2", "ping -c 2 -W 1 192.168.50.10", "PC2 → PC1", "Обратный ICMP должен проходить через учебный eth1"),
	}
	result := checker.NewResult(tasks...)
	result.Report = "Computer Networks 006: IPv4: адрес, сеть и префикс"
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

// checkDirectRoute verifies the local L3 decision independently of ICMP.
// A Kubernetes management default route must NOT masquerade as a lab route.
func checkDirectRoute(ctx context.Context, environment checker.Environment, node, target, source string) *checker.Task {
	task := checker.NewTask(strings.ToUpper(node)+": direct eth1 → "+target,
		"ip route get must choose eth1 without a gateway")
	command := fmt.Sprintf("ip -4 route get %s from %s", target, source)
	output, err := runSSH(ctx, node, command)
	if err != nil {
		return task.AddLog("route lookup failed: "+err.Error(), node, environment.SessionNamespace)
	}
	if routeDirectOnEth1(output) {
		return task.SetCompleted(true)
	}
	return task.AddLog("not direct on eth1; route get: "+strings.TrimSpace(output),
		node, environment.SessionNamespace)
}

func routeDirectOnEth1(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		found := false
		for i, field := range fields {
			if field == "via" {
				return false
			}
			if field == "dev" && i+1 < len(fields) && fields[i+1] == "eth1" {
				found = true
			}
		}
		if found {
			return true
		}
	}
	return false
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
