package cn009

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
func (*Checker) Name() string { return "cn009" }
func (*Checker) Aliases() []string {
	return []string{"computer_network_009", "lab-computer-network-009"}
}

func (*Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	tasks := []*checker.Task{
		checkContains(ctx, environment, "pc1", "ip -6 -o addr show dev eth1", "2001:db8:9::10/64", "PC1: IPv6 /64", "Назначьте global IPv6"),
		checkContains(ctx, environment, "pc2", "ip -6 -o addr show dev eth1", "2001:db8:9::20/64", "PC2: IPv6 /64", "Назначьте global IPv6"),
		checkSuccess(ctx, environment, "pc1", "ping -6 -c 2 -W 1 2001:db8:9::20", "IPv6 ping", "ICMPv6 должен проходить"),
		checkSuccess(ctx, environment, "pc1", "sh -lc \"ip -6 neigh show 2001:db8:9::20 dev eth1 | grep lladdr | grep -Ev '(FAILED|INCOMPLETE)'\"", "NDP neighbor entry", "После ping должна быть NDP-запись"),
	}
	result := checker.NewResult(tasks...)
	result.Report = "Computer Networks 009: IPv6 и Neighbor Discovery"
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
