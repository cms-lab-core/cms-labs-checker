package cn005

import (
	"bytes"
	"context"
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
func (*Checker) Name() string { return "cn005" }
func (*Checker) Aliases() []string {
	return []string{"computer_network_005", "lab-computer-network-005"}
}

func (*Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	tasks := []*checker.Task{
		checkSuccess(ctx, environment, "pc1", "ping -c 2 -W 1 10.5.0.20", "PC1 → PC2", "ICMP должен проходить"),
		checkSuccess(ctx, environment, "pc1", "sh -lc \"ip neigh show 10.5.0.20 dev eth1 | grep lladdr | grep -Ev '(FAILED|INCOMPLETE)'\"", "PC1: ARP/neighbor cache", "Должна быть разрешённая запись для pc2"),
	}
	result := checker.NewResult(tasks...)
	result.Report = "Computer Networks 005: ARP: как IP превращается в MAC"
	return result, nil
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
