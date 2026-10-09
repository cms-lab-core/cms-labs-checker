package cn011

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
func (*Checker) Name() string { return "cn011" }
func (*Checker) Aliases() []string {
	return []string{"computer_network_011", "lab-computer-network-011"}
}

func (*Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	tasks := []*checker.Task{
		checkContains(ctx, environment, "pc1", "ip -4 -o addr show dev eth1", "10.11.0.10/24", "PC1: IPv4", "Настройте client address"),
		checkContains(ctx, environment, "pc2", "ip -4 -o addr show dev eth1", "10.11.0.20/24", "PC2: IPv4", "Настройте server address"),
		checkExchange(ctx, environment),
	}
	result := checker.NewResult(tasks...)
	result.Report = "Computer Networks 011: TCP как разговор двух автоматов"
	return result, nil
}

func checkExchange(ctx context.Context, environment checker.Environment) *checker.Task {
	task := checker.NewTask("TCP exchange", "Checker сам поднимает временный listener и проверяет реальную доставку marker")

	if _, err := runSSH(ctx, "pc2", "sh -lc \"rm -f /tmp/cn011-data; nohup sh -c 'timeout 5 nc -l -p 8080 > /tmp/cn011-data' >/tmp/cn011-listener.log 2>&1 &\""); err != nil {
		return task.AddLog("listener start failed: "+err.Error(), "pc2", environment.SessionNamespace)
	}
	time.Sleep(300 * time.Millisecond)

	if output, err := runSSH(ctx, "pc1", "sh -lc \"printf 'cn011-marker\\\\n' | nc -w 2 10.11.0.20 8080\""); err != nil {
		if strings.TrimSpace(output) != "" {
			task.AddLog(strings.TrimSpace(output), "pc1", environment.SessionNamespace)
		}
		return task.AddLog("send failed: "+err.Error(), "pc1", environment.SessionNamespace)
	}
	time.Sleep(300 * time.Millisecond)

	output, err := runSSH(ctx, "pc2", "sh -lc \"cat /tmp/cn011-data 2>/dev/null || true\"")
	if err != nil {
		return task.AddLog("read failed: "+err.Error(), "pc2", environment.SessionNamespace)
	}
	if strings.Contains(output, "cn011-marker") {
		return task.AddLog("TCP marker доставлен", "pc2", environment.SessionNamespace).SetCompleted(true)
	}
	return task.AddLog("marker не получен; data="+strings.TrimSpace(output), "pc2", environment.SessionNamespace)
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
