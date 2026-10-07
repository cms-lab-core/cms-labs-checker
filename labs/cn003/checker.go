package cn003

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

func (*Checker) Name() string { return "cn003" }

func (*Checker) Aliases() []string {
	return []string{
		"computer_network_003",
		"lab-computer-network-003",
	}
}

func (*Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	tasks := []*checker.Task{
		checkHostIdentity(ctx, environment, "pc1", "02:00:00:00:03:01", "198.51.100.10/24"),
		checkHostIdentity(ctx, environment, "pc2", "02:00:00:00:03:02", "198.51.100.20/24"),
		checkNeighbor(ctx, environment, "pc1", "198.51.100.20", "02:00:00:00:03:02"),
		checkNeighbor(ctx, environment, "pc2", "198.51.100.10", "02:00:00:00:03:01"),
		checkPing(ctx, environment, "pc1", "198.51.100.20"),
		checkPing(ctx, environment, "pc2", "198.51.100.10"),
	}

	result := checker.NewResult(tasks...)
	result.Report = "Computer Networks 003: Ethernet frame и L2 destination"
	return result, nil
}

func checkHostIdentity(ctx context.Context, environment checker.Environment, node, expectedMAC, expectedCIDR string) *checker.Task {
	task := checker.NewTask(
		fmt.Sprintf("%s: Ethernet identity", strings.ToUpper(node)),
		fmt.Sprintf("eth1 должен быть UP, иметь MAC %s и IPv4 %s", expectedMAC, expectedCIDR),
	)

	ok := true

	state, err := runSSH(ctx, node, "cat /sys/class/net/eth1/operstate")
	if err != nil {
		task.AddLog("не удалось проверить link state: "+err.Error(), node, environment.SessionNamespace)
		ok = false
	} else if strings.TrimSpace(state) == "up" {
		task.AddLog("link: eth1 UP", node, environment.SessionNamespace)
	} else {
		task.AddLog("link: ожидался UP, получено "+strings.TrimSpace(state), node, environment.SessionNamespace)
		ok = false
	}

	mac, err := runSSH(ctx, node, "cat /sys/class/net/eth1/address")
	if err != nil {
		task.AddLog("не удалось прочитать MAC: "+err.Error(), node, environment.SessionNamespace)
		ok = false
	} else if strings.EqualFold(strings.TrimSpace(mac), expectedMAC) {
		task.AddLog("MAC: "+expectedMAC, node, environment.SessionNamespace)
	} else {
		task.AddLog("MAC: ожидался "+expectedMAC+", получено "+strings.TrimSpace(mac), node, environment.SessionNamespace)
		ok = false
	}

	addresses, err := runSSH(ctx, node, "ip -4 -o addr show dev eth1")
	if err != nil {
		task.AddLog("не удалось прочитать IPv4: "+err.Error(), node, environment.SessionNamespace)
		ok = false
	} else if strings.Contains(addresses, "inet "+expectedCIDR) {
		task.AddLog("IPv4: "+expectedCIDR, node, environment.SessionNamespace)
	} else {
		task.AddLog("IPv4: ожидается "+expectedCIDR, node, environment.SessionNamespace)
		ok = false
	}

	if ok {
		task.SetCompleted(true)
	}
	return task
}

func checkNeighbor(ctx context.Context, environment checker.Environment, node, destination, expectedMAC string) *checker.Task {
	task := checker.NewTask(
		fmt.Sprintf("%s: L2 mapping для %s", strings.ToUpper(node), destination),
		fmt.Sprintf("%s должен соответствовать MAC %s на eth1", destination, expectedMAC),
	)

	output, err := runSSH(ctx, node, fmt.Sprintf("ip neigh show %s dev eth1", destination))
	if err != nil {
		return task.AddLog("не удалось прочитать neighbor table: "+err.Error(), node, environment.SessionNamespace)
	}

	state := strings.TrimSpace(output)
	lower := strings.ToLower(state)
	if strings.Contains(lower, "lladdr "+strings.ToLower(expectedMAC)) &&
		strings.Contains(strings.ToUpper(state), "PERMANENT") {
		return task.
			AddLog("neighbor: "+state, node, environment.SessionNamespace).
			SetCompleted(true)
	}

	if state == "" {
		return task.AddLog("neighbor mapping отсутствует", node, environment.SessionNamespace)
	}

	return task.AddLog(
		fmt.Sprintf("ожидался lladdr %s PERMANENT, получено: %s", expectedMAC, state),
		node,
		environment.SessionNamespace,
	)
}

func checkPing(ctx context.Context, environment checker.Environment, node, destination string) *checker.Task {
	task := checker.NewTask(
		fmt.Sprintf("%s → %s", strings.ToUpper(node), destination),
		"ICMP должен проходить при корректном Ethernet destination mapping",
	)

	output, err := runSSH(ctx, node, fmt.Sprintf("ping -c 2 -W 1 %s", destination))
	if err != nil {
		if strings.TrimSpace(output) != "" {
			task.AddLog(lastLine(output), node, environment.SessionNamespace)
		}
		return task.AddLog("ping не проходит", node, environment.SessionNamespace)
	}

	return task.
		AddLog("ping успешен", node, environment.SessionNamespace).
		SetCompleted(true)
}

func runSSH(ctx context.Context, host, command string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	config := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            []ssh.AuthMethod{ssh.Password(sshPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // ephemeral lab namespace; node keys are recreated per attempt
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
