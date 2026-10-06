package cn002

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

func (*Checker) Name() string { return "cn002" }

func (*Checker) Aliases() []string {
	return []string{
		"computer_network_002",
		"lab-computer-network-002",
	}
}

func (*Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	tasks := []*checker.Task{
		checkHostState(ctx, environment, "pc1", "192.0.2.10/24", "192.0.2.10"),
		checkHostState(ctx, environment, "pc2", "192.0.2.20/24", "192.0.2.20"),
		checkPing(ctx, environment, "pc1", "192.0.2.20"),
		checkNeighbor(ctx, environment, "pc1", "192.0.2.20"),
	}

	result := checker.NewResult(tasks...)
	result.Report = "Computer Networks 002: Хост как сетевой узел"
	return result, nil
}

func checkHostState(ctx context.Context, environment checker.Environment, node, cidr, sourceIP string) *checker.Task {
	task := checker.NewTask(
		fmt.Sprintf("%s: состояние eth1", strings.ToUpper(node)),
		fmt.Sprintf("eth1 должен быть UP, иметь %s, MTU 1400 и connected route 192.0.2.0/24", cidr),
	)

	ok := true

	operstate, err := runSSH(ctx, node, "cat /sys/class/net/eth1/operstate")
	if err != nil {
		task.AddLog("не удалось проверить link state: "+err.Error(), node, environment.SessionNamespace)
		ok = false
	} else if strings.TrimSpace(operstate) == "up" {
		task.AddLog("link: eth1 UP", node, environment.SessionNamespace)
	} else {
		task.AddLog("link: ожидался UP, получено "+strings.TrimSpace(operstate), node, environment.SessionNamespace)
		ok = false
	}

	addresses, err := runSSH(ctx, node, "ip -4 -o addr show dev eth1")
	if err != nil {
		task.AddLog("не удалось прочитать IPv4: "+err.Error(), node, environment.SessionNamespace)
		ok = false
	} else if strings.Contains(addresses, "inet "+cidr) {
		task.AddLog("IPv4: "+cidr, node, environment.SessionNamespace)
	} else {
		task.AddLog("IPv4: ожидается "+cidr, node, environment.SessionNamespace)
		ok = false
	}

	mtu, err := runSSH(ctx, node, "cat /sys/class/net/eth1/mtu")
	if err != nil {
		task.AddLog("не удалось проверить MTU: "+err.Error(), node, environment.SessionNamespace)
		ok = false
	} else if strings.TrimSpace(mtu) == "1400" {
		task.AddLog("MTU: 1400", node, environment.SessionNamespace)
	} else {
		task.AddLog("MTU: ожидалось 1400, получено "+strings.TrimSpace(mtu), node, environment.SessionNamespace)
		ok = false
	}

	route, err := runSSH(ctx, node, "ip -4 route show 192.0.2.0/24 dev eth1")
	if err != nil {
		task.AddLog("не удалось проверить connected route: "+err.Error(), node, environment.SessionNamespace)
		ok = false
	} else if strings.Contains(route, "192.0.2.0/24") &&
		strings.Contains(route, "dev eth1") &&
		strings.Contains(route, "scope link") &&
		strings.Contains(route, "src "+sourceIP) {
		task.AddLog("route: 192.0.2.0/24 dev eth1 scope link", node, environment.SessionNamespace)
	} else if strings.TrimSpace(route) == "" {
		task.AddLog("route: connected route 192.0.2.0/24 отсутствует", node, environment.SessionNamespace)
		ok = false
	} else {
		task.AddLog("route: неожидаемое состояние: "+strings.TrimSpace(route), node, environment.SessionNamespace)
		ok = false
	}

	if ok {
		task.SetCompleted(true)
	}
	return task
}

func checkPing(ctx context.Context, environment checker.Environment, node, destination string) *checker.Task {
	task := checker.NewTask(
		"PC1 → PC2: IPv4 reachability",
		"После настройки host pc1 должен достигать pc2 по учебному eth1",
	)

	output, err := runSSH(ctx, node, fmt.Sprintf("ping -c 2 -W 1 %s", destination))
	if err != nil {
		if strings.TrimSpace(output) != "" {
			task.AddLog(lastLine(output), node, environment.SessionNamespace)
		}
		return task.AddLog("ping не проходит", node, environment.SessionNamespace)
	}

	return task.
		AddLog("ping 192.0.2.20 успешен", node, environment.SessionNamespace).
		SetCompleted(true)
}

func checkNeighbor(ctx context.Context, environment checker.Environment, node, destination string) *checker.Task {
	task := checker.NewTask(
		"PC1: neighbor state для PC2",
		"После реального трафика pc1 должен иметь рабочую neighbor entry для 192.0.2.20 на eth1",
	)

	output, err := runSSH(ctx, node, fmt.Sprintf("ip neigh show %s dev eth1", destination))
	if err != nil {
		return task.AddLog("не удалось прочитать neighbor table: "+err.Error(), node, environment.SessionNamespace)
	}

	state := strings.TrimSpace(output)
	upper := strings.ToUpper(state)
	if state != "" &&
		strings.Contains(state, "lladdr") &&
		!strings.Contains(upper, "FAILED") &&
		!strings.Contains(upper, "INCOMPLETE") {
		return task.
			AddLog("neighbor: "+state, node, environment.SessionNamespace).
			SetCompleted(true)
	}

	if state == "" {
		return task.AddLog("neighbor entry отсутствует; выполните ping и снова проверьте ip neigh", node, environment.SessionNamespace)
	}
	return task.AddLog("neighbor entry нерабочая: "+state, node, environment.SessionNamespace)
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
