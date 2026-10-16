package cn007

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
	maxLogBytes = 160
)

type commandRunner func(context.Context, string, string) (string, error)

type Checker struct {
	run commandRunner
}

func New() *Checker           { return &Checker{run: runSSH} }
func (*Checker) Name() string { return "cn007" }
func (*Checker) Aliases() []string {
	return []string{"computer_network_007", "lab-computer-network-007"}
}

func (c *Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	run := c.run
	if run == nil {
		run = runSSH
	}
	tasks := []*checker.Task{
		checkText(ctx, run, "pc1", "ip -4 -o addr show dev eth1", "10.7.10.10/24", "PC1: LAN A IPv4"),
		checkText(ctx, run, "pc2", "ip -4 -o addr show dev eth1", "10.7.20.10/24", "PC2: LAN B IPv4"),
		checkText(ctx, run, "pc1", "ip -4 route show 10.7.20.0/24", "via 10.7.10.1 dev eth1", "PC1: next hop R1"),
		checkText(ctx, run, "pc2", "ip -4 route show 10.7.10.0/24", "via 10.7.20.1 dev eth1", "PC2: next hop R2"),

		checkText(ctx, run, "r1", "show ip route connected", "10.7.10.0/24", "R1: connected LAN A"),
		checkText(ctx, run, "r1", "show ip route connected", "10.7.12.0/30", "R1: connected transit"),
		checkText(ctx, run, "r2", "show ip route connected", "10.7.12.0/30", "R2: connected transit"),
		checkText(ctx, run, "r2", "show ip route connected", "10.7.20.0/24", "R2: connected LAN B"),

		checkStatic(ctx, run, "r1", "10.7.20.0/24", "10.7.12.2", "R1: static route to LAN B"),
		checkStatic(ctx, run, "r2", "10.7.10.0/24", "10.7.12.1", "R2: reverse static route"),
		checkNoBlackhole(ctx, run),
		checkPing(ctx, run, "pc1", "10.7.20.10", "PC1 → PC2"),
		checkPing(ctx, run, "pc2", "10.7.10.10", "PC2 → PC1"),
	}
	result := checker.NewResult(tasks...)
	result.Report = "CN007: routing, static next hops and longest-prefix recovery"
	return result, nil
}

func checkText(ctx context.Context, run commandRunner, node, command, expected, title string) *checker.Task {
	task := checker.NewTask(title, "")
	output, err := run(ctx, node, command)
	if err != nil {
		return task.AddLog(brief("command failed: "+err.Error()), node)
	}
	if strings.Contains(output, expected) {
		return task.SetCompleted(true)
	}
	return task.AddLog(brief("expected "+expected+", got: "+output), node)
}

func checkStatic(ctx context.Context, run commandRunner, node, prefix, nextHop, title string) *checker.Task {
	task := checker.NewTask(title, "")
	output, err := run(ctx, node, "show ip route "+prefix)
	if err != nil {
		return task.AddLog(brief("FRR route lookup failed: "+err.Error()), node)
	}
	if routeHasStaticNextHop(output, prefix, nextHop) {
		return task.SetCompleted(true)
	}
	return task.AddLog(brief("no active static "+prefix+" via "+nextHop+": "+output), node)
}

// FRR "show ip route PREFIX" prints the destination, protocol and next hop.
// All three must match so a coincidental mention of the next-hop elsewhere
// cannot satisfy an incorrect route.
func routeHasStaticNextHop(output, prefix, nextHop string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(output, prefix) &&
		strings.Contains(output, nextHop) &&
		(strings.Contains(lower, "static") || strings.Contains(output, "S>") || strings.Contains(output, "S*"))
}

func checkNoBlackhole(ctx context.Context, run commandRunner) *checker.Task {
	task := checker.NewTask("R1: /32 Null0 removed", "")
	output, err := run(ctx, "r1", "show running-config")
	if err != nil {
		return task.AddLog(brief("cannot read R1 running-config: "+err.Error()), "r1")
	}
	if !containsBlackholeRoute(output) {
		return task.SetCompleted(true)
	}
	return task.AddLog("remove ip route 10.7.20.10/32 Null0 from R1", "r1")
}

func containsBlackholeRoute(output string) bool {
	for _, line := range strings.Split(strings.ToLower(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "ip" && fields[1] == "route" &&
			fields[2] == "10.7.20.10/32" &&
			(fields[3] == "null0" || fields[3] == "blackhole" || fields[3] == "reject") {
			return true
		}
	}
	return false
}

func checkPing(ctx context.Context, run commandRunner, node, target, title string) *checker.Task {
	task := checker.NewTask(title, "")
	_, err := run(ctx, node, "ping -c 2 -W 1 "+target)
	if err != nil {
		return task.AddLog(brief("ping failed: "+err.Error()), node)
	}
	return task.SetCompleted(true)
}

func brief(value string) string {
	clean := strings.Join(strings.Fields(value), " ")
	if len(clean) <= maxLogBytes {
		return clean
	}
	// Bound UTF-8 length in bytes; do not break a multibyte rune.
	limit := maxLogBytes - 3
	for limit > 0 && limit < len(clean) && (clean[limit]&0xc0) == 0x80 {
		limit--
	}
	return clean[:limit] + "..."
}

func runSSH(ctx context.Context, host, command string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	config := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            []ssh.AuthMethod{ssh.Password(sshPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // ephemeral, namespace-local lab nodes
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
