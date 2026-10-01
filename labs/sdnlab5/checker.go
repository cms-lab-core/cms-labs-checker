package sdnlab5

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cms-lab-core/cms-labs-checker/checker"
)

const agentPort = 8080

type nodeState struct {
	Hostname   string `json:"hostname"`
	Interfaces map[string]struct {
		Addresses []string `json:"addresses"`
	} `json:"interfaces"`
	PeerReachable bool `json:"peer_reachable"`
	Services      struct {
		SSH  bool `json:"ssh"`
		SNMP bool `json:"snmp"`
	} `json:"services"`
}

type Checker struct {
	client  *http.Client
	targets map[string][]string
}

func New() *Checker {
	return &Checker{client: &http.Client{Timeout: 5 * time.Second}}
}

func (*Checker) Name() string { return "sdn_lab_5" }

func (*Checker) Aliases() []string { return []string{"sdn-lab-5", "SDN_Lab_5"} }

func (c *Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	router, routerURL, routerErr := c.readState(ctx, environment, "r1")
	switchNode, switchURL, switchErr := c.readState(ctx, environment, "s1")

	routerAddress := addressTask("Маршрутизатор r1", "Настройте 10.50.0.1/30 на интерфейсе eth1", router, routerErr, "10.50.0.1/30", routerURL, environment.SessionNamespace)
	switchAddress := addressTask("Коммутатор s1", "Настройте 10.50.0.2/30 на интерфейсе eth1", switchNode, switchErr, "10.50.0.2/30", switchURL, environment.SessionNamespace)

	reachability := checker.NewTask("Связность", "Узлы r1 и s1 должны отвечать друг другу по лабораторному каналу")
	if routerErr != nil || switchErr != nil {
		reachability.AddLog(joinErrors(routerErr, switchErr), "", environment.SessionNamespace)
	} else if router.PeerReachable && switchNode.PeerReachable {
		reachability.AddLog("двусторонняя ICMP-связность подтверждена", "r1,s1", environment.SessionNamespace).SetCompleted(true)
	} else {
		reachability.AddLog(fmt.Sprintf("peer_reachable: r1=%t, s1=%t", router.PeerReachable, switchNode.PeerReachable), "r1,s1", environment.SessionNamespace)
	}

	ssh := serviceTask("SSH", "SSH должен быть доступен на обоих узлах", router, switchNode, routerErr, switchErr, func(state *nodeState) bool { return state.Services.SSH }, environment.SessionNamespace)
	snmp := serviceTask("SNMP", "SNMP-агент должен работать на обоих узлах", router, switchNode, routerErr, switchErr, func(state *nodeState) bool { return state.Services.SNMP }, environment.SessionNamespace)

	result := checker.NewResult(routerAddress, switchAddress, reachability, ssh, snmp)
	result.Report = "Проверены адреса лабораторного канала, двусторонняя связность, SSH и SNMP."
	return result, nil
}

func (c *Checker) readState(ctx context.Context, environment checker.Environment, node string) (*nodeState, string, error) {
	urls := c.targets[node]
	if len(urls) == 0 {
		urls = candidateURLs(environment, node)
	}
	errorsSeen := make([]string, 0, len(urls))
	for _, target := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target+"/state", nil)
		if err != nil {
			errorsSeen = append(errorsSeen, err.Error())
			continue
		}
		response, err := c.client.Do(req)
		if err != nil {
			errorsSeen = append(errorsSeen, fmt.Sprintf("%s: %v", target, err))
			continue
		}
		var state nodeState
		decodeErr := json.NewDecoder(response.Body).Decode(&state)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			errorsSeen = append(errorsSeen, fmt.Sprintf("%s: HTTP %s", target, response.Status))
			continue
		}
		if decodeErr != nil {
			errorsSeen = append(errorsSeen, fmt.Sprintf("%s: decode state: %v", target, decodeErr))
			continue
		}
		return &state, target, nil
	}
	return nil, "", fmt.Errorf("%s lab agent is unavailable: %s", node, strings.Join(errorsSeen, "; "))
}

func candidateURLs(environment checker.Environment, node string) []string {
	candidates := []string{"http://" + node + fmt.Sprintf(":%d", agentPort)}
	for _, prefix := range []string{environment.SessionNamespace, environment.SessionID} {
		prefix = strings.TrimSpace(prefix)
		if prefix != "" {
			candidates = append(candidates, fmt.Sprintf("http://%s-%s:%d", prefix, node, agentPort))
		}
	}
	return candidates
}

func addressTask(title, description string, state *nodeState, stateErr error, expected, target, namespace string) *checker.Task {
	task := checker.NewTask(title, description)
	if stateErr != nil {
		return task.AddLog(stateErr.Error(), "", namespace)
	}
	addresses := state.Interfaces["eth1"].Addresses
	for _, address := range addresses {
		if address == expected {
			return task.AddLog(fmt.Sprintf("eth1=%s (%s)", expected, target), state.Hostname, namespace).SetCompleted(true)
		}
	}
	return task.AddLog(fmt.Sprintf("eth1: ожидался %s, получено %v", expected, addresses), state.Hostname, namespace)
}

func serviceTask(title, description string, router, switchNode *nodeState, routerErr, switchErr error, ready func(*nodeState) bool, namespace string) *checker.Task {
	task := checker.NewTask(title, description)
	if routerErr != nil || switchErr != nil {
		return task.AddLog(joinErrors(routerErr, switchErr), "", namespace)
	}
	if ready(router) && ready(switchNode) {
		return task.AddLog("сервис доступен на r1 и s1", "r1,s1", namespace).SetCompleted(true)
	}
	return task.AddLog(fmt.Sprintf("состояние сервиса: r1=%t, s1=%t", ready(router), ready(switchNode)), "r1,s1", namespace)
}

func joinErrors(values ...error) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		if value != nil {
			parts = append(parts, value.Error())
		}
	}
	return strings.Join(parts, "; ")
}
