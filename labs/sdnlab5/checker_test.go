package sdnlab5

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cms-lab-core/cms-labs-checker/checker"
)

func TestCheckerReportsCompletedLab(t *testing.T) {
	lab := New()
	lab.client = stateClient(map[string]string{
		"r1.test": `{"hostname":"r1","interfaces":{"eth1":{"addresses":["10.50.0.1/30"]}},"peer_reachable":true,"services":{"ssh":true,"snmp":true}}`,
		"s1.test": `{"hostname":"s1","interfaces":{"eth1":{"addresses":["10.50.0.2/30"]}},"peer_reachable":true,"services":{"ssh":true,"snmp":true}}`,
	})
	lab.targets = map[string][]string{"r1": {"http://r1.test"}, "s1": {"http://s1.test"}}
	result, err := lab.Check(context.Background(), checker.Environment{SessionNamespace: "lab-test"})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.CurrentScore != 5 || result.MaxScore != 5 {
		t.Fatalf("score = %g/%g, want 5/5", result.CurrentScore, result.MaxScore)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestCheckerReturnsStructuredFailure(t *testing.T) {
	lab := New()
	lab.client = stateClient(map[string]string{
		"r1.test": `{"hostname":"r1","interfaces":{"eth1":{"addresses":[]}},"peer_reachable":false,"services":{"ssh":true,"snmp":true}}`,
		"s1.test": `{"hostname":"s1","interfaces":{"eth1":{"addresses":[]}},"peer_reachable":false,"services":{"ssh":true,"snmp":true}}`,
	})
	lab.targets = map[string][]string{"r1": {"http://r1.test"}, "s1": {"http://s1.test"}}
	result, err := lab.Check(context.Background(), checker.Environment{})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.CurrentScore != 2 || result.MaxScore != 5 {
		t.Fatalf("score = %g/%g, want 2/5", result.CurrentScore, result.MaxScore)
	}
	if result.Tasks[0].Complete || len(result.Tasks[0].Logs) == 0 {
		t.Fatalf("expected an incomplete address task with logs: %+v", result.Tasks[0])
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func stateClient(states map[string]string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		state, ok := states[request.URL.Host]
		if !ok || request.URL.Path != "/state" {
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{"error":"not found"}`))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(state))}, nil
	})}
}
