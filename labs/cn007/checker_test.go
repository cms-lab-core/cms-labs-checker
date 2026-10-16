package cn007

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cms-lab-core/cms-labs-checker/checker"
)

func TestFRRStaticRouteMatcher(t *testing.T) {
	cases := []struct {
		name, output string
		want         bool
	}{
		{"valid FRR detailed", "Routing entry for 10.7.20.0/24\n Known via \"static\", distance 1, metric 0\n * 10.7.12.2, via eth2", true},
		{"valid FRR summary", "S>* 10.7.20.0/24 [1/0] via 10.7.12.2, eth2", true},
		{"wrong nexthop", "Routing entry for 10.7.20.0/24\n Known via \"static\"\n * 10.7.12.3", false},
		{"wrong prefix", "Routing entry for 10.7.21.0/24\n Known via \"static\"\n * 10.7.12.2", false},
		{"connected route", "C>* 10.7.20.0/24 is directly connected, eth1\n 10.7.12.2", false},
		{"missing", "Network not in table", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeHasStaticNextHop(tc.output, "10.7.20.0/24", "10.7.12.2"); got != tc.want {
				t.Fatalf("routeHasStaticNextHop(%q) = %t; want %t", tc.output, got, tc.want)
			}
		})
	}
}

func TestNull0RouteDetector(t *testing.T) {
	cases := []struct {
		config string
		want   bool
	}{
		{"ip route 10.7.20.10/32 Null0\n", true},
		{"ip route 10.7.20.10/32 blackhole\n", true},
		{"ip route 10.7.20.10/32 reject\n", true},
		{"ip route 10.7.20.0/24 10.7.12.2\n", false},
		{"! restored\n", false},
	}
	for _, tc := range cases {
		if got := containsBlackholeRoute(tc.config); got != tc.want {
			t.Fatalf("containsBlackholeRoute(%q) = %t; want %t", tc.config, got, tc.want)
		}
	}
}

func TestAllChecksAndNull0Failure(t *testing.T) {
	for _, failing := range []bool{false, true} {
		runner := fakeRunner(failing)
		result, err := (&Checker{run: runner}).Check(context.Background(), checker.Environment{})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Tasks) != 13 || result.MaxScore != 13 {
			t.Fatalf("got %d tasks and %g possible points, want 13", len(result.Tasks), result.MaxScore)
		}
		want := float64(13)
		if failing {
			want = 12
		}
		if result.CurrentScore != want {
			t.Fatalf("failing=%t score=%g, want %g", failing, result.CurrentScore, want)
		}
	}
}

func fakeRunner(failing bool) commandRunner {
	return func(_ context.Context, node, command string) (string, error) {
		switch {
		case strings.HasPrefix(command, "ip -4 -o addr show dev"):
			if node == "pc1" {
				return "2: eth1 inet 10.7.10.10/24", nil
			}
			return "2: eth1 inet 10.7.20.10/24", nil
		case strings.HasPrefix(command, "ip -4 route show"):
			if node == "pc1" {
				return "10.7.20.0/24 via 10.7.10.1 dev eth1", nil
			}
			return "10.7.10.0/24 via 10.7.20.1 dev eth1", nil
		case command == "show ip route connected":
			if node == "r1" {
				return "C>* 10.7.10.0/24 eth1\nC>* 10.7.12.0/30 eth2", nil
			}
			return "C>* 10.7.12.0/30 eth1\nC>* 10.7.20.0/24 eth2", nil
		case strings.HasPrefix(command, "show ip route "):
			if node == "r1" {
				return "Routing entry for 10.7.20.0/24\n Known via \"static\"\n * 10.7.12.2", nil
			}
			return "Routing entry for 10.7.10.0/24\n Known via \"static\"\n * 10.7.12.1", nil
		case command == "show running-config":
			config := "ip route 10.7.20.0/24 10.7.12.2\n"
			if failing {
				config += "ip route 10.7.20.10/32 Null0\n"
			}
			return config, nil
		case strings.HasPrefix(command, "ping "):
			return "2 packets transmitted, 2 received", nil
		default:
			return "", errors.New("unexpected test command: " + command)
		}
	}
}
