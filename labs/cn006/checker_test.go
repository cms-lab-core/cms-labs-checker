package cn006

import "testing"

func TestRouteDirectOnEth1(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name:   "connected eth1",
			output: "192.168.50.130 from 192.168.50.10 dev eth1 uid 0\n    cache\n",
			want:   true,
		},
		{
			name:   "gateway over management eth0",
			output: "192.168.50.130 from 192.168.50.10 via 10.0.0.1 dev eth0 uid 0\n    cache\n",
			want:   false,
		},
		{
			name:   "on eth1 but via router",
			output: "192.168.50.130 via 192.168.50.1 dev eth1 src 192.168.50.10\n",
			want:   false,
		},
		{name: "network unreachable", output: "", want: false},
		{name: "other interface", output: "192.168.50.130 dev eth0 src 172.20.0.6", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := routeDirectOnEth1(tt.output)
			if got != tt.want {
				t.Fatalf("routeDirectOnEth1(%q) = %t, want %t", tt.output, got, tt.want)
			}
		})
	}
}
