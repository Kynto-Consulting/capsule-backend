package service

import "testing"

func TestHeldHostPortsIPv6Lines(t *testing.T) {
	out := "3000/tcp -> 0.0.0.0:20123\n3000/tcp -> [::]:20123\n5432/tcp -> :::20124\n"
	got := heldHostPorts(out)
	if len(got) != 2 || !got[20123] || !got[20124] {
		t.Fatalf("%v", got)
	}
}
