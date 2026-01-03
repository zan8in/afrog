package portscan

import (
	"reflect"
	"strconv"
	"testing"
)

func TestBuildStagePortsMutuallyExclusiveAndCoverAll(t *testing.T) {
	s1, s2, s3, s4 := BuildStagePorts(nil)

	seen := make(map[int]string, 65535)
	add := func(label string, ports []int) {
		for _, p := range ports {
			if !isValidPort(p) {
				t.Fatalf("invalid port in %s: %d", label, p)
			}
			if prev, ok := seen[p]; ok {
				t.Fatalf("port %d appears in both %s and %s", p, prev, label)
			}
			seen[p] = label
		}
	}

	add("s1", s1)
	add("s2", s2)
	add("s3", s3)
	add("s4", s4)

	if len(seen) != 65535 {
		t.Fatalf("union size mismatch: got=%d want=%d", len(seen), 65535)
	}
	for p := 1; p <= 65535; p++ {
		if _, ok := seen[p]; !ok {
			t.Fatalf("missing port in union: %d", p)
		}
	}
}

func TestChunkPorts(t *testing.T) {
	in := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	got := ChunkPorts(in, 3)
	want := [][]int{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}, {10}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chunk mismatch: got=%v want=%v", got, want)
	}

	got2 := ChunkPorts(in, 0)
	want2 := [][]int{in}
	if !reflect.DeepEqual(got2, want2) {
		t.Fatalf("chunk mismatch (size=0): got=%v want=%v", got2, want2)
	}
}

func TestS3Parts(t *testing.T) {
	_, _, s3Parts, _ := buildStagePortsWithS3Parts(nil)
	if len(s3Parts) != 6 {
		t.Fatalf("s3 parts mismatch: got=%d want=%d", len(s3Parts), 6)
	}

	_, _, s3, _ := BuildStagePorts(nil)
	flat := make([]int, 0, len(s3))
	for _, part := range s3Parts {
		flat = append(flat, part...)
	}
	if !reflect.DeepEqual(flat, s3) {
		t.Fatalf("s3 parts flatten mismatch: got=%d want=%d", len(flat), len(s3))
	}

	for i := 1; i <= 6; i++ {
		iter, err := NewPortIterator("s3-" + strconv.Itoa(i))
		if err != nil {
			t.Fatalf("NewPortIterator s3-%d error: %v", i, err)
		}
		if iter.Total() != len(s3Parts[i-1]) {
			t.Fatalf("s3-%d total mismatch: got=%d want=%d", i, iter.Total(), len(s3Parts[i-1]))
		}
	}
}
