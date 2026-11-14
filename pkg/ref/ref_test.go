package ref

import "testing"

func TestMakeIsStableAndDistinct(t *testing.T) {
	a := Make(KindEvidence, "sha256:abc")
	b := Make(KindEvidence, "sha256:abc")
	if a != b {
		t.Fatalf("same canonical must produce same id: %q != %q", a, b)
	}
	if a == Make(KindEvidence, "sha256:abd") {
		t.Fatal("different canonical must produce different id")
	}
	if a == Make(KindFinding, "sha256:abc") {
		t.Fatal("different kind must produce different id")
	}
	if len(a) != len("evd_")+shortLen {
		t.Fatalf("unexpected id length: %q", a)
	}
}

func TestDigestPrefix(t *testing.T) {
	d := Digest("x")
	if len(d) != len("sha256:")+64 || d[:7] != "sha256:" {
		t.Fatalf("unexpected digest: %q", d)
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"HTTP://Example.COM:80/a/b/?x=1#f", "http://example.com/a/b"},
		{"https://example.com:443/", "https://example.com/"},
		{"https://example.com:8443/a/", "https://example.com:8443/a"},
		{"http://[::1]:8080/x?y=1", "http://[::1]:8080/x"},
	}
	for _, c := range cases {
		got, err := NormalizeEndpoint(c.in)
		if err != nil {
			t.Fatalf("NormalizeEndpoint(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("NormalizeEndpoint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeEndpointRejectsRelative(t *testing.T) {
	if _, err := NormalizeEndpoint("/a/b"); err == nil {
		t.Fatal("relative url must be rejected")
	}
}

func TestEndpoint(t *testing.T) {
	if Endpoint("/a") != "" {
		t.Fatal("relative url must map to empty id")
	}
	if Endpoint("http://a.com/x") != Endpoint("HTTP://A.COM:80/x#y") {
		t.Fatal("equivalent urls must map to the same endpoint id")
	}
}
