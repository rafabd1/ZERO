package probe

import "testing"

func TestBuildHTTPXArgsIncludesRequestPolicy(t *testing.T) {
	args := buildHTTPXArgs(4, 20)
	assertArgPair(t, args, "-timeout", "4")
	assertArgPair(t, args, "-threads", "20")
	assertContains(t, args, "-json")
	assertContains(t, args, "-tech-detect")
}

func assertArgPair(t *testing.T, args []string, name, value string) {
	t.Helper()
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name && args[i+1] == value {
			return
		}
	}
	t.Fatalf("args %#v do not include %s %s", args, name, value)
}

func assertContains(t *testing.T, args []string, want string) {
	t.Helper()
	for _, arg := range args {
		if arg == want {
			return
		}
	}
	t.Fatalf("args %#v do not include %s", args, want)
}
