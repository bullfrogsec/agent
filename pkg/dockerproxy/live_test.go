package dockerproxy

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The live test drives a REAL daemon through the proxy, as an unprivileged
// member of the docker group. The policy tests judge JSON; this one is the
// only thing that proves the socket takeover, the HTTP plumbing, and the
// streaming endpoints actually work against docker as shipped.
//
// It is destructive to the box's docker socket, so it runs only when asked:
//
//	sudo DOCKERPROXY_LIVE=1 DOCKERPROXY_USER=someone go test ./pkg/dockerproxy -run Live -v
func TestLiveProxyAgainstRealDaemon(t *testing.T) {
	if os.Getenv("DOCKERPROXY_LIVE") != "1" {
		t.Skip("set DOCKERPROXY_LIVE=1 (and run as root, with docker present) to run this")
	}
	user := os.Getenv("DOCKERPROXY_USER")
	if user == "" {
		t.Fatal("DOCKERPROXY_USER must name an unprivileged member of the docker group")
	}
	image := os.Getenv("DOCKERPROXY_IMAGE")
	if image == "" {
		image = "alpine/curl:8.7.1"
	}

	p, err := Start(DefaultSocket, t.Logf)
	if err != nil {
		t.Fatalf("starting the proxy: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Stop(); err != nil {
			t.Errorf("restoring the docker socket: %v", err)
		}
	})

	// Every command runs as the unprivileged user, through the socket the
	// proxy now owns — the same path a build step uses.
	run := func(args ...string) (string, error) {
		cmd := exec.Command("runuser", append([]string{"-u", user, "--", "docker"}, args...)...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// A container's OUTPUT has to come back, not just its exit status.
	// `docker run` collects stdout over a hijacked connection, which is the
	// one part of the API that stops being ordinary HTTP halfway through. A
	// proxy that mishandles it produces a container that ran, exited 0, and
	// printed nothing — which looks like a passing test and a broken build.
	t.Run("container output survives the proxy", func(t *testing.T) {
		out, err := run("run", "--rm", "--entrypoint", "sh", image, "-c", "echo hello-from-the-container")
		if err != nil {
			t.Fatalf("docker run failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "hello-from-the-container") {
			t.Errorf("the container's stdout was lost in the proxy; got %q", out)
		}
	})

	t.Run("ordinary use still works", func(t *testing.T) {
		for _, args := range [][]string{
			{"version", "--format", "{{.Server.Version}}"},
			{"ps"},
			{"run", "--rm", "-m", "64m", "--cap-drop", "ALL", "--entrypoint", "sh", image, "-c", "id"},
			{"volume", "create", "proxy-live-vol"},
			{"run", "--rm", "-v", "proxy-live-vol:/data", "--entrypoint", "sh", image, "-c", "touch /data/x && ls /data"},
			{"volume", "rm", "proxy-live-vol"},
		} {
			out, err := run(args...)
			if err != nil {
				t.Errorf("docker %s failed through the proxy: %v\n%s",
					strings.Join(args, " "), err, out)
			}
		}
	})

	t.Run("escalation is refused", func(t *testing.T) {
		marker := "/etc/sudoers.d/dockerproxy-live-poc"
		for name, args := range map[string][]string{
			"privileged host mount": {"run", "--rm", "--privileged", "-v", "/:/host", "--entrypoint", "sh", image, "-c", "echo x > /host" + marker},
			"single directory bind": {"run", "--rm", "-v", "/etc/sudoers.d:/t", "--entrypoint", "sh", image, "-c", "echo x > /t/dockerproxy-live-poc"},
			"host network":          {"run", "--rm", "--net=host", "--entrypoint", "sh", image, "-c", "true"},
			"added capability":      {"run", "--rm", "--cap-add", "SYS_ADMIN", "--entrypoint", "sh", image, "-c", "true"},
			"host pid namespace":    {"run", "--rm", "--pid=host", "--entrypoint", "sh", image, "-c", "true"},
			"unconfined seccomp":    {"run", "--rm", "--security-opt", "seccomp=unconfined", "--entrypoint", "sh", image, "-c", "true"},
			"host device":           {"run", "--rm", "--device", "/dev/sda", "--entrypoint", "sh", image, "-c", "true"},
			"bind-backed volume":    {"volume", "create", "-d", "local", "-o", "type=none", "-o", "device=/etc/sudoers.d", "-o", "o=bind", "proxy-live-bad"},
			"macvlan network":       {"network", "create", "-d", "macvlan", "-o", "parent=eth0", "proxy-live-net"},
		} {
			out, err := run(args...)
			if err == nil {
				t.Errorf("%s SUCCEEDED through the proxy — this is a bypass\n%s", name, out)
				continue
			}
			if !strings.Contains(out, "bullfrog") {
				t.Errorf("%s was refused, but not by the policy (no reason given to the user):\n%s", name, out)
			}
		}
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("%s was written: the escalation landed despite the denial", marker)
			_ = os.Remove(marker)
		}
		if _, err := os.Stat("/etc/sudoers.d/dockerproxy-live-poc"); err == nil {
			t.Error("/etc/sudoers.d/dockerproxy-live-poc was written: the escalation landed despite the denial")
			_ = os.Remove("/etc/sudoers.d/dockerproxy-live-poc")
		}
	})

	// The daemon accepts any run of digits and dots as an API version, so a
	// request can be spelled in ways a narrower version-strip does not
	// recognise while the daemon still routes it to the same endpoint. Both
	// sides have to agree, and the only way to know they do is to ask a real
	// daemon.
	t.Run("versioned paths are judged the same as unversioned ones", func(t *testing.T) {
		body := `{"Image":"` + image + `","HostConfig":{"Privileged":true,"Binds":["/:/host"]}}`
		for _, prefix := range []string{"", "/v1.51", "/v1.51.0", "/v1.51.", "/v1"} {
			cmd := exec.Command("runuser", "-u", user, "--",
				"curl", "-sS", "--unix-socket", DefaultSocket,
				"-H", "Content-Type: application/json", "-X", "POST", "-d", body,
				"http://docker"+prefix+"/containers/create")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("curl %s: %v\n%s", prefix, err, out)
			}
			if !strings.Contains(string(out), "bullfrog") {
				t.Errorf("BYPASS: %s/containers/create was not judged by the policy: %s", prefix, out)
			}
		}
	})

	// Moving the daemon's socket aside is not hiding it. The rename preserves
	// the inode, so unless its permissions are changed the file keeps the
	// group access it had, and `docker -H unix://<real socket>` reaches the
	// unfiltered daemon directly — the filter becomes advisory.
	t.Run("the daemon's real socket is unreachable by the group", func(t *testing.T) {
		out, err := run("-H", "unix://"+p.RealPath, "run", "--rm", "--privileged",
			"-v", "/:/host", "--entrypoint", "sh", image, "-c", "echo x > /host/tmp/proxy-bypass-poc")
		if err == nil {
			t.Errorf("BYPASS: the real socket is still reachable, so the filter can be walked around\n%s", out)
		}
		if _, serr := os.Stat("/tmp/proxy-bypass-poc"); serr == nil {
			t.Error("BYPASS: a privileged container wrote to the host through the real socket")
			_ = os.Remove("/tmp/proxy-bypass-poc")
		}
	})

	// A filter that only judged the FIRST request on a connection would be
	// bypassed by sending a harmless one first. Docker clients re-use
	// connections constantly, so this is the ordinary path, not an exotic
	// one. curl with two URLs re-uses the connection for the second.
	t.Run("every request on a re-used connection is judged", func(t *testing.T) {
		body := `{"Image":"` + image + `","HostConfig":{"Privileged":true}}`
		cmd := exec.Command("runuser", "-u", user, "--",
			"curl", "-s", "--unix-socket", DefaultSocket,
			"http://d/_ping",
			"-X", "POST", "-H", "Content-Type: application/json",
			"-d", body, "http://d/containers/create")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("curl: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "bullfrog") {
			t.Errorf("the second request on a re-used connection was not judged by the policy: %s", out)
		}
	})
}
