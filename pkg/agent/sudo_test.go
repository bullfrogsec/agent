package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// The socket permissions are the part of --enable-sudo=false that stops a step
// from becoming root through the docker group; see revokeDockerAccess.
func TestRevokeDockerAccessRestrictsTheSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chowning to root needs root")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "docker.sock")
	if err := os.WriteFile(sock, nil, 0o660); err != nil {
		t.Fatal(err)
	}
	swapSockets(t, sock)

	if err := revokeDockerAccess(); err != nil {
		t.Fatalf("revokeDockerAccess: %v", err)
	}
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("socket mode is %04o, want 0600 — the docker group can still reach the daemon, which is root", got)
	}
}

// A box without Docker is not an error: the agent must still start.
func TestRevokeDockerAccessIgnoresAMissingSocket(t *testing.T) {
	swapSockets(t, filepath.Join(t.TempDir(), "docker.sock"))
	if err := revokeDockerAccess(); err != nil {
		t.Fatalf("revokeDockerAccess with no socket present: %v", err)
	}
}

func swapSockets(t *testing.T, paths ...string) {
	t.Helper()
	orig := dockerSockets
	t.Cleanup(func() { dockerSockets = orig })
	dockerSockets = paths
}
