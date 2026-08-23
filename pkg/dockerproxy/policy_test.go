package dockerproxy

import (
	"encoding/json"
	"strings"
	"testing"
)

// stubInspector stands in for the daemon when the policy has to ask about
// state that already exists.
type stubInspector struct {
	volumes    map[string]map[string]string
	containers map[string]string
}

func (s stubInspector) VolumeOptions(name string) (map[string]string, error) {
	if o, ok := s.volumes[name]; ok {
		return o, nil
	}
	return nil, errNotFound
}

func (s stubInspector) ContainerHostConfig(id string) (json.RawMessage, error) {
	if c, ok := s.containers[id]; ok {
		return json.RawMessage(c), nil
	}
	return nil, errNotFound
}

var errNotFound = &notFound{}

type notFound struct{}

func (*notFound) Error() string { return "no such object" }

// The vectors below were each measured against a real daemon as an
// unprivileged docker-group user. Three of them need neither --privileged nor
// a mount of /, which is why this policy judges fields rather than flags.
func TestPolicyDeniesEscalation(t *testing.T) {
	inspect := stubInspector{
		volumes: map[string]map[string]string{
			"bindvol":  {"type": "none", "device": "/etc/sudoers.d", "o": "bind"},
			"plainvol": {},
		},
		containers: map[string]string{
			"privileged": `{"Privileged":true}`,
			"harmless":   `{"AutoRemove":true}`,
		},
	}
	p := &Policy{Inspect: inspect}

	cases := []struct {
		name           string
		method, path   string
		query          string
		body           string
		wantDenyReason string // substring
	}{
		{
			name: "privileged container", method: "POST", path: "/v1.44/containers/create",
			body:           `{"Image":"alpine","HostConfig":{"Privileged":true}}`,
			wantDenyReason: "--privileged",
		},
		{
			// The reported proof of concept.
			name: "host root bind mount", method: "POST", path: "/containers/create",
			body:           `{"Image":"alpine","HostConfig":{"Binds":["/:/host"]}}`,
			wantDenyReason: "mounting the host path /",
		},
		{
			// Measured: needs no --privileged and no mount of /.
			name: "one directory is enough", method: "POST", path: "/containers/create",
			body:           `{"Image":"alpine","HostConfig":{"Binds":["/etc/sudoers.d:/target"]}}`,
			wantDenyReason: "/etc/sudoers.d",
		},
		{
			name: "bind by --mount syntax", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/etc","Target":"/x"}]}}`,
			wantDenyReason: "type=bind",
		},
		{
			// Measured: defeats a filter that only looks at Binds.
			name: "bind-backed named volume", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"Binds":["bindvol:/target"]}}`,
			wantDenyReason: "bind mount under another name",
		},
		{
			name: "creating the bind-backed volume", method: "POST", path: "/volumes/create",
			body:           `{"Name":"v","Driver":"local","DriverOpts":{"type":"none","device":"/","o":"bind"}}`,
			wantDenyReason: "backed by the host path",
		},
		{
			// Measured: CAP_NET_RAW in the host network namespace, which is
			// the raw-socket bypass --enable-sudo=false exists to close.
			name: "host network namespace", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"NetworkMode":"host"}}`,
			wantDenyReason: "--network=host",
		},
		{
			name: "joining another container's namespace", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"NetworkMode":"container:abc"}}`,
			wantDenyReason: "network namespace",
		},
		{
			name: "added capabilities", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"CapAdd":["SYS_MODULE"]}}`,
			wantDenyReason: "--cap-add",
		},
		{
			name: "host disk device", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"Devices":[{"PathOnHost":"/dev/sda"}]}}`,
			wantDenyReason: "--device",
		},
		{
			name: "unconfined seccomp", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`,
			wantDenyReason: "--security-opt",
		},
		{
			name: "host pid namespace", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"PidMode":"host"}}`,
			wantDenyReason: "PidMode=host",
		},
		{
			// Emptying the masks makes /proc/sys writable, and
			// /proc/sys/kernel/core_pattern is host-global.
			name: "unmasked proc", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"MaskedPaths":[]}}`,
			wantDenyReason: "MaskedPaths",
		},
		{
			name: "volume plugin", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"VolumeDriver":"some-plugin"}}`,
			wantDenyReason: "--volume-driver",
		},
		{
			name: "inherited mounts", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"VolumesFrom":["other"]}}`,
			wantDenyReason: "--volumes-from",
		},
		{
			name: "custom runtime", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"Runtime":"sysbox-runc"}}`,
			wantDenyReason: "--runtime",
		},
		{
			name: "cgroup parent", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"CgroupParent":"/somewhere"}}`,
			wantDenyReason: "CgroupParent",
		},
		{
			name: "plugin install", method: "POST", path: "/v1.44/plugins/pull",
			wantDenyReason: "/plugins is disabled",
		},
		{
			name: "swarm init", method: "POST", path: "/swarm/init",
			wantDenyReason: "/swarm is disabled",
		},
		{
			name: "macvlan network", method: "POST", path: "/networks/create",
			body:           `{"Name":"n","Driver":"macvlan","Options":{"parent":"eth0"}}`,
			wantDenyReason: "macvlan",
		},
		{
			name: "build in the host network", method: "POST", path: "/build",
			query:          "networkmode=host&t=x",
			wantDenyReason: "--network=host",
		},
		{
			name: "privileged exec", method: "POST", path: "/containers/harmless/exec",
			body:           `{"Privileged":true,"Cmd":["sh"]}`,
			wantDenyReason: "exec --privileged",
		},
		{
			// A container that predates the agent was never judged, and may
			// hold everything this policy refuses to grant.
			name: "exec into a pre-existing privileged container", method: "POST", path: "/containers/privileged/exec",
			body:           `{"Cmd":["sh"]}`,
			wantDenyReason: "running commands in container privileged",
		},
		{
			name: "writing into a pre-existing privileged container", method: "PUT", path: "/containers/privileged/archive",
			wantDenyReason: "writing files into container privileged",
		},
		{
			// The daemon routes any run of digits and dots as a version, so a
			// policy that strips a narrower shape leaves a remainder it does
			// not recognise and forwards a request the daemon DOES.
			name: "version with a patch component", method: "POST", path: "/v1.51.0/containers/create",
			body:           `{"Image":"alpine","HostConfig":{"Privileged":true}}`,
			wantDenyReason: "--privileged",
		},
		{
			name: "version with a trailing dot", method: "POST", path: "/v1.51./containers/create",
			body:           `{"HostConfig":{"Binds":["/:/host"]}}`,
			wantDenyReason: "mounting the host path /",
		},
		{
			name: "major-only version", method: "POST", path: "/v1/containers/create",
			body:           `{"HostConfig":{"Privileged":true}}`,
			wantDenyReason: "--privileged",
		},
		{
			name: "versioned plugin install", method: "POST", path: "/v1.51.0/plugins/pull",
			wantDenyReason: "/plugins is disabled",
		},
		{
			name: "versioned exec into a privileged container", method: "POST", path: "/v1.51.0/containers/privileged/exec",
			body:           `{"Cmd":["sh"]}`,
			wantDenyReason: "running commands in container privileged",
		},
		{
			// The daemon percent-decodes this value; a substring match on the
			// raw query does not.
			name: "percent-encoded host network build", method: "POST", path: "/build",
			query:          "networkmode=%68ost&t=x",
			wantDenyReason: "--network=host",
		},
		{
			name: "build joining a container's namespace", method: "POST", path: "/build",
			query:          "networkmode=container:abc",
			wantDenyReason: "--network=container:abc",
		},
		{
			name: "build network this policy does not recognise", method: "POST", path: "/build",
			query:          "networkmode=some%20thing",
			wantDenyReason: "not recognised",
		},
		{
			// The allow-list doing its job: a field this policy has never
			// heard of is refused rather than passed through.
			name: "unknown HostConfig field", method: "POST", path: "/containers/create",
			body:           `{"HostConfig":{"SomeFutureEscapeHatch":true}}`,
			wantDenyReason: "not recognised by this policy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := p.Evaluate(tc.method, tc.path, tc.query, []byte(tc.body))
			if d.Allow {
				t.Fatalf("ALLOWED, expected a denial mentioning %q — this is a bypass of --enable-sudo=false", tc.wantDenyReason)
			}
			if !strings.Contains(d.Reason, tc.wantDenyReason) {
				t.Errorf("denied for %q, want a reason mentioning %q (the message is what the user sees)", d.Reason, tc.wantDenyReason)
			}
		})
	}
}

// The other direction, and the whole reason for a proxy rather than a
// lockdown: ordinary CI use of Docker has to keep working, or the filter is
// just a slower way of switching Docker off.
func TestPolicyAllowsOrdinaryUse(t *testing.T) {
	p := &Policy{Inspect: stubInspector{volumes: map[string]map[string]string{"plainvol": {}}}}

	cases := []struct {
		name         string
		method, path string
		query, body  string
	}{
		{name: "plain run", method: "POST", path: "/v1.44/containers/create",
			body: `{"Image":"alpine","Cmd":["true"],"HostConfig":{"AutoRemove":true}}`},
		{name: "no HostConfig at all", method: "POST", path: "/containers/create",
			body: `{"Image":"alpine"}`},
		{name: "published ports and restart policy", method: "POST", path: "/containers/create",
			body: `{"HostConfig":{"PortBindings":{"80/tcp":[{"HostPort":"8080"}]},"RestartPolicy":{"Name":"no"},"PublishAllPorts":true}}`},
		{name: "named volume", method: "POST", path: "/containers/create",
			body: `{"HostConfig":{"Binds":["plainvol:/data"]}}`},
		{name: "anonymous volume that does not exist yet", method: "POST", path: "/containers/create",
			body: `{"HostConfig":{"Binds":["brandnew:/data"]}}`},
		{name: "tmpfs mount", method: "POST", path: "/containers/create",
			body: `{"HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/scratch"}]}}`},
		{name: "resource limits", method: "POST", path: "/containers/create",
			body: `{"HostConfig":{"Memory":536870912,"NanoCpus":2000000000,"PidsLimit":100,"Ulimits":[{"Name":"nofile","Soft":1024,"Hard":2048}]}}`},
		{name: "dropped capabilities and read-only rootfs", method: "POST", path: "/containers/create",
			body: `{"HostConfig":{"CapDrop":["ALL"],"ReadonlyRootfs":true,"SecurityOpt":["no-new-privileges:true"]}}`},
		{name: "user-defined bridge network", method: "POST", path: "/networks/create",
			body: `{"Name":"compose_default","Driver":"bridge"}`},
		{name: "ordinary volume", method: "POST", path: "/volumes/create",
			body: `{"Name":"cache","Driver":"local"}`},
		{name: "image pull", method: "POST", path: "/images/create", query: "fromImage=alpine&tag=latest"},
		{name: "image build", method: "POST", path: "/build", query: "t=myimage&dockerfile=Dockerfile"},
		{name: "build on a user-defined network", method: "POST", path: "/build", query: "networkmode=compose_default&t=x"},
		{name: "build with no network", method: "POST", path: "/build", query: "networkmode=none"},
		{name: "versioned plain run", method: "POST", path: "/v1.51.0/containers/create",
			body: `{"Image":"alpine","HostConfig":{"AutoRemove":true}}`},
		{name: "versioned ping", method: "GET", path: "/v1.51.0/_ping"},
		{name: "start", method: "POST", path: "/containers/abc/start"},
		{name: "logs", method: "GET", path: "/containers/abc/logs?follow=1"},
		{name: "wait", method: "POST", path: "/containers/abc/wait"},
		{name: "remove", method: "DELETE", path: "/containers/abc"},
		{name: "version", method: "GET", path: "/version"},
		{name: "ping", method: "GET", path: "/_ping"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if d := p.Evaluate(tc.method, tc.path, tc.query, []byte(tc.body)); !d.Allow {
				t.Fatalf("DENIED ordinary usage: %s — a filter that blocks this is just a slower lockdown", d.Reason)
			}
		})
	}
}

// Docker's own API decodes JSON case-insensitively, so a client can write
// "hostconfig" or "privileged" and the daemon honours it. A policy that only
// matched the documented spelling would be bypassed by changing case.
func TestPolicyMatchesDockersOwnJSONCasing(t *testing.T) {
	p := &Policy{}
	d := p.Evaluate("POST", "/containers/create", "",
		[]byte(`{"image":"alpine","hostconfig":{"privileged":true}}`))
	if d.Allow {
		t.Fatal("ALLOWED a privileged container spelled in lower case — the daemon would have honoured it")
	}
}
