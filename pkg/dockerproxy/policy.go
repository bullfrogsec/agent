// Package dockerproxy puts a filtering proxy in front of the Docker daemon
// socket, so a job can keep using Docker while --enable-sudo=false holds.
//
// The daemon's API is root-equivalent by design: it runs as root and does what
// a client asks. Access to its socket is therefore access to root unless the
// requests themselves are judged, and judging them at the CLI is not a control
// at all — anything can talk to the socket directly with an HTTP client.
//
// The policy below is written as an ALLOW-LIST over request fields. Every
// field of a container's HostConfig must be recognised and cleared; a field
// this code has never heard of is a denial, not a pass. Docker adds fields
// over time, and a blocklist silently stops covering the API the day it does.
package dockerproxy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// Decision is the verdict on one request.
type Decision struct {
	Allow bool
	// Reason is shown to the user, verbatim, as the daemon's error message. It
	// is the only explanation they get for a failed command, so it names the
	// field that caused the denial.
	Reason string
}

var allow = Decision{Allow: true}

func deny(format string, a ...any) Decision {
	return Decision{Reason: fmt.Sprintf(format, a...)}
}

// Inspector answers questions about state that already exists in the daemon.
//
// Some denials cannot be made from the request alone. A container asking for a
// named volume is harmless or a full host mount depending on how that volume
// was created, and only the daemon knows which.
type Inspector interface {
	VolumeOptions(name string) (map[string]string, error)
	ContainerHostConfig(id string) (json.RawMessage, error)
}

// Policy judges one request at a time.
type Policy struct {
	Inspect Inspector
}

// apiVersion matches the version prefix docker clients put on every path.
//
// It has to accept exactly what the DAEMON accepts, which is looser than it
// looks: moby registers every route under "/v{version:[0-9.]+}", so any run of
// digits and dots is a version to it. Matching a narrower shape here and
// stripping only part of the prefix is an authorization bypass, not a cosmetic
// difference — "/v1.51.0/containers/create" would leave ".0/containers/create",
// which matches no rule below and sails through to a daemon that routes it
// straight to POST /containers/create.
var apiVersion = regexp.MustCompile(`^/v[0-9.]+(/|$)`)

// containerPath pulls the id out of /containers/<id>/<verb>.
var containerPath = regexp.MustCompile(`^/containers/([^/]+)/(.+)$`)

// normalizePath strips the API version prefix the way the daemon does, and
// reports whether what is left can be judged at all.
//
// Every place that decides something from the path MUST go through this, or
// the two decisions drift apart and the gap between them is the bypass.
func normalizePath(path string) (string, bool) {
	if m := apiVersion.FindString(path); m != "" {
		path = path[len(m)-1:] // keep the "/" the match ended on
		if path == "" {
			path = "/"
		}
	}
	// Fail closed rather than guess. A path that is not rooted, or that still
	// leads with something version-shaped, is not one this policy understands.
	if !strings.HasPrefix(path, "/") || apiVersion.MatchString(path) {
		return "", false
	}
	return path, true
}

// Evaluate decides whether a request may reach the daemon.
//
// body is nil for endpoints whose bodies are not inspected — image pushes and
// build contexts are gigabytes and carry nothing this policy reads.
func (p *Policy) Evaluate(method, path, rawQuery string, body []byte) Decision {
	path, ok := normalizePath(path)
	if !ok {
		return deny("this request's path is not one bullfrog can judge, so it is refused while sudo is disabled")
	}

	// Endpoints that hand out host privileges by their nature, with no field
	// to inspect. Plugins run with host capabilities and can mount the host
	// filesystem; swarm turns any node into a scheduler for containers this
	// policy never sees.
	for _, prefix := range []string{"/plugins", "/swarm", "/nodes", "/services", "/tasks", "/secrets", "/configs"} {
		if strings.HasPrefix(path, prefix) {
			return deny("%s is disabled while sudo is disabled: it grants host privileges the egress policy cannot contain", prefix)
		}
	}

	switch {
	case method == "POST" && path == "/containers/create":
		return p.containerCreate(body)
	case method == "POST" && path == "/volumes/create":
		return volumeCreate(body)
	case method == "POST" && path == "/networks/create":
		return networkCreate(body)
	case method == "POST" && path == "/build":
		return buildDecision(rawQuery)
	}

	if m := containerPath.FindStringSubmatch(path); m != nil {
		id, verb := m[1], m[2]
		switch {
		// An exec runs in a container that already exists, so its privileges
		// are that container's. A container created before the agent started
		// — a service container, or one from an earlier step — may hold
		// everything this policy refuses to grant.
		case method == "POST" && verb == "exec":
			return p.exec(id, body)
		// Writing into a container writes through its mounts, which is a host
		// write if any of them is a bind.
		case method == "PUT" && verb == "archive":
			return p.existingContainer(id, "writing files into")
		}
	}

	// Everything else is reading, starting, stopping, and removing things
	// whose configuration was already judged when they were created.
	return allow
}

// containerCreate is the main event: this is where privilege is requested.
func (p *Policy) containerCreate(body []byte) Decision {
	var req struct {
		HostConfig json.RawMessage `json:"HostConfig"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return deny("the container definition could not be parsed, so it cannot be cleared: %v", err)
		}
	}
	if len(req.HostConfig) == 0 {
		// No HostConfig at all is a plain container with default privileges.
		return allow
	}
	return p.hostConfig(req.HostConfig)
}

// hostConfigSafe are the fields that grant nothing. Anything not listed here
// and not handled by hostConfig's switch is refused, so a field added by a
// future API version fails closed instead of sailing through.
var hostConfigSafe = map[string]bool{
	// Plumbing.
	"ContainerIDFile": true, "LogConfig": true, "PortBindings": true,
	"RestartPolicy": true, "AutoRemove": true, "PublishAllPorts": true,
	"ReadonlyRootfs": true, "Dns": true, "DnsOptions": true, "DnsSearch": true,
	"ExtraHosts": true, "GroupAdd": true, "Links": true, "OomScoreAdj": true,
	"ShmSize": true, "Tmpfs": true, "StorageOpt": true, "ConsoleSize": true,
	"Isolation": true, "Init": true, "CapDrop": true, "NetworkingConfig": true,

	// Resource limits. These throttle, they do not grant. The Blkio device
	// entries name host devices but only to rate-limit them.
	"CpuShares": true, "Memory": true, "NanoCpus": true, "BlkioWeight": true,
	"BlkioWeightDevice": true, "BlkioDeviceReadBps": true, "BlkioDeviceWriteBps": true,
	"BlkioDeviceReadIOps": true, "BlkioDeviceWriteIOps": true, "CpuPeriod": true,
	"CpuQuota": true, "CpuRealtimePeriod": true, "CpuRealtimeRuntime": true,
	"CpusetCpus": true, "CpusetMems": true, "DiskQuota": true,
	"KernelMemory": true, "KernelMemoryTCP": true, "MemoryReservation": true,
	"MemorySwap": true, "MemorySwappiness": true, "OomKillDisable": true,
	"PidsLimit": true, "Ulimits": true, "CpuCount": true, "CpuPercent": true,
	"IOMaximumIOps": true, "IOMaximumBandwidth": true,
}

// maskedPathsRequired and readonlyPathsRequired are the entries under /proc and
// /sys that a container must not be able to see or write. Losing one of them
// is an escape rather than a tweak: with /proc/sys writable, root in a
// container writes /proc/sys/kernel/core_pattern, which is host-global, and
// /proc/kcore is the host's memory.
//
// They are judged as a MINIMUM the request has to cover, not as an exact list.
// A container's HostConfig read back from the daemon always carries the
// daemon's own defaults, so an exact match would refuse every container that
// already exists, and would refuse a newer daemon that masks one more path.
// Extra entries only tighten.
var maskedPathsRequired = []string{
	"/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
	"/proc/sched_debug", "/proc/scsi", "/proc/timer_list", "/sys/firmware",
}

var readonlyPathsRequired = []string{
	"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
}

func requiredPaths(field string, val json.RawMessage, required []string) Decision {
	var list []string
	if err := json.Unmarshal(val, &list); err != nil {
		return deny("HostConfig.%s could not be parsed: %v", field, err)
	}
	have := make(map[string]bool, len(list))
	for _, entry := range list {
		have[path.Clean(entry)] = true
	}
	for _, want := range required {
		if !have[want] {
			return deny("HostConfig.%s does not cover %s, so it is refused while sudo is disabled: those masks are what keep host-global kernel knobs out of the container", field, want)
		}
	}
	return allow
}

func (p *Policy) hostConfig(raw json.RawMessage) Decision {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return deny("the container's HostConfig could not be parsed, so it cannot be cleared: %v", err)
	}

	for key, val := range fields {
		if isNull(val) || hostConfigSafe[key] {
			continue
		}
		switch key {
		case "Privileged":
			if truthy(val) {
				return deny("--privileged is not allowed while sudo is disabled: it is root on the host")
			}

		// Namespaces shared with the host. Any of them puts the container in
		// the host's view of something: --net=host in particular hands the
		// container CAP_NET_RAW in the HOST network namespace, which is the
		// raw-socket path around the egress filter that --enable-sudo=false
		// exists to close.
		case "NetworkMode":
			if s := str(val); s == "host" || strings.HasPrefix(s, "container:") {
				return deny("--network=%s is not allowed while sudo is disabled: it puts the container in a network namespace the egress filter does not judge", s)
			}
		case "PidMode", "IpcMode", "UTSMode", "CgroupnsMode", "UsernsMode":
			if s := str(val); s == "host" || strings.HasPrefix(s, "container:") {
				return deny("%s=%s is not allowed while sudo is disabled: sharing that namespace with the host is a path to root", key, s)
			}

		// Capabilities, devices and runtimes: each is a direct grant.
		case "CapAdd":
			if !emptyList(val) {
				return deny("--cap-add is not allowed while sudo is disabled: SYS_ADMIN, SYS_MODULE, SYS_PTRACE and NET_RAW are each enough to leave the container")
			}
		case "Devices", "DeviceCgroupRules", "DeviceRequests":
			if !emptyList(val) {
				return deny("--device is not allowed while sudo is disabled: a host disk device is the host filesystem")
			}
		case "Runtime":
			if s := str(val); s != "" && s != "runc" {
				return deny("--runtime=%s is not allowed while sudo is disabled: only the default runtime is judged by this policy", s)
			}
		case "Sysctls":
			if !emptyMap(val) {
				return deny("--sysctl is not allowed while sudo is disabled")
			}
		case "CgroupParent", "Cgroup":
			if str(val) != "" {
				return deny("%s is not allowed while sudo is disabled: joining an existing cgroup escapes the container's limits", key)
			}
		case "SecurityOpt":
			if d := securityOpt(val); !d.Allow {
				return d
			}
		case "MaskedPaths":
			if d := requiredPaths(key, val, maskedPathsRequired); !d.Allow {
				return d
			}
		case "ReadonlyPaths":
			if d := requiredPaths(key, val, readonlyPathsRequired); !d.Allow {
				return d
			}

		case "Annotations":
			if !emptyMap(val) {
				return deny("container annotations are not allowed while sudo is disabled: they are passed to the runtime unread")
			}

		// Anything that can name a host path.
		case "Binds":
			if d := p.binds(val); !d.Allow {
				return d
			}
		case "Mounts":
			if d := p.mounts(val); !d.Allow {
				return d
			}
		case "VolumeDriver":
			if s := str(val); s != "" && s != "local" {
				return deny("--volume-driver=%s is not allowed while sudo is disabled: volume plugins run on the host", s)
			}
		case "VolumesFrom":
			if !emptyList(val) {
				return deny("--volumes-from is not allowed while sudo is disabled: it inherits mounts this policy never saw")
			}

		default:
			// The allow-list doing its job. A new field is refused until
			// someone has decided what it grants.
			return deny("HostConfig.%s is not recognised by this policy, so it is refused while sudo is disabled", key)
		}
	}
	return allow
}

// binds judges the -v form, where a host path and a named volume are the same
// syntax and told apart only by the leading slash.
func (p *Policy) binds(val json.RawMessage) Decision {
	var list []string
	if err := json.Unmarshal(val, &list); err != nil {
		return deny("HostConfig.Binds could not be parsed: %v", err)
	}
	for _, b := range list {
		src := b
		if i := strings.Index(b, ":"); i >= 0 {
			src = b[:i]
		}
		if strings.HasPrefix(src, "/") || strings.HasPrefix(src, "~") || strings.HasPrefix(src, ".") {
			return deny("mounting the host path %s is not allowed while sudo is disabled: the daemon writes it as root", src)
		}
		if d := p.namedVolume(src); !d.Allow {
			return d
		}
	}
	return allow
}

func (p *Policy) mounts(val json.RawMessage) Decision {
	var list []struct {
		Type          string `json:"Type"`
		Source        string `json:"Source"`
		VolumeOptions *struct {
			DriverConfig *struct {
				Name    string            `json:"Name"`
				Options map[string]string `json:"Options"`
			} `json:"DriverConfig"`
		} `json:"VolumeOptions"`
	}
	if err := json.Unmarshal(val, &list); err != nil {
		return deny("HostConfig.Mounts could not be parsed: %v", err)
	}
	for _, m := range list {
		switch strings.ToLower(m.Type) {
		case "tmpfs":
		case "volume":
			if vo := m.VolumeOptions; vo != nil && vo.DriverConfig != nil {
				if d := driverOptions(m.Source, vo.DriverConfig.Name, vo.DriverConfig.Options); !d.Allow {
					return d
				}
			}
			if d := p.namedVolume(m.Source); !d.Allow {
				return d
			}
		default:
			// bind, npipe, cluster, and anything new.
			return deny("--mount type=%s is not allowed while sudo is disabled: it reaches the host filesystem", m.Type)
		}
	}
	return allow
}

// namedVolume closes the bypass that defeats naive bind-mount filtering: the
// local volume driver takes a host path as a device option, so a volume can BE
// a bind mount under another name. Whether it is one is known only to the
// daemon, which is why this asks.
func (p *Policy) namedVolume(name string) Decision {
	if name == "" || p.Inspect == nil {
		return allow
	}
	opts, err := p.Inspect.VolumeOptions(name)
	if err != nil {
		// A volume that does not exist yet is created empty under the
		// daemon's own data root, which is not a host path of the caller's
		// choosing.
		return allow
	}
	return driverOptions(name, "local", opts)
}

func driverOptions(name, driver string, opts map[string]string) Decision {
	if driver != "" && driver != "local" {
		return deny("volume %q uses the %q driver, which is a plugin running on the host", name, driver)
	}
	// Checked in a fixed order, not by ranging the map: which of these fires
	// decides the message the user sees, and a message that changes between
	// identical runs is one nobody can act on or test against.
	for k, v := range opts {
		if strings.EqualFold(k, "device") {
			return deny("volume %q is backed by the host path %q, which is a bind mount under another name", name, v)
		}
	}
	for k, v := range opts {
		if strings.EqualFold(k, "o") && strings.Contains(strings.ToLower(v), "bind") {
			return deny("volume %q is declared as a bind mount, which reaches the host filesystem", name)
		}
	}
	return allow
}

func securityOpt(val json.RawMessage) Decision {
	var list []string
	if err := json.Unmarshal(val, &list); err != nil {
		return deny("HostConfig.SecurityOpt could not be parsed: %v", err)
	}
	for _, o := range list {
		// Tightening is fine; loosening is the whole point of the field.
		if strings.HasPrefix(o, "no-new-privileges") || strings.HasPrefix(o, "label=") {
			continue
		}
		return deny("--security-opt %s is not allowed while sudo is disabled: seccomp and AppArmor are what keep a container in", o)
	}
	return allow
}

// volumeCreate stops the bind-backed volume from being created at all, so the
// denial lands on the command that asked for it rather than on an unrelated
// `docker run` later.
func volumeCreate(body []byte) Decision {
	var req struct {
		Name       string            `json:"Name"`
		Driver     string            `json:"Driver"`
		DriverOpts map[string]string `json:"DriverOpts"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return deny("the volume definition could not be parsed: %v", err)
		}
	}
	return driverOptions(req.Name, req.Driver, req.DriverOpts)
}

// networkCreate refuses the drivers that attach a container straight to a host
// interface. Their traffic never crosses the bridge the egress rules watch.
func networkCreate(body []byte) Decision {
	var req struct {
		Name    string            `json:"Name"`
		Driver  string            `json:"Driver"`
		Options map[string]string `json:"Options"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return deny("the network definition could not be parsed: %v", err)
		}
	}
	switch strings.ToLower(req.Driver) {
	case "", "bridge", "null", "none":
	default:
		return deny("the %q network driver is not allowed while sudo is disabled: it attaches containers to a host interface, where their traffic is never judged", req.Driver)
	}
	if _, ok := req.Options["parent"]; ok {
		return deny("a network bound to a host interface is not allowed while sudo is disabled")
	}
	return allow
}

// networkName is a plain user-defined network, which is a bridge and is fine.
var networkName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

// buildDecision judges a build by its query string: the body is the build
// context, which can be gigabytes and is never read here.
//
// The query is PARSED, never substring-matched. The daemon reads this value
// with r.FormValue, which percent-decodes it, so "networkmode=%68ost" is
// "host" to the daemon and something else entirely to a substring check —
// the two sides disagreeing is the bypass.
func buildDecision(rawQuery string) Decision {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return deny("the build's query string could not be parsed, so it cannot be cleared: %v", err)
	}
	mode := strings.ToLower(strings.TrimSpace(q.Get("networkmode")))
	switch {
	case mode == "", mode == "default", mode == "bridge", mode == "none":
		return allow
	case mode == "host":
		// Every RUN step would run in the host network namespace as root,
		// with CAP_NET_RAW: the raw-socket path around the egress filter.
		return deny("building with --network=host is not allowed while sudo is disabled")
	case strings.HasPrefix(mode, "container:"):
		return deny("building with --network=%s is not allowed while sudo is disabled: it joins a network namespace this policy never judged", mode)
	case networkName.MatchString(mode):
		return allow
	}
	return deny("the build network %q is not recognised by this policy, so it is refused while sudo is disabled", mode)
}

// exec applies the target container's own privileges to the request, and
// refuses an exec that asks for more on top.
func (p *Policy) exec(id string, body []byte) Decision {
	var req struct {
		Privileged bool `json:"Privileged"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return deny("the exec definition could not be parsed: %v", err)
		}
	}
	if req.Privileged {
		return deny("docker exec --privileged is not allowed while sudo is disabled")
	}
	return p.existingContainer(id, "running commands in")
}

// existingContainer re-judges a container that already exists. A container
// created before the agent started was never seen by this policy, and may hold
// everything it refuses to grant.
func (p *Policy) existingContainer(id, action string) Decision {
	if p.Inspect == nil {
		return allow
	}
	hc, err := p.Inspect.ContainerHostConfig(id)
	if err != nil {
		// Let the daemon produce its own "no such container" rather than
		// inventing one here.
		return allow
	}
	if d := p.hostConfig(hc); !d.Allow {
		return deny("%s container %s is not allowed while sudo is disabled: %s", action, id, d.Reason)
	}
	return allow
}

func isNull(v json.RawMessage) bool { return len(v) == 0 || string(v) == "null" }

func truthy(v json.RawMessage) bool {
	var b bool
	return json.Unmarshal(v, &b) == nil && b
}

func str(v json.RawMessage) string {
	var s string
	_ = json.Unmarshal(v, &s)
	return s
}

func emptyList(v json.RawMessage) bool {
	var l []json.RawMessage
	return json.Unmarshal(v, &l) == nil && len(l) == 0
}

func emptyMap(v json.RawMessage) bool {
	var m map[string]json.RawMessage
	return json.Unmarshal(v, &m) == nil && len(m) == 0
}
