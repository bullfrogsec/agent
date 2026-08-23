package dockerproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// DefaultSocket is where every Docker client looks. On a GitHub runner
// /var/run is a symlink to /run, so this is the same file as /run/docker.sock.
const DefaultSocket = "/var/run/docker.sock"

// RealSocketSuffix names the daemon's socket after the proxy takes its place.
//
// The daemon is not restarted and does not learn about any of this: a
// listening unix socket is bound to its inode, not to its name, so renaming
// the file leaves every existing listener working and frees the well-known
// path for the proxy. Clients keep using DOCKER_HOST as they always did.
const RealSocketSuffix = ".bullfrog-real"

// ErrNoDocker means there is no daemon socket to protect.
var ErrNoDocker = errors.New("no docker socket present")

// Proxy is the filtering socket. It is created by Start and runs until the
// process exits.
type Proxy struct {
	// Path is the socket clients connect to, i.e. the daemon's usual one.
	Path string
	// RealPath is where the daemon's own socket was moved to.
	RealPath string

	// Log receives one line per denial. Denials are the whole point of this
	// component, so they are never silent.
	Log func(format string, a ...any)

	listener net.Listener
	server   *http.Server
	policy   *Policy

	// How the daemon's socket looked before any of this, so the proxy can
	// present the same face to clients and Stop can put it back.
	origUID, origGID int
	origMode         os.FileMode
}

// Start takes over the daemon socket and serves the filtered one.
//
// Ordering matters and is not reversible halfway: the real socket is renamed
// first, so there is never a moment when the well-known path is an unfiltered
// socket that a client could still reach. If anything after the rename fails,
// Start puts the original name back — a job with no Docker is a nuisance, one
// with unfiltered Docker is the vulnerability this exists to close.
func Start(socketPath string, logf func(string, ...any)) (*Proxy, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var st syscall.Stat_t
	if err := syscall.Stat(socketPath, &st); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoDocker
		}
		return nil, fmt.Errorf("%s: %w", socketPath, err)
	}

	real := realPath(socketPath)
	if _, err := os.Stat(real); err == nil {
		return nil, fmt.Errorf("%s already exists: a previous run did not clean up, and continuing would hide the daemon behind two proxies", real)
	}

	p := &Proxy{
		Path: socketPath, RealPath: real, Log: logf,
		origUID: int(st.Uid), origGID: int(st.Gid), origMode: os.FileMode(st.Mode & 0o7777),
	}

	// Take the daemon's socket to root-only BEFORE moving it.
	//
	// Renaming preserves the inode, and with it the group access the socket
	// had: a socket left at 0660 root:docker under a new name is reachable
	// with `docker -H unix://<new path>`, which walks around the filter
	// entirely. Doing it in this order also means there is no instant when a
	// group-accessible socket exists at a path an attacker could be waiting
	// on — during the changeover the daemon is reachable only by root.
	if err := os.Chown(socketPath, 0, 0); err != nil {
		return nil, fmt.Errorf("taking ownership of %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = p.restoreDaemonSocket(socketPath)
		return nil, fmt.Errorf("restricting %s: %w", socketPath, err)
	}
	if err := os.Rename(socketPath, real); err != nil {
		_ = p.restoreDaemonSocket(socketPath)
		return nil, fmt.Errorf("moving the daemon socket aside: %w", err)
	}

	if err := p.listen(&st); err != nil {
		// Undo everything: the daemon must not be left unreachable by a
		// failure to install the filter.
		if rerr := os.Rename(real, socketPath); rerr != nil {
			return nil, fmt.Errorf("%w (and the daemon socket could not be restored: %v)", err, rerr)
		}
		_ = p.restoreDaemonSocket(socketPath)
		return nil, err
	}
	go func() {
		if err := p.server.Serve(p.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logf("docker proxy stopped serving: %v", err)
		}
	}()
	return p, nil
}

func realPath(socketPath string) string {
	return filepath.Join(filepath.Dir(socketPath), filepath.Base(socketPath)+RealSocketSuffix)
}

// listen binds the well-known path and reproduces the ownership and mode the
// daemon's socket had, so the `docker` group reaches the proxy exactly as it
// reached the daemon.
func (p *Proxy) listen(orig *syscall.Stat_t) error {
	l, err := net.Listen("unix", p.Path)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", p.Path, err)
	}
	if err := os.Chown(p.Path, int(orig.Uid), int(orig.Gid)); err != nil {
		l.Close()
		return fmt.Errorf("setting ownership of %s: %w", p.Path, err)
	}
	if err := os.Chmod(p.Path, os.FileMode(orig.Mode&0o7777)); err != nil {
		l.Close()
		return fmt.Errorf("setting mode of %s: %w", p.Path, err)
	}

	// One dialer for both the reverse proxy and the policy's own lookups.
	dial := func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", p.RealPath)
	}
	transport := &http.Transport{DialContext: dial}
	p.policy = &Policy{Inspect: &daemonInspector{client: &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}}}

	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = "http"
			// The unix transport ignores the host, but net/http insists on
			// one being present.
			r.URL.Host = "docker"
		},
		Transport: transport,
		// Docker streams: build output, `logs -f`, and the raw stream an
		// attach or exec returns. Buffering any of those makes the client
		// look hung.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeDockerError(w, http.StatusBadGateway, fmt.Sprintf("bullfrog: the docker daemon could not be reached: %v", err))
		},
	}

	p.listener = l
	p.server = &http.Server{Handler: p.handler(rp)}
	return nil
}

// handler judges every request, including the second and third on a re-used
// connection. Docker clients keep connections alive, and a filter that only
// looked at the first request on each one would be bypassed by preceding the
// real request with a harmless one.
func (p *Proxy) handler(rp *httputil.ReverseProxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := p.bodyFor(r)
		if err != nil {
			writeDockerError(w, http.StatusRequestEntityTooLarge, "bullfrog: "+err.Error())
			return
		}

		if d := p.policy.Evaluate(r.Method, r.URL.Path, r.URL.RawQuery, body); !d.Allow {
			p.Log("DOCKER DENY: %s %s — %s", r.Method, r.URL.Path, d.Reason)
			// 403 with the daemon's own error shape, so `docker run` prints
			// the reason instead of a transport error.
			writeDockerError(w, http.StatusForbidden, "bullfrog: "+d.Reason)
			return
		}
		// attach and exec stop being ordinary HTTP once the daemon answers
		// 101, and net/http's reverse proxy is the wrong tool for what
		// happens next. See serveUpgrade.
		if isUpgrade(r) {
			p.serveUpgrade(w, r)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

// isUpgrade reports whether the client asked to leave HTTP behind. `docker
// run`, `docker attach` and `docker exec` all do, to carry the container's
// streams.
func isUpgrade(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// serveUpgrade relays a connection that turns into a raw byte stream.
//
// httputil.ReverseProxy handles 101 responses, but it finishes as soon as
// EITHER direction ends. `docker run` attaches without sending anything on
// stdin, so the client-to-daemon copy reaches EOF immediately, the proxy tears
// the connection down, and the container's output is lost — a container that
// runs, exits 0, and prints nothing. Here, the daemon-to-client direction is
// what decides when the exchange is over, and the client's EOF is passed on as
// a half-close instead of a teardown.
func (p *Proxy) serveUpgrade(w http.ResponseWriter, r *http.Request) {
	backend, err := net.Dial("unix", p.RealPath)
	if err != nil {
		writeDockerError(w, http.StatusBadGateway, fmt.Sprintf("bullfrog: the docker daemon could not be reached: %v", err))
		return
	}
	defer backend.Close()

	if err := r.Write(backend); err != nil {
		writeDockerError(w, http.StatusBadGateway, fmt.Sprintf("bullfrog: forwarding to the docker daemon: %v", err))
		return
	}
	fromDaemon := bufio.NewReader(backend)
	resp, err := http.ReadResponse(fromDaemon, r)
	if err != nil {
		writeDockerError(w, http.StatusBadGateway, fmt.Sprintf("bullfrog: reading the docker daemon's response: %v", err))
		return
	}

	// The daemon may decline to upgrade — an error before the stream starts.
	// That is an ordinary response and is relayed as one.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		writeDockerError(w, http.StatusInternalServerError, "bullfrog: this connection cannot be upgraded")
		return
	}
	client, clientBuf, err := hj.Hijack()
	if err != nil {
		writeDockerError(w, http.StatusInternalServerError, fmt.Sprintf("bullfrog: %v", err))
		return
	}
	defer client.Close()

	// Hand the 101 to the client, then get out of the way.
	if err := resp.Write(clientBuf); err != nil {
		return
	}
	if err := clientBuf.Flush(); err != nil {
		return
	}

	// Client to daemon, ending in a half-close so the daemon learns that
	// stdin is finished without losing the direction that carries output.
	go func() {
		_, _ = io.Copy(backend, clientBuf)
		if cw, ok := backend.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	// Daemon to client. This is the one that matters, and its end is the end
	// of the exchange. fromDaemon, not backend: the response reader may
	// already hold the first bytes of the stream.
	_, _ = io.Copy(client, fromDaemon)
}

// maxInspectedBody bounds what the policy will buffer. Only the endpoints the
// policy actually reads are buffered at all: an image load or a build context
// is gigabytes and is streamed straight through.
const maxInspectedBody = 4 << 20

func (p *Policy) inspectsBody(method, path string) bool {
	// The SAME normalization the policy judges with. Two spellings of "strip
	// the version" is how a body escapes inspection while the path is still
	// routed to an endpoint whose body decides everything.
	path, ok := normalizePath(path)
	if !ok {
		return false
	}
	if method != "POST" {
		return false
	}
	switch path {
	case "/containers/create", "/volumes/create", "/networks/create":
		return true
	}
	return containerPath.MatchString(path) && strings.HasSuffix(path, "/exec")
}

// bodyFor reads the request body when the policy needs it, and puts it back so
// the proxied request still carries it.
func (p *Proxy) bodyFor(r *http.Request) ([]byte, error) {
	if r.Body == nil || !p.policy.inspectsBody(r.Method, r.URL.Path) {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxInspectedBody+1))
	if err != nil {
		return nil, fmt.Errorf("reading the request body: %w", err)
	}
	if len(body) > maxInspectedBody {
		return nil, errors.New("this request is too large to be judged, so it is refused while sudo is disabled")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return body, nil
}

// writeDockerError speaks the daemon's error shape: {"message": "..."}.
func writeDockerError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

// daemonInspector answers the policy's questions by asking the daemon.
type daemonInspector struct {
	client *http.Client
}

func (d *daemonInspector) VolumeOptions(name string) (map[string]string, error) {
	var v struct {
		Options map[string]string `json:"Options"`
	}
	if err := d.get("/volumes/"+url.PathEscape(name), &v); err != nil {
		return nil, err
	}
	return v.Options, nil
}

func (d *daemonInspector) ContainerHostConfig(id string) (json.RawMessage, error) {
	var c struct {
		HostConfig json.RawMessage `json:"HostConfig"`
	}
	if err := d.get("/containers/"+url.PathEscape(id)+"/json", &c); err != nil {
		return nil, err
	}
	return c.HostConfig, nil
}

func (d *daemonInspector) get(path string, out any) error {
	resp, err := d.client.Get("http://docker" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker API %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// restoreDaemonSocket gives the daemon's socket back the ownership and mode it
// had before the proxy touched it.
func (p *Proxy) restoreDaemonSocket(path string) error {
	if err := os.Chown(path, p.origUID, p.origGID); err != nil {
		return err
	}
	return os.Chmod(path, p.origMode)
}

// Stop puts the daemon's socket back where clients expect it.
//
// Best effort by design: the agent is normally killed outright at the end of a
// job, so nothing may ever call this. Leaving the filter in place is the safe
// direction, and the runner is discarded either way.
func (p *Proxy) Stop() error {
	if p.server != nil {
		_ = p.server.Close()
	}
	if err := os.Remove(p.Path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(p.RealPath, p.Path); err != nil {
		return err
	}
	// The socket was taken to root-only on the way in. Leaving it that way
	// would hand back a daemon no client can reach.
	return p.restoreDaemonSocket(p.Path)
}
