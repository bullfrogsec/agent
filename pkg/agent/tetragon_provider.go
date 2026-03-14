package agent

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	tetragonpb "github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	tetragonDefaultSocket  = "unix:///run/tetragon/tetragon.sock"
	tetragonReadyTimeout   = 10 * time.Second
	tetragonReadyPollDelay = 100 * time.Millisecond
	tetragonExitRetention  = 5 * time.Minute
	tetragonGCInterval     = 1 * time.Minute
)

type tetragonEntry struct {
	PID      uint32
	PPID     uint32
	Binary   string    // full executable path from Tetragon exec event
	Args     string    // arguments string from Tetragon exec event
	ExitedAt time.Time // zero if still running
}

// TetragonProcProvider implements IProcProvider using Cilium Tetragon as
// the process event source. It launches Tetragon as a child process and
// maintains an in-memory cache of PID→entry populated from the gRPC event
// stream. GetParentPID uses this cache so the parent chain is captured at
// fork/exec time (defeats double-fork evasion). Other methods that rely on
// socket scanning delegate to LinuxProcProvider.
type TetragonProcProvider struct {
	mu      sync.RWMutex
	entries map[uint32]*tetragonEntry

	cmd      *exec.Cmd
	conn     *grpc.ClientConn
	cancel   context.CancelFunc
	fallback *LinuxProcProvider
	stopCh   chan struct{}
}

// NewTetragonProcProvider launches the Tetragon binary at tetragonPath,
// waits for its gRPC server to be ready on socketPath, subscribes to
// the event stream, and bootstraps the cache from /proc.
// socketPath uses gRPC target syntax, e.g. "unix:///run/tetragon/tetragon.sock".
func NewTetragonProcProvider(tetragonPath, socketPath string) (*TetragonProcProvider, error) {
	// Ensure the socket directory exists
	if unixPath := unixSocketPath(socketPath); unixPath != "" {
		if err := os.MkdirAll(filepath.Dir(unixPath), 0755); err != nil {
			return nil, fmt.Errorf("creating tetragon socket dir: %w", err)
		}
		// Remove stale socket from previous run
		os.Remove(unixPath)
	}

	cmd := exec.Command(tetragonPath,
		"--server-address", socketPath,
		"--log-level", "warn",
		"--log-format", "json",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting tetragon: %w", err)
	}

	// Wait for gRPC server to be ready
	if err := waitForSocket(unixSocketPath(socketPath), tetragonReadyTimeout); err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("tetragon did not become ready: %w", err)
	}

	conn, err := grpc.NewClient(socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("connecting to tetragon gRPC: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &TetragonProcProvider{
		entries:  make(map[uint32]*tetragonEntry),
		cmd:      cmd,
		conn:     conn,
		cancel:   cancel,
		fallback: &LinuxProcProvider{},
		stopCh:   make(chan struct{}),
	}

	// Bootstrap from /proc for processes already running before Tetragon
	p.bootstrapFromProc()

	// Start event stream goroutine
	go p.eventLoop(ctx)
	// Start GC goroutine
	go p.gcLoop()

	return p, nil
}

// Close stops the event loop, kills the Tetragon child process, and
// closes the gRPC connection.
func (p *TetragonProcProvider) Close() {
	p.cancel()
	close(p.stopCh)
	p.conn.Close()
	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Kill()
		p.cmd.Wait()
	}
}

func (p *TetragonProcProvider) eventLoop(ctx context.Context) {
	client := tetragonpb.NewFineGuidanceSensorsClient(p.conn)
	for {
		if err := p.subscribe(ctx, client); err != nil {
			if ctx.Err() != nil {
				return // shutting down
			}
			log.Printf("TetragonProcProvider: event stream error: %v; reconnecting in 1s", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		}
	}
}

func (p *TetragonProcProvider) subscribe(ctx context.Context, client tetragonpb.FineGuidanceSensorsClient) error {
	stream, err := client.GetEvents(ctx, &tetragonpb.GetEventsRequest{})
	if err != nil {
		return err
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			return err
		}
		switch ev := resp.Event.(type) {
		case *tetragonpb.GetEventsResponse_ProcessExec:
			p.handleExec(ev.ProcessExec)
		case *tetragonpb.GetEventsResponse_ProcessExit:
			p.handleExit(ev.ProcessExit)
		}
	}
}

func (p *TetragonProcProvider) handleExec(ev *tetragonpb.ProcessExec) {
	if ev.GetProcess() == nil {
		return
	}
	pid := ev.GetProcess().GetPid().GetValue()
	ppid := uint32(0)
	if ev.GetParent() != nil {
		ppid = ev.GetParent().GetPid().GetValue()
	}
	binary := ev.GetProcess().GetBinary()
	args := ev.GetProcess().GetArguments()

	log.Printf("[tetragon] exec pid=%d ppid=%d binary=%q args=%q ancestors=%d",
		pid, ppid, binary, args, len(ev.GetAncestors()))

	p.mu.Lock()
	defer p.mu.Unlock()

	p.entries[pid] = &tetragonEntry{
		PID:    pid,
		PPID:   ppid,
		Binary: binary,
		Args:   args,
	}

	// Cache ancestor entries to fill gaps in the parent chain
	for _, ancestor := range ev.GetAncestors() {
		if ancestor == nil {
			continue
		}
		ancestorPID := ancestor.GetPid().GetValue()
		if _, exists := p.entries[ancestorPID]; !exists {
			p.entries[ancestorPID] = &tetragonEntry{
				PID:    ancestorPID,
				Binary: ancestor.GetBinary(),
				Args:   ancestor.GetArguments(),
			}
			log.Printf("[tetragon] ancestor pid=%d binary=%q (from exec of pid=%d)",
				ancestorPID, ancestor.GetBinary(), pid)
		}
	}
}

func (p *TetragonProcProvider) handleExit(ev *tetragonpb.ProcessExit) {
	if ev.GetProcess() == nil {
		return
	}
	pid := ev.GetProcess().GetPid().GetValue()

	p.mu.Lock()
	defer p.mu.Unlock()

	if entry, ok := p.entries[pid]; ok {
		entry.ExitedAt = time.Now()
		log.Printf("[tetragon] exit  pid=%d binary=%q (retained for %s)", pid, entry.Binary, tetragonExitRetention)
	}
	// Entry is NOT deleted immediately — retained for tetragonExitRetention
	// so that double-fork parent chains remain resolvable.
}

func (p *TetragonProcProvider) gcLoop() {
	ticker := time.NewTicker(tetragonGCInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-tetragonExitRetention)
			p.mu.Lock()
			for pid, entry := range p.entries {
				if !entry.ExitedAt.IsZero() && entry.ExitedAt.Before(cutoff) {
					delete(p.entries, pid)
				}
			}
			p.mu.Unlock()
		}
	}
}

func (p *TetragonProcProvider) bootstrapFromProc() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		ppid := uint32(readPPIDFromProc(int(pid)))
		binary, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		p.entries[uint32(pid)] = &tetragonEntry{
			PID:    uint32(pid),
			PPID:   ppid,
			Binary: binary,
		}
		count++
	}
	log.Printf("[tetragon] bootstrapped %d processes from /proc", count)
}

// ---- IProcProvider implementation ----

// GetParentPID returns PPID from the Tetragon event cache.
// Critical: entries for exited processes are retained, so the parent chain
// of a double-forked process remains resolvable even after the intermediate
// process exits and the OS re-parents the grandchild to PID 1.
func (p *TetragonProcProvider) GetParentPID(pid int) (int, error) {
	p.mu.RLock()
	entry, ok := p.entries[uint32(pid)]
	p.mu.RUnlock()
	if ok {
		log.Printf("[tetragon] GetParentPID(pid=%d) → ppid=%d [cache]", pid, entry.PPID)
		return int(entry.PPID), nil
	}
	ppid, err := p.fallback.GetParentPID(pid)
	log.Printf("[tetragon] GetParentPID(pid=%d) → ppid=%d [/proc fallback, err=%v]", pid, ppid, err)
	return ppid, err
}

func (p *TetragonProcProvider) GetProcessName(pid int) (string, error) {
	p.mu.RLock()
	entry, ok := p.entries[uint32(pid)]
	p.mu.RUnlock()
	if ok && entry.Binary != "" {
		name := filepath.Base(entry.Binary)
		log.Printf("[tetragon] GetProcessName(pid=%d) → %q [cache]", pid, name)
		return name, nil
	}
	name, err := p.fallback.GetProcessName(pid)
	log.Printf("[tetragon] GetProcessName(pid=%d) → %q [/proc fallback, err=%v]", pid, name, err)
	return name, err
}

func (p *TetragonProcProvider) GetCommandLine(pid int) (string, error) {
	p.mu.RLock()
	entry, ok := p.entries[uint32(pid)]
	p.mu.RUnlock()
	if ok && entry.Binary != "" {
		var cmdline string
		if entry.Args != "" {
			cmdline = entry.Binary + " " + entry.Args
		} else {
			cmdline = entry.Binary
		}
		log.Printf("[tetragon] GetCommandLine(pid=%d) → %q [cache]", pid, cmdline)
		return cmdline, nil
	}
	cmdline, err := p.fallback.GetCommandLine(pid)
	log.Printf("[tetragon] GetCommandLine(pid=%d) → %q [/proc fallback, err=%v]", pid, cmdline, err)
	return cmdline, err
}

func (p *TetragonProcProvider) GetExecutablePath(pid int) (string, error) {
	p.mu.RLock()
	entry, ok := p.entries[uint32(pid)]
	p.mu.RUnlock()
	if ok && entry.Binary != "" {
		log.Printf("[tetragon] GetExecutablePath(pid=%d) → %q [cache]", pid, entry.Binary)
		return entry.Binary, nil
	}
	path, err := p.fallback.GetExecutablePath(pid)
	log.Printf("[tetragon] GetExecutablePath(pid=%d) → %q [/proc fallback, err=%v]", pid, path, err)
	return path, err
}

// These methods delegate entirely to LinuxProcProvider — socket scanning
// is not covered by Tetragon and stays /proc-based.
func (p *TetragonProcProvider) ReadProcNetFile(protocol string, ipVersion int) ([]SocketEntry, error) {
	return p.fallback.ReadProcNetFile(protocol, ipVersion)
}
func (p *TetragonProcProvider) FindProcessByInode(inode uint64) (int, error) {
	return p.fallback.FindProcessByInode(inode)
}
func (p *TetragonProcProvider) GetProcesses() ([]int, error) {
	return p.fallback.GetProcesses()
}

// ---- helpers ----

// unixSocketPath extracts the filesystem path from a gRPC Unix socket target.
// "unix:///run/tetragon/tetragon.sock" → "/run/tetragon/tetragon.sock"
func unixSocketPath(target string) string {
	if len(target) > 7 && target[:7] == "unix://" {
		return target[7:]
	}
	return ""
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(tetragonReadyPollDelay)
	}
	return fmt.Errorf("timed out after %s waiting for %s", timeout, path)
}

func readPPIDFromProc(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ppid, _ := strconv.Atoi(fields[1])
				return ppid
			}
		}
	}
	return 0
}
