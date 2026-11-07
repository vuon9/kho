package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/vuon9/kho/internal/history"
	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/vuln"
)

// confirm is a dialog that asks before kho changes anything. A dialog with no
// run only explains why there is nothing to do.
type confirm struct {
	title string
	lines []string
	run   tea.Cmd
}

type installedMsg struct {
	provider, name, version string
	err                     error
	// removed is an uninstall, which has no version to land on.
	removed bool
}

type linkedMsg struct {
	done string
	err  error
}

// The actions that change the machine, swapped out in tests.
var (
	runExec        = tea.Exec
	installProcess = func(c *exec.Cmd) *exec.Cmd { return c }
	skillLinks     = provider.SkillLinks
	linkSkill      = provider.LinkSkill
	unlinkSkill    = provider.UnlinkSkill
)

// askInstall offers to move the selected package to the selected version.
func (m *model) askInstall() {
	p, ok := m.current()
	r, ok2 := at(m.currentVersions(), m.sideCursor)
	if !ok || !ok2 {
		return
	}
	version := r.Version
	// Skill versions are commits, and the skills CLI can only take a skill to
	// its newest one.
	if p.Source == "skills" && m.sideCursor == 0 {
		version = p.Latest
	}
	verb := "Reinstall"
	switch c := vuln.Compare(provider.TagVersion(r.Version), provider.TagVersion(p.Version)); {
	case p.Source == "skills":
		verb = "Update"
	case c > 0:
		verb = "Upgrade"
	case c < 0:
		verb = "Downgrade"
	}
	cmd, err := provider.InstallCmd(p, version)
	if err != nil {
		m.confirm = &confirm{title: "Can't change " + p.Name, lines: []string{err.Error()}}
		return
	}
	arrow := map[string]string{"Upgrade": "⬆", "Downgrade": "⬇", "Reinstall": "↻", "Update": "⬆"}[verb]
	lines := []string{
		bold().Render(p.Name) + "  " + p.Version + faint().Render(" → ") + green().Render(r.Version),
		"",
	}
	eco, name := provider.Ecosystem(p), provider.OSVName(p)
	affected := 0
	for _, a := range m.db.Known(eco, name) {
		if a.Affects(r.Version) {
			affected++
		}
	}
	switch {
	case affected > 0:
		lines = append(lines, red().Render(fmt.Sprintf("⚠ %d known advisories affect %s", affected, r.Version)))
	case eco != "" && m.db.HistoryFresh(eco, name, now()):
		lines = append(lines, green().Render("✓ no known advisories in "+r.Version))
	}
	lines = append(lines, faint().Render("runs  ")+strings.Join(cmd.Args, " "), "", accent().Render("y")+faint().Render(" run it   ")+accent().Render("n")+faint().Render(" cancel"))
	title := arrow + " " + verb + " " + p.Name
	m.confirm = &confirm{title: title + "?", lines: lines, run: startInstall(title, cmd, m.log, installedMsg{provider: provider.ProviderOf(p), name: p.Name, version: r.Version})}
}

// askRemove offers to uninstall the selected package. Like an install, it asks
// first: kho changes the machine only after a person says yes.
func (m *model) askRemove() {
	p, ok := m.current()
	if !ok {
		return
	}
	cmd, err := provider.RemoveCmd(p, false)
	if err != nil {
		m.confirm = &confirm{title: "Can't remove " + p.Name, lines: []string{err.Error()}}
		return
	}
	lines := []string{bold().Render(p.Name) + "  " + p.Version, ""}
	if p.Dependency {
		lines = append(lines, yellow().Render("⚠ another installed package needs it, so Homebrew may refuse"), "")
	}
	lines = append(lines, faint().Render("runs  ")+strings.Join(cmd.Args, " "), "", accent().Render("y")+faint().Render(" remove it   ")+accent().Render("n")+faint().Render(" cancel"))
	title := "🗑 Remove " + p.Name
	m.confirm = &confirm{title: title + "?", lines: lines,
		run: startInstall(title, cmd, m.log, installedMsg{provider: provider.ProviderOf(p), name: p.Name, removed: true})}
}

// installing is a package manager running in a popup. cmd is the command as
// kho asked for it, which t runs again in the terminal, and lines are the
// output the popup shows.
//
// The output is read as fast as the command writes it, whatever the
// screen's pace: the reader keeps the lines a terminal would show in shown,
// and says so on changed. Once the install is logged, logged closes and its
// installedMsg comes on over.
type installing struct {
	title      string
	cmd        *exec.Cmd
	lines      []string
	start, end time.Time
	done       *installedMsg
	pid        int
	stopping   bool

	mu      sync.Mutex
	shown   []string
	changed chan struct{}
	logged  chan struct{}
	over    chan installedMsg
	cut     chan struct{}
}

type installStartedMsg struct{ *installing }

// outputMsg is the output the popup shows, newest last.
type outputMsg []string

// live is the install kho started last. serve stops it if it is still going
// when kho leaves, even if the screen never heard it started. Starting one
// holds the lock, so serve can't miss one on its way, and once kho is
// leaving none starts.
var live struct {
	sync.Mutex
	in      *installing
	leaving bool
}

// startInstall runs cmd in a popup. A command that can't even start leaves
// nothing to watch or stop, so it comes back as a failed installedMsg.
func startInstall(title string, cmd *exec.Cmd, log *history.Log, done installedMsg) tea.Cmd {
	return func() tea.Msg {
		live.Lock()
		defer live.Unlock()
		if live.leaving {
			return nil
		}
		run := installProcess(cmd)
		out, err := detach(run)
		if err != nil {
			done.err = err
			log.Add(entry(history.Change, cmd.Args, 0, err, ""))
			return done
		}
		in := &installing{title: title, cmd: cmd, start: now(), pid: run.Process.Pid,
			changed: make(chan struct{}, 1), logged: make(chan struct{}), over: make(chan installedMsg, 1), cut: make(chan struct{}, 1)}
		live.in = in
		go in.run(run, out, log, done)
		return installStartedMsg{in}
	}
}

// next waits for new output or the result, which brings the last lines on
// its own.
func (in *installing) next() tea.Cmd {
	return func() tea.Msg {
		select {
		case <-in.changed:
			return outputMsg(in.screen())
		case done := <-in.over:
			return done
		}
	}
}

func (in *installing) screen() []string {
	in.mu.Lock()
	defer in.mu.Unlock()
	return slices.Clone(in.shown)
}

// show adds a line to the output, or puts it over the last one when a \r
// went back over that.
func (in *installing) show(text string, redraw bool) {
	in.mu.Lock()
	if n := len(in.shown); redraw && n > 0 {
		in.shown[n-1] = text
	} else {
		in.shown = append(in.shown, text)
	}
	if over := len(in.shown) - 500; over > 0 {
		in.shown = in.shown[over:]
	}
	in.mu.Unlock()
	select {
	case in.changed <- struct{}{}:
	default:
	}
}

// The phases of an install. Its popup, its keys and the footer all go by
// them.
const (
	instRunning = iota
	instStopping
	instFailed
	instDone
)

func (in *installing) phase() int {
	switch {
	case in.done == nil && in.stopping:
		return instStopping
	case in.done == nil:
		return instRunning
	case in.done.err != nil:
		return instFailed
	}
	return instDone
}

// running is whether the package manager is still going, so ctrl+c must stop
// it before kho can quit.
func (in *installing) running() bool {
	return in != nil && in.phase() <= instStopping
}

// again is a new command like c, which has run and can't be started twice.
func again(c *exec.Cmd) *exec.Cmd {
	r := exec.Command(c.Path, c.Args[1:]...)
	r.Args, r.Env, r.Dir = c.Args, c.Env, c.Dir
	return r
}

// stop interrupts the install and everything it started, or when an
// interrupt didn't do it, kills them and stops reading what a child out of
// reach still writes.
func (in *installing) stop() {
	if !in.stopping {
		in.stopping = true
		syscall.Kill(-in.pid, syscall.SIGINT)
		return
	}
	syscall.Kill(-in.pid, syscall.SIGKILL)
	select {
	case in.cut <- struct{}{}:
	default:
	}
}

// finish stops an install kho is leaving, and kills it when it is still
// going after patience. It returns once the install is logged.
func (in *installing) finish(patience time.Duration) {
	in.stop()
	select {
	case <-in.logged:
		return
	case <-time.After(patience):
	}
	in.stop()
	<-in.logged
}

// detach starts cmd in a session of its own, with no terminal: a password
// prompt then fails instead of drawing over kho, and t can rerun it in the
// terminal. Being its own process group, it can be stopped as a whole.
func detach(cmd *exec.Cmd) (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer w.Close()
	cmd.Stdout, cmd.Stderr = w, w
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// After the command exits, kho stops reading its output once it has been
// quiet for outputGrace, or at the latest after outputLimit.
const (
	outputGrace = time.Second
	outputLimit = 10 * time.Second
)

// run reads cmd's output while it runs, and sends its installedMsg once it
// has exited and is logged.
func (in *installing) run(cmd *exec.Cmd, out *os.File, log *history.Log, done installedMsg) {
	var output tail
	var got counter
	start := time.Now()
	read := make(chan struct{})
	go func() {
		in.stream(io.TeeReader(out, io.MultiWriter(&output, &got)))
		close(read)
	}()
	done.err = cmd.Wait()
	// A child the command left behind, maybe in a process group of its own
	// that a stop can't reach, can hold the output open, and write to it, for
	// as long as it likes. kho closes it once it goes quiet, after a while
	// at the latest, or on a kill, and the child gets SIGPIPE if it writes
	// again.
	quiet(read, in.cut, &got, outputGrace, outputLimit)
	out.Close()
	<-read
	log.Add(entry(history.Change, in.cmd.Args, time.Since(start), done.err, output.String()))
	close(in.logged)
	in.over <- done
}

// quiet waits until the output ends, nothing has come on it for grace, limit
// has passed, or the install is cut short.
func quiet(read, cut <-chan struct{}, got *counter, grace, limit time.Duration) {
	end := time.After(limit)
	for {
		seen := got.Load()
		select {
		case <-read:
			return
		case <-cut:
			return
		case <-end:
			return
		case <-time.After(grace):
			if got.Load() == seen {
				return
			}
		}
	}
}

type counter struct{ atomic.Int64 }

func (c *counter) Write(p []byte) (int, error) {
	c.Add(int64(len(p)))
	return len(p), nil
}

// stream reads what the command prints until the output ends or is closed,
// and shows it as a terminal would after each read, the line still being
// written included. A \r goes back to the start of the line, so the text
// after it draws the line again, as a progress bar does.
func (in *installing) stream(r io.Reader) {
	// line is the line being written. shown says it is on screen, back that
	// a \r went back over it, and drawn that it changed since it was shown.
	var line []byte
	shown, back, drawn := false, false, false
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		for _, b := range buf[:n] {
			switch b {
			case '\r':
				back = true
			case '\n':
				// The line ends as it stands, an empty one included.
				if drawn || !shown {
					in.show(printable(string(line)), shown)
				}
				line, shown, back, drawn = line[:0], false, false, false
			default:
				if back {
					line, back = line[:0], false
				}
				// A line that never ends keeps its last part.
				if len(line) >= 1<<20 {
					line = line[:copy(line, line[len(line)/2:])]
				}
				line, drawn = append(line, b), true
			}
		}
		if drawn {
			in.show(printable(string(line)), shown)
			shown, drawn = true, false
		}
		if err != nil {
			return
		}
	}
}

// printable is a line of output as wide as the popup measures it: no
// styles, tabs as spaces, and no other control characters, which ansi.Strip
// keeps and the popup would count as no width at all.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, expandTabs(ansi.Strip(s)))
}

// tidy is what an install printed as its popup showed it: each line as a
// terminal leaves it after its last \r, then printable.
func tidy(output string) string {
	lines := strings.Split(output, "\n")
	for i, l := range lines {
		l = strings.TrimRight(l, "\r")
		lines[i] = printable(l[strings.LastIndex(l, "\r")+1:])
	}
	return strings.Join(lines, "\n")
}

// askLink offers to add or remove the selected agent's link to a skill.
func (m *model) askLink() {
	p, ok := m.current()
	l, ok2 := at(m.links, m.sideCursor)
	if !ok || !ok2 {
		return
	}
	name := agentName(l)
	nothing := func(lines ...string) { m.confirm = &confirm{title: "Nothing to link", lines: lines} }
	switch {
	case l.CanLink():
		target := provider.LinkTarget(p)
		m.confirm = &confirm{title: "🔗 Link " + p.Name + " into " + name + "?", lines: []string{
			"creates  " + tilde(l.Path), "      →  " + tilde(target), "",
			accent().Render("y") + faint().Render(" link it   ") + accent().Render("n") + faint().Render(" cancel"),
		}, run: m.logged([]string{"ln", "-s", target, l.Path}, func() tea.Msg {
			return linkedMsg{"linked " + p.Name + " into " + name, linkSkill(l, p)}
		})}
	case l.Kind == provider.LinkSymlink:
		m.confirm = &confirm{title: "✂ Unlink " + p.Name + " from " + name + "?", lines: []string{
			"removes  " + tilde(l.Path), faint().Render("the skill itself stays in ") + tilde(provider.RealPath(p)), "",
			accent().Render("y") + faint().Render(" remove the link   ") + accent().Render("n") + faint().Render(" cancel"),
		}, run: m.logged([]string{"rm", l.Path}, func() tea.Msg {
			return linkedMsg{"removed " + p.Name + " from " + name, unlinkSkill(l)}
		})}
	case l.Kind == provider.LinkCopy:
		m.confirm = &confirm{title: "Nothing to toggle", lines: []string{tilde(l.Path) + " is a folder, not a link.", "kho won't delete it."}}
	case l.Kind == provider.LinkNoFolder && l.Shared:
		nothing(name+" reads ~/.agents/skills directly,", "so it always sees "+p.Name+".")
	case l.Kind == provider.LinkNoFolder:
		nothing(name+" reads only ~/.agents/skills,", "and "+p.Name+" isn't there.")
	default:
		nothing(name+" already sees "+p.Name+" through ~/.agents/skills,", "so a link of its own would load it twice.")
	}
}

// logged records a change kho makes without a command of its own, like a
// symlink, as the shell command that would do the same.
func (m model) logged(command []string, run func() tea.Msg) tea.Cmd {
	log := m.log
	return func() tea.Msg {
		start := time.Now()
		msg := run()
		log.Add(entry(history.Change, command, time.Since(start), msg.(linkedMsg).err, ""))
		return msg
	}
}

func entry(kind string, command []string, took time.Duration, err error, output string) history.Entry {
	e := history.Entry{At: now(), Kind: kind, Command: command, Took: took, Output: output}
	if err != nil {
		e.Err = err.Error()
	}
	return e
}

// tail keeps the last 64KB written to it, enough to read why an install
// failed without the history file growing without end.
type tail struct{ buf []byte }

func (t *tail) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - 64<<10; over > 0 {
		t.buf = t.buf[over:]
	}
	return len(p), nil
}

func (t *tail) String() string { return string(t.buf) }

func tilde(path string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(path, home+string(filepath.Separator)) {
		return "~" + path[len(home):]
	}
	return path
}

// terminalRun runs a failed install again in the terminal kho hands over, so
// the package manager can ask for a password, shows its output, and waits for
// enter so the output can be read before kho comes back.
type terminalRun struct {
	cmd    *exec.Cmd
	log    *history.Log
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func (t *terminalRun) SetStdin(r io.Reader)  { t.stdin = r }
func (t *terminalRun) SetStdout(w io.Writer) { t.stdout = w }
func (t *terminalRun) SetStderr(w io.Writer) { t.stderr = w }

func (t *terminalRun) Run() error {
	fmt.Fprintf(t.stdout, "\n🏮 kho runs: %s\n\n", strings.Join(t.cmd.Args, " "))
	var output tail
	t.cmd.Stdin = t.stdin
	t.cmd.Stdout, t.cmd.Stderr = io.MultiWriter(t.stdout, &output), io.MultiWriter(t.stderr, &output)
	start := time.Now()
	err := t.cmd.Run()
	t.log.Add(entry(history.Change, t.cmd.Args, time.Since(start), err, output.String()))
	result := "✓ done"
	if err != nil {
		result = "✗ " + err.Error()
	}
	fmt.Fprintf(t.stdout, "\n%s. Press enter to go back to kho.", result)
	bufio.NewReader(t.stdin).ReadString('\n')
	return err
}
