package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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
	m.confirm = &confirm{title: title + "?", lines: lines, run: startInstall(title, cmd, m.log, installedMsg{provider.ProviderOf(p), p.Name, r.Version, nil})}
}

// installing is a package manager running in a popup. Its output, and then
// its installedMsg, arrive on events.
type installing struct {
	title      string
	args       []string
	lines      []string
	start, end time.Time
	events     chan tea.Msg
	done       *installedMsg
	pid        int
	stopping   bool
}

type installStartedMsg struct{ *installing }

type outputMsg string

func startInstall(title string, cmd *exec.Cmd, log *history.Log, done installedMsg) tea.Cmd {
	return func() tea.Msg {
		in := &installing{title: title, args: cmd.Args, start: now(), events: make(chan tea.Msg, 64)}
		cmd = installProcess(cmd)
		out, err := detach(cmd)
		if err == nil {
			in.pid = cmd.Process.Pid
		}
		go in.run(cmd, out, err, log, done)
		return installStartedMsg{in}
	}
}

func (in *installing) next() tea.Cmd {
	return func() tea.Msg { return <-in.events }
}

// running is whether the package manager is still going, so ctrl+c must stop
// it before kho can quit.
func (in *installing) running() bool {
	return in != nil && in.done == nil && in.pid > 0
}

// stop interrupts the install and everything it started, or kills them when
// an interrupt didn't do it.
func (in *installing) stop() {
	sig := syscall.SIGINT
	if in.stopping {
		sig = syscall.SIGKILL
	}
	in.stopping = true
	syscall.Kill(-in.pid, sig)
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

func (in *installing) run(cmd *exec.Cmd, out *os.File, err error, log *history.Log, done installedMsg) {
	var output tail
	start := time.Now()
	if err == nil {
		err = in.stream(cmd, out, &output)
	}
	done.err = err
	log.Add(entry(history.Change, in.args, time.Since(start), done.err, output.String()))
	in.events <- done
}

// stream sends what cmd prints until it exits. Each line keeps only what
// follows its last \r, as a progress bar would leave it on screen.
func (in *installing) stream(cmd *exec.Cmd, out *os.File, output io.Writer) error {
	defer out.Close()
	sc := bufio.NewScanner(io.TeeReader(out, output))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		in.events <- outputMsg(ansi.Strip(line[strings.LastIndex(line, "\r")+1:]))
	}
	// A line too long for the scanner stops it; read the rest so the command
	// never blocks on a full pipe.
	io.Copy(output, out)
	return cmd.Wait()
}

// askLink offers to add or remove the selected agent's link to a skill.
func (m *model) askLink() {
	p, ok := m.current()
	l, ok2 := at(m.links(p), m.sideCursor)
	if !ok || !ok2 {
		return
	}
	switch l.Kind {
	case "missing":
		target := tilde(provider.RealPath(p))
		m.confirm = &confirm{title: "🔗 Link " + p.Name + " into " + agentName(l) + "?", lines: []string{
			"creates  " + tilde(l.Path), "      →  " + target, "",
			accent().Render("y") + faint().Render(" link it   ") + accent().Render("n") + faint().Render(" cancel"),
		}, run: m.logged([]string{"ln", "-s", provider.RealPath(p), l.Path}, func() tea.Msg {
			return linkedMsg{"linked " + p.Name + " into " + agentName(l), linkSkill(l, p)}
		})}
	case "link":
		m.confirm = &confirm{title: "✂ Unlink " + p.Name + " from " + agentName(l) + "?", lines: []string{
			"removes  " + tilde(l.Path), faint().Render("the skill itself stays in ") + tilde(provider.RealPath(p)), "",
			accent().Render("y") + faint().Render(" remove the link   ") + accent().Render("n") + faint().Render(" cancel"),
		}, run: m.logged([]string{"rm", l.Path}, func() tea.Msg {
			return linkedMsg{"removed " + p.Name + " from " + agentName(l), unlinkSkill(l)}
		})}
	case "copy":
		m.confirm = &confirm{title: "Nothing to toggle", lines: []string{tilde(l.Path) + " is a copied folder, not a link.", "kho won't delete it."}}
	default:
		m.confirm = &confirm{title: "Nothing to toggle", lines: []string{agentName(l) + " reads ~/.agents/skills directly,", "so it always sees " + p.Name + "."}}
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
