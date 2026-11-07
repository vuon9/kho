package image

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/vuon9/kho/internal/provider"
)

// Local is one image on the machine, as docker lists it.
type LocalImage struct {
	Image   string
	Repo    string
	Tag     string
	Digest  string
	ID      string
	Size    string
	Created time.Time
}

// Container is one container docker knows about.
type Container struct {
	Name    string
	Image   string
	State   string
	Created time.Time
}

// Docker runs a docker subcommand and returns its stdout. Tests swap it.
var Docker = func(ctx context.Context, args ...string) ([]byte, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	provider.Record(append([]string{"docker"}, args...), time.Since(start), err)
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, errText(msg)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

type errText string

func (e errText) Error() string { return string(e) }

const listFormat = `{{.Repository}}\t{{.Tag}}\t{{.Digest}}\t{{.ID}}\t{{.CreatedAt}}\t{{.Size}}`

// ListLocal reads the images docker holds. A machine with no daemon gets an
// error, which callers report as "could not ask" rather than "nothing there".
func ListLocal(ctx context.Context) ([]LocalImage, error) {
	out, err := Docker(ctx, "image", "ls", "--digests", "--no-trunc", "--format", listFormat)
	if err != nil {
		return nil, err
	}
	var images []LocalImage
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 6 {
			continue
		}
		images = append(images, LocalImage{
			Image:   f[0] + ":" + f[1],
			Repo:    f[0],
			Tag:     f[1],
			Digest:  f[2],
			ID:      f[3],
			Size:    f[5],
			Created: parseDockerTime(f[4]),
		})
	}
	return images, nil
}

// ListContainers reads every container docker knows about, running or not.
func ListContainers(ctx context.Context) ([]Container, error) {
	out, err := Docker(ctx, "ps", "-a", "--format", `{{.Names}}\t{{.Image}}\t{{.State}}\t{{.CreatedAt}}`)
	if err != nil {
		return nil, err
	}
	var containers []Container
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		containers = append(containers, Container{Name: f[0], Image: f[1], State: f[2], Created: parseDockerTime(f[3])})
	}
	return containers, nil
}

// parseDockerTime reads the timestamps docker prints, as in
// "2026-10-17 08:12:34 +0700 +07".
func parseDockerTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02 15:04:05 -0700 MST", "2006-01-02 15:04:05 -0700", time.RFC3339} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Join fills each reference's presence from the machine's images. A reference
// docker lists keeps its age; one it does not list is missing. When docker
// was never asked, nothing is claimed.
func Join(refs []Ref, local []LocalImage) []Ref {
	byCanonical := map[string]LocalImage{}
	byRepo := map[string][]LocalImage{}
	for _, l := range local {
		r := Parse(l.Image)
		byCanonical[r.Canonical()] = l
		byRepo[r.CanonicalRepo()] = append(byRepo[r.CanonicalRepo()], l)
	}
	for i := range refs {
		r := &refs[i]
		if r.Unresolved {
			continue
		}
		if l, ok := byCanonical[r.Canonical()]; ok {
			r.Presence, r.Built = OnDisk, l.Created
			continue
		}
		r.Presence = NotPulled
		if others := byRepo[r.CanonicalRepo()]; len(others) > 0 {
			r.Note = "another tag of this image is on disk"
		}
	}
	return refs
}
