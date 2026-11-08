package image

import (
	"context"
	"os/exec"
	"strings"
)

// Users lists the containers made from this image, running or stopped, so a
// person can see what removing it would break before saying yes.
func Users(ctx context.Context, r Ref) ([]Container, error) {
	all, err := ListContainers(ctx)
	if err != nil {
		return nil, err
	}
	var out []Container
	for _, c := range all {
		if c.Image == r.Image || Parse(c.Image).Canonical() == r.Canonical() {
			out = append(out, c)
		}
	}
	return out, nil
}

// RemoveCmd is docker's own removal of one image. It never forces: an image a
// container still uses is refused by docker, and that refusal is the answer.
func RemoveCmd(r Ref) *exec.Cmd {
	return exec.Command("docker", "rmi", r.Image)
}

// ContainerLine says what a container is doing, in the words docker uses.
func ContainerLine(c Container) string {
	state := strings.TrimSpace(c.State)
	if state == "" {
		state = "unknown"
	}
	return c.Name + "  " + state
}
