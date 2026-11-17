package image

import (
	"context"
	"os/exec"
	"strings"
)

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

// Never forces: docker refuses an image a container still uses, and that refusal is the answer.
func RemoveCmd(r Ref) *exec.Cmd {
	return exec.Command("docker", "rmi", r.Image)
}

func ContainerLine(c Container) string {
	state := strings.TrimSpace(c.State)
	if state == "" {
		state = "unknown"
	}
	return c.Name + "  " + state
}
