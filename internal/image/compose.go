package image

import "strings"

// ParseCompose reads the images a compose file names, one per service. It
// understands the part of YAML compose uses here: a services block, one key
// per service under it, and an image key inside a service. A service that
// only builds has no image key, so its name never appears: docker decides
// that name, not the file.
func ParseCompose(file string, src []byte) []Ref {
	return parseCompose(file, string(src))
}

func parseCompose(file, src string) []Ref {
	var refs []Ref
	services := -1 // indent of the services block, -1 outside it
	service := -1  // indent of the current service key
	name := ""
	for i, raw := range strings.Split(src, "\n") {
		line := stripComment(raw)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "- ") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.Trim(strings.TrimSpace(value), `"'`)
		switch {
		case key == "services" && value == "":
			services, service = indent, -1
		case services < 0:
			continue
		case indent <= services:
			services, service = -1, -1
		case value == "" && (service < 0 || indent <= service):
			service, name = indent, key
		case service >= 0 && indent > service && key == "image" && value != "":
			r := Parse(value)
			r.File, r.Line, r.Source, r.Service = file, i+1, "compose", name
			expanded, via, ok := expand(value, nil)
			switch {
			case !ok:
				r.Image, r.Raw, r.Via, r.Unresolved = value, value, via, true
				r.Registry, r.Repo, r.Tag, r.Digest = "", "", "", ""
			case expanded != value:
				r = Parse(expanded)
				r.File, r.Line, r.Source, r.Service = file, i+1, "compose", name
				r.Raw, r.Via = value, via
			}
			refs = append(refs, r)
		}
	}
	return refs
}

// stripComment drops a trailing comment, leaving a # inside quotes alone.
func stripComment(line string) string {
	var quote rune
	for i, c := range line {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#' && i > 0 && (line[i-1] == ' ' || line[i-1] == '\t'):
			return line[:i]
		}
	}
	return line
}
