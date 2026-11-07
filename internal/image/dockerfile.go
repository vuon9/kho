package image

import (
	"regexp"
	"strings"
)

// ParseDockerfile reads every image a Dockerfile builds on, in file order.
// ARG defaults are resolved the way docker resolves them, an ARG with no
// default leaves the reference unresolved, and FROM naming an earlier stage
// is not an image at all.
func ParseDockerfile(file string, src []byte) []Ref {
	var refs []Ref
	args := map[string]string{}
	stages := map[string]bool{}
	for _, line := range logicalLines(string(src)) {
		s := strings.TrimSpace(line.text)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		word, rest, _ := strings.Cut(s, " ")
		switch strings.ToUpper(word) {
		case "ARG":
			name, value, ok := strings.Cut(strings.TrimSpace(rest), "=")
			name = strings.TrimSpace(name)
			if !ok {
				// No default: whatever the build passes, which the file does
				// not say. Forget an earlier default in this scope.
				delete(args, name)
				continue
			}
			args[name] = strings.Trim(strings.TrimSpace(value), `"'`)
		case "FROM":
			ref, stage := parseFrom(strings.TrimSpace(rest))
			if ref == "" {
				continue
			}
			if stages[ref] {
				continue
			}
			r := Parse(ref)
			r.File, r.Line, r.Source, r.Stage = file, line.number, "dockerfile", stage
			expanded, via, ok := expand(ref, args)
			switch {
			case !ok:
				r.Image, r.Raw, r.Via, r.Unresolved = ref, ref, via, true
				r.Registry, r.Repo, r.Tag, r.Digest = "", "", "", ""
			case expanded != ref:
				r = Parse(expanded)
				r.File, r.Line, r.Source, r.Stage = file, line.number, "dockerfile", stage
				r.Raw, r.Via = ref, via
			}
			if r.Repo == "scratch" {
				r.Presence = NotPulled
			}
			refs = append(refs, r)
			if stage != "" {
				stages[stage] = true
			}
		}
	}
	return refs
}

// withParts re-splits a reference whose variables were just resolved, keeping
// where it was read.
func withParts(r Ref) Ref {
	p := Parse(r.Image)
	p.File, p.Line, p.Source, p.Stage, p.Raw = r.File, r.Line, r.Source, r.Stage, r.Raw
	return p
}

var fromFlags = regexp.MustCompile(`^--\S+\s+`)

// parseFrom splits "ref AS name" and drops the --platform flag docker allows
// in front of the image.
func parseFrom(s string) (ref, stage string) {
	for fromFlags.MatchString(s) {
		s = fromFlags.ReplaceAllString(s, "")
	}
	upper := strings.ToUpper(s)
	if i := strings.LastIndex(upper, " AS "); i >= 0 {
		stage = strings.TrimSpace(s[i+4:])
		s = s[:i]
	}
	return strings.TrimSpace(s), stage
}

type logicalLine struct {
	text   string
	number int
}

// logicalLines joins backslash continuations and keeps the first line number,
// so a report can point at the line a person sees.
func logicalLines(src string) []logicalLine {
	raw := strings.Split(src, "\n")
	var out []logicalLine
	for i := 0; i < len(raw); i++ {
		line := logicalLine{text: raw[i], number: i + 1}
		for strings.HasSuffix(strings.TrimRight(line.text, " \t"), `\`) && i+1 < len(raw) {
			line.text = strings.TrimSuffix(strings.TrimRight(line.text, " \t"), `\`)
			i++
			line.text += " " + strings.TrimSpace(raw[i])
		}
		out = append(out, line)
	}
	return out
}

// expand replaces the variables docker would replace, in order. It returns
// the first variable it met, and the first one the file gives no value for.
func expand(s string, args map[string]string) (out, via string, ok bool) {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '$' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if i+1 < len(s) && s[i+1] == '{' {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				b.WriteString(s[i:])
				break
			}
			body := s[i+2 : i+end]
			name, def, hasDef := body, "", false
			if j := strings.Index(body, ":-"); j >= 0 {
				name, def, hasDef = body[:j], body[j+2:], true
			}
			if via == "" {
				via = name
			}
			v, found := args[name]
			switch {
			case found:
				b.WriteString(v)
			case hasDef:
				b.WriteString(def)
			default:
				return "", name, false
			}
			i += end + 1
			continue
		}
		j := i + 1
		for j < len(s) && nameByte(s[j]) {
			j++
		}
		if j == i+1 {
			b.WriteByte(s[i])
			i++
			continue
		}
		name := s[i+1 : j]
		if via == "" {
			via = name
		}
		v, found := args[name]
		if !found {
			return "", name, false
		}
		b.WriteString(v)
		i = j
	}
	return b.String(), via, true
}

func nameByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
