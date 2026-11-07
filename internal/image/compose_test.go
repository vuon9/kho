package image

import "testing"

func TestParseCompose(t *testing.T) {
	tests := []struct {
		id   string
		src  string
		want []Ref
	}{
		{
			id: "one image per service",
			src: `services:
  db:
    image: postgres:13
    ports:
      - "5432:5432"
  web:
    build: .
    image: vanjayak/open-design:latest
`,
			want: []Ref{
				{Image: "postgres:13", Registry: "docker.io", Repo: "postgres", Tag: "13", Source: "compose", Service: "db", Line: 3},
				{Image: "vanjayak/open-design:latest", Registry: "docker.io", Repo: "vanjayak/open-design", Tag: "latest", Source: "compose", Service: "web", Line: 8},
			},
		},
		{
			id: "a variable default is the image",
			src: `services:
  app:
    image: ${OD_IMAGE:-ghcr.io/open-design/od:edge}
`,
			want: []Ref{{Image: "ghcr.io/open-design/od:edge", Raw: "${OD_IMAGE:-ghcr.io/open-design/od:edge}", Via: "OD_IMAGE",
				Registry: "ghcr.io", Repo: "open-design/od", Tag: "edge", Source: "compose", Service: "app", Line: 3}},
		},
		{
			id: "a variable with no default leaves it open",
			src: `services:
  app:
    image: ${API_IMAGE}
`,
			want: []Ref{{Image: "${API_IMAGE}", Raw: "${API_IMAGE}", Via: "API_IMAGE", Unresolved: true, Source: "compose", Service: "app", Line: 3}},
		},
		{
			id: "a service that only builds has no image",
			src: `services:
  odoo:
    build:
      context: .
    depends_on:
      - db
  db:
    image: postgres:13
`,
			want: []Ref{{Image: "postgres:13", Registry: "docker.io", Repo: "postgres", Tag: "13", Source: "compose", Service: "db", Line: 8}},
		},
		{
			id: "a key outside services is not an image",
			src: `x-image: ignored:1
services:
  app:
    image: alpine:3.20 # pinned
volumes:
  image: nope:1
`,
			want: []Ref{{Image: "alpine:3.20", Registry: "docker.io", Repo: "alpine", Tag: "3.20", Source: "compose", Service: "app", Line: 4}},
		},
	}
	for _, tt := range tests {
		got := ParseCompose("compose.yaml", []byte(tt.src))
		if len(got) != len(tt.want) {
			t.Fatalf("%s: %d refs, want %d: %+v", tt.id, len(got), len(tt.want), got)
		}
		for i := range got {
			got[i].File = ""
			if got[i] != tt.want[i] {
				t.Errorf("%s: ref %d\n got %+v\nwant %+v", tt.id, i, got[i], tt.want[i])
			}
		}
	}
}
