package image

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type Remote struct {
	// The index digest when the image is multi platform.
	Digest   string
	Pushed   time.Time
	Upstream string
	// BaseVersion is the base runtime's own version, never Upstream.
	Base        string
	BaseVersion string
	Gone        bool
}

type Life struct {
	Cycle  string
	EOL    time.Time
	Latest string
}

// A run with no network gets zero values rather than an error.
type Asker interface {
	Remote(ctx context.Context, r Ref) (Remote, error)
	Life(ctx context.Context, r Ref) (Life, error)
}

// A failed lookup leaves the state Unknown, never Fresh.
func Inspect(ctx context.Context, refs []Ref, local []LocalImage, asked bool, ask Asker, now time.Time) []Ref {
	refs = Joined(refs, local, asked)
	InspectEach(ctx, refs, ask, now, func(i int, r Ref) { refs[i] = r })
	return refs
}

func Joined(refs []Ref, local []LocalImage, asked bool) []Ref {
	if asked {
		return Join(refs, local)
	}
	for i := range refs {
		refs[i].Presence = Unasked
	}
	return refs
}

// The refs must already be joined with the machine's images.
func InspectEach(ctx context.Context, refs []Ref, ask Asker, now time.Time, emit func(i int, r Ref)) {
	if ask == nil {
		for i := range refs {
			refs[i].State = Unknown
			emit(i, refs[i])
		}
		return
	}
	var g errgroup.Group
	g.SetLimit(8)
	var mu sync.Mutex
	for i := range refs {
		g.Go(func() error {
			r := refs[i]
			remote, err := ask.Remote(ctx, r)
			switch {
			case err != nil:
				r.State, r.Note = Unknown, err.Error()
			default:
				life, _ := ask.Life(ctx, r)
				r = Decide(r, remote, life, now)
			}
			mu.Lock()
			emit(i, r)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()
}

// Order matters: a closed line outranks a fresh digest, and a build made here has
// no registry to compare with.
func Decide(r Ref, remote Remote, life Life, now time.Time) Ref {
	if r.Unresolved {
		return r
	}
	if r.Repo == Scratch {
		r.State = None
		return r
	}
	r.Upstream, r.Base, r.BaseVersion = remote.Upstream, remote.Base, remote.BaseVersion
	if !life.EOL.IsZero() {
		r.EOL = life.EOL
	}
	if remote.Gone {
		r.State = Gone
		return r
	}
	if !r.EOL.IsZero() && now.After(r.EOL) {
		r.State = EOL
		return r
	}
	if r.Digest != "" && r.Tag == "" {
		r.State = Pinned
		return r
	}
	if remote.Digest == "" {
		r.State = Unknown
		return r
	}
	r.RemoteDigest, r.RemotePushed = remote.Digest, remote.Pushed
	if r.Digest != "" && r.Digest != remote.Digest {
		r.State = Stale
		r.Note = "the tag now points at " + shortDigest(remote.Digest)
		return r
	}
	if r.Presence == OnDisk && !r.Built.IsZero() && !remote.Pushed.IsZero() && r.Built.Before(remote.Pushed) {
		r.State = Stale
		return r
	}
	r.State = Fresh
	return r
}

// An image built here has no registry copy, so it stays Local instead of looking Gone.
func Machine(ctx context.Context, local []LocalImage, ask Asker, now time.Time) []Ref {
	var refs []Ref
	var dangling int
	for _, l := range local {
		if l.Repo == "<none>" {
			dangling++
			continue
		}
		r := Parse(l.Image)
		r.Built = l.Created
		r.Presence = OnDisk
		if l.Digest != "" {
			r.Digest = l.Digest
		}
		refs = append(refs, r)
	}
	refs = Inspect(ctx, refs, local, true, ask, now)
	for i := range refs {
		// No repository digest means docker never pulled it: it was built or loaded here,
		// so a registry that does not know the name says nothing about it.
		if refs[i].Digest == "" && (refs[i].State == Gone || refs[i].State == Unknown) {
			refs[i].State = Local
			refs[i].Note = ""
		}
	}
	if dangling > 0 {
		refs = append(refs, Ref{Image: "<none>", State: Local, Note: itoa(dangling) + " dangling"})
	}
	return refs
}
