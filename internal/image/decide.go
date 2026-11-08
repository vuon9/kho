package image

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// Remote is what a registry says about a reference right now.
type Remote struct {
	// Digest is what the tag resolves to, the index digest when the image is
	// multi platform.
	Digest string
	// Pushed is when the image was built, from its own config.
	Pushed time.Time
	// Upstream is the version the image declares, as in 22.23.4 from
	// NODE_VERSION.
	Upstream string
	// Base is the distribution or runtime the image sits on, when it says, and
	// BaseVersion is that runtime's own version, which is never Upstream.
	Base        string
	BaseVersion string
	// Gone means the registry does not publish this tag at all.
	Gone bool
}

// Life is what a lifecycle page says about an upstream release line.
type Life struct {
	Cycle  string
	EOL    time.Time
	Latest string
}

// Asker answers what the registry and the lifecycle pages say. Tests swap it,
// and a run with no network gets zero values rather than an error.
type Asker interface {
	Remote(ctx context.Context, r Ref) (Remote, error)
	Life(ctx context.Context, r Ref) (Life, error)
}

// Inspect joins the machine's images to refs and asks about each one, in
// parallel. A failed lookup leaves the state Unknown, never Fresh.
func Inspect(ctx context.Context, refs []Ref, local []LocalImage, asked bool, ask Asker, now time.Time) []Ref {
	refs = Joined(refs, local, asked)
	InspectEach(ctx, refs, ask, now, func(i int, r Ref) { refs[i] = r })
	return refs
}

// Joined marks each ref with what the machine already has, without asking any
// registry: the part of Inspect that needs no network.
func Joined(refs []Ref, local []LocalImage, asked bool) []Ref {
	if asked {
		return Join(refs, local)
	}
	for i := range refs {
		refs[i].Presence = Unasked
	}
	return refs
}

// InspectEach is Inspect with each answer handed over as it lands, so a screen
// can fill in one row at a time instead of waiting for the slowest registry.
// The refs it is given must already be joined with the machine's images.
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

// Decide turns what kho learned into the one word the table shows. Order
// matters: a closed line outranks a fresh digest, and a build made here has
// no registry to compare with.
func Decide(r Ref, remote Remote, life Life, now time.Time) Ref {
	if r.Unresolved {
		return r
	}
	if r.Repo == "scratch" {
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

// Machine is the machine's own image list, one row per image, with the
// verdict of the registry attached. An image built here has no registry copy,
// so it stays Local instead of looking Gone.
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
		// No repository digest means docker never pulled it: it was built or
		// loaded here, so a registry that does not know the name says nothing
		// about it.
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
