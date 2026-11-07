package image

import (
	"context"
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
	// Base is the distribution the image sits on, when it says.
	Base string
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
	if asked {
		refs = Join(refs, local)
	} else {
		for i := range refs {
			refs[i].Presence = Unasked
		}
	}
	if ask == nil {
		for i := range refs {
			refs[i].State = Unknown
		}
		return refs
	}
	var g errgroup.Group
	g.SetLimit(8)
	for i := range refs {
		g.Go(func() error {
			remote, err := ask.Remote(ctx, refs[i])
			if err != nil {
				refs[i].State = Unknown
				refs[i].Note = err.Error()
				return nil
			}
			life, _ := ask.Life(ctx, refs[i])
			refs[i] = Decide(refs[i], remote, life, now)
			return nil
		})
	}
	_ = g.Wait()
	return refs
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
	r.Upstream, r.Base = remote.Upstream, remote.Base
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
		if refs[i].State == Gone && refs[i].Digest == "" {
			refs[i].State = Local
			refs[i].Note = ""
		}
	}
	if dangling > 0 {
		refs = append(refs, Ref{Image: "<none>", State: Local, Note: itoa(dangling) + " dangling"})
	}
	return refs
}
