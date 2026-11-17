// Package terminalmeter is an experimental, Xray-INDEPENDENT session-drain
// reference. It is NOT wired into production Xray, does not sign receipts,
// and cannot authorize a refund. It models what a future patched Xray must
// guarantee before a post-stop meter may even be considered for attestation.
package terminalmeter

import (
	"context"
	"errors"
	"math"
	"sync"
)

var (
	ErrInvalidScope = errors.New("terminalmeter: invalid signed scope")
	ErrScopeMismatch = errors.New("terminalmeter: changed lease/runtime identity")
	ErrMissing = errors.New("terminalmeter: no registered user session")
	ErrRevoked = errors.New("terminalmeter: admission already fenced")
	ErrFinished = errors.New("terminalmeter: session accounting already finished")
	ErrOverflow = errors.New("terminalmeter: counter overflow")
	ErrCancelRequired = errors.New("terminalmeter: session cancellation hook required")
)

// Scope must be bound to the authenticated user, actual Xray process
// incarnation and signed account/lease identity. Do not construct from
// untrusted desired-config content or user-supplied strings.
type Scope struct {
	UserEmail string
	AccountEpoch string
	MeterEpoch string
	ReservationID string
	RuntimeID string
}

func (s Scope) valid() bool {
	return s.UserEmail != "" && s.AccountEpoch != "" &&
		s.MeterEpoch != "" && s.ReservationID != "" && s.RuntimeID != ""
}

// Bytes count only transfers actually attributed by the dataplane. Callers
// must NOT synthesize bytes from reservations, traffic estimates or timeouts.
type Bytes struct {
	Uplink uint64
	Downlink uint64
}

// Observation is intentionally NOT a final-meter proof. In particular,
// Refundable is always false. This prototype cannot attest to the exact set
// of physical streams in Xray or to durable, signed counter persistence.
type Observation struct {
	Scope Scope
	Bytes Bytes
	ActiveSessions int
	AdmissionFenced bool
	Refundable bool
}

type userState struct {
	scope Scope
	sessions map[*Session]struct{}
	bytes Bytes
	fenced bool
	done chan struct{}
	doneClosed bool
	overflow bool
}

// Registry is scoped to ONE process incarnation; it is not a cross-restart
// ledger and must not be confused with a global source of truth.
type Registry struct {
	mu sync.Mutex
	users map[string]*userState
}

func New() *Registry {
	return &Registry{users: make(map[string]*userState)}
}

// Session is a physical user stream that must be registered BEFORE it can
// transfer a byte. Finish must execute only AFTER all attributable writers
// have finished accounting and the transport has stopped.
type Session struct {
	registry *Registry
	user *userState
	cancel func()
	finished bool
}

// Admit is atomic with FenceAndWait. A stream with another reservation or
// process incarnation cannot reuse a tracked email as a shortcut.
func (r *Registry) Admit(scope Scope, cancel func()) (*Session, error) {
	if !scope.valid() {
		return nil, ErrInvalidScope
	}
	if cancel == nil {
		return nil, ErrCancelRequired
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	user := r.users[scope.UserEmail]
	if user == nil {
		user = &userState{scope: scope, sessions: make(map[*Session]struct{}), done: make(chan struct{})}
		r.users[scope.UserEmail] = user
	}
	if user.scope != scope {
		return nil, ErrScopeMismatch
	}
	if user.fenced {
		return nil, ErrRevoked
	}
	session := &Session{registry: r, user: user, cancel: cancel}
	user.sessions[session] = struct{}{}
	return session, nil
}

// Account must be called on actual successfully transferred bytes, before
// Finish. It is serialized with the drain transition. Overflow permanently
// invalidates the current incarnation and denies terminal observation.
func (s *Session) Account(up, down uint64) error {
	r := s.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.finished {
		return ErrFinished
	}
	u := s.user
	if u.overflow || math.MaxUint64-u.bytes.Uplink < up ||
		math.MaxUint64-u.bytes.Downlink < down {
		u.overflow = true
		return ErrOverflow
	}
	u.bytes.Uplink += up
	u.bytes.Downlink += down
	return nil
}

// Finish signals completion AFTER the final counted transfer and transport
// shutdown. Calling it twice cannot create extra bytes or prematurely close
// another stream's barrier.
func (s *Session) Finish() {
	r := s.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.finished {
		return
	}
	s.finished = true
	delete(s.user.sessions, s)
	if s.user.fenced && len(s.user.sessions) == 0 && !s.user.doneClosed {
		close(s.user.done)
		s.user.doneClosed = true
	}
}

func observation(u *userState) Observation {
	return Observation{
		Scope: u.scope, Bytes: u.bytes, ActiveSessions: len(u.sessions),
		AdmissionFenced: u.fenced, Refundable: false,
	}
}

// FenceAndWait atomically rejects new sessions, invokes cancellation on every
// admitted stream, and waits for each stream's accounting-completion signal.
// Timeout, crash or missing identity MUST NOT release a reservation. Cancels
// run outside the registry lock; repeats cannot duplicate cancellation.
// Even successful return is only a LOCAL OBSERVATION, NEVER a signed final
// meter or a permit to refund Xray traffic.
func (r *Registry) FenceAndWait(ctx context.Context, scope Scope) (Observation, error) {
	if !scope.valid() {
		return Observation{}, ErrInvalidScope
	}
	r.mu.Lock()
	u := r.users[scope.UserEmail]
	if u == nil {
		r.mu.Unlock()
		return Observation{}, ErrMissing
	}
	if u.scope != scope {
		r.mu.Unlock()
		return Observation{}, ErrScopeMismatch
	}
	var cancels []func()
	if !u.fenced {
		u.fenced = true
		for sess := range u.sessions {
			cancels = append(cancels, sess.cancel)
		}
		if len(u.sessions) == 0 && !u.doneClosed {
			close(u.done)
			u.doneClosed = true
		}
	}
	done := u.done
	r.mu.Unlock()
	for _, fn := range cancels {
		go fn() // A blocked transport cancel cannot block an API thread.
	}
	select {
	case <-ctx.Done():
		return Observation{}, ctx.Err()
	case <-done:
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if u.overflow {
		return Observation{}, ErrOverflow
	}
	return observation(u), nil
}

// Inspect is monitoring only. It never emits a proof or a refund decision.
func (r *Registry) Inspect(scope Scope) (Observation, error) {
	if !scope.valid() {
		return Observation{}, ErrInvalidScope
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	u := r.users[scope.UserEmail]
	if u == nil {
		return Observation{}, ErrMissing
	}
	if u.scope != scope {
		return Observation{}, ErrScopeMismatch
	}
	return observation(u), nil
}
