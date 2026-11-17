package terminalmeter

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func scope() Scope {
	return Scope{
		UserEmail: "xmesh-user-42", AccountEpoch: "epoch-1",
		MeterEpoch: "meter-1", ReservationID: "lease-1",
		RuntimeID: "xray-runtime-1",
	}
}

func TestFenceWaitsForCountedOldSessionsAndNeverRefunds(t *testing.T) {
	r := New()
	s := scope()
	cancelOne := make(chan struct{}, 1)
	cancelTwo := make(chan struct{}, 1)
	first, err := r.Admit(s, func() { cancelOne <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Admit(s, func() { cancelTwo <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Account(100, 200); err != nil {
		t.Fatal(err)
	}
	result := make(chan Observation, 1)
	failure := make(chan error, 1)
	go func() {
		observation, err := r.FenceAndWait(context.Background(), s)
		if err != nil {
			failure <- err
			return
		}
		result <- observation
	}()
	select {
	case <-cancelOne:
	case <-time.After(2 * time.Second):
		t.Fatal("old stream 1 wasn't cancelled")
	}
	select {
	case <-cancelTwo:
	case <-time.After(2 * time.Second):
		t.Fatal("old stream 2 wasn't cancelled")
	}
	if _, err := r.Admit(s, func() {}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("new admission after revoke: %v", err)
	}
	first.Finish()
	select {
	case <-result:
		t.Fatal("incorrectly completed while another stream was active")
	case err := <-failure:
		t.Fatal(err)
	default:
	}
	if err := second.Account(900, 500); err != nil {
		t.Fatal(err)
	}
	second.Finish()
	select {
	case got := <-result:
		if got.ActiveSessions != 0 || !got.AdmissionFenced ||
			got.Bytes != (Bytes{Uplink: 1000, Downlink: 700}) ||
			got.Refundable {
			t.Fatalf("incorrect nonterminal observation: %+v", got)
		}
	case err := <-failure:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("counted completion did not unblock drain")
	}
	again, err := r.FenceAndWait(context.Background(), s)
	if err != nil || again.Refundable || again.Bytes.Uplink != 1000 {
		t.Fatalf("unsafe replay: %+v, %v", again, err)
	}
}

func TestTimeoutCannotRestoreAdmission(t *testing.T) {
	r := New()
	s := scope()
	var cancelCalls atomic.Int32
	stream, err := r.Admit(s, func() { cancelCalls.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.FenceAndWait(ctx, s); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled fence returned %v", err)
	}
	if _, err := r.Admit(s, func() {}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("timeout revived old user: %v", err)
	}
	if err := stream.Account(99, 2); err != nil {
		t.Fatal(err)
	}
	stream.Finish()
	result, err := r.FenceAndWait(context.Background(), s)
	if err != nil || result.Refundable || result.Bytes != (Bytes{Uplink: 99, Downlink: 2}) {
		t.Fatalf("stale retry: %+v, %v", result, err)
	}
	// A cancellation hook might race the first return, but it must not
	// be invoked twice for a repeated fence.
	deadline := time.Now().Add(time.Second)
	for cancelCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if cancelCalls.Load() != 1 {
		t.Fatalf("cancellation did not run exactly once: %d", cancelCalls.Load())
	}
}

func TestIdentityAndMeterIncarnationAreSticky(t *testing.T) {
	r := New()
	s := scope()
	if _, err := r.FenceAndWait(context.Background(), s); !errors.Is(err, ErrMissing) {
		t.Fatalf("nonexistent session proved final: %v", err)
	}
	if _, err := r.Admit(Scope{}, func() {}); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("accepted missing identities: %v", err)
	}
	if _, err := r.Admit(s, nil); !errors.Is(err, ErrCancelRequired) {
		t.Fatalf("accepted unkillable session: %v", err)
	}
	stream, err := r.Admit(s, func() {})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Scope){
		func(s *Scope) { s.AccountEpoch = "epoch-2" },
		func(s *Scope) { s.MeterEpoch = "meter-2" },
		func(s *Scope) { s.ReservationID = "lease-2" },
		func(s *Scope) { s.RuntimeID = "xray-runtime-2" },
	} {
		other := s
		mutate(&other)
		if _, err := r.Admit(other, func() {}); !errors.Is(err, ErrScopeMismatch) {
			t.Fatalf("substituted lease admitted: %v", err)
		}
		if _, err := r.FenceAndWait(context.Background(), other); !errors.Is(err, ErrScopeMismatch) {
			t.Fatalf("substituted lease drained: %v", err)
		}
	}
	stream.Finish()
	fenced, err := r.FenceAndWait(context.Background(), s)
	if err != nil || fenced.Refundable {
		t.Fatalf("unproven final meter: %+v, %v", fenced, err)
	}
	if _, err := r.Admit(s, func() {}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("old credential revived: %v", err)
	}
}

func TestDuplicateFinishAndLateCounterCannotAddBytes(t *testing.T) {
	r := New()
	s := scope()
	session, err := r.Admit(s, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Account(4, 8); err != nil {
		t.Fatal(err)
	}
	session.Finish()
	session.Finish()
	if err := session.Account(1, 2); !errors.Is(err, ErrFinished) {
		t.Fatalf("late count after close accepted: %v", err)
	}
	result, err := r.FenceAndWait(context.Background(), s)
	if err != nil || result.Bytes != (Bytes{Uplink: 4, Downlink: 8}) {
		t.Fatalf("double debit after finish: %+v, %v", result, err)
	}
}

func TestOverflowIsPermanentNonProof(t *testing.T) {
	r := New()
	s := scope()
	session, err := r.Admit(s, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Account(math.MaxUint64, 0); err != nil {
		t.Fatal(err)
	}
	if err := session.Account(1, 0); !errors.Is(err, ErrOverflow) {
		t.Fatalf("wrapped byte counter: %v", err)
	}
	session.Finish()
	if _, err := r.FenceAndWait(context.Background(), s); !errors.Is(err, ErrOverflow) {
		t.Fatalf("overflow gave usable observation: %v", err)
	}
}

func TestConcurrentSessionsAndRepeatedFences(t *testing.T) {
	const n = 200
	r := New()
	s := scope()
	sessions := make([]*Session, 0, n)
	var cancels atomic.Int32
	for i := 0; i < n; i++ {
		session, err := r.Admit(s, func() { cancels.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
	}
	var wg sync.WaitGroup
	wg.Add(n)
	for _, session := range sessions {
		session := session
		go func() {
			defer wg.Done()
			if err := session.Account(1, 2); err != nil {
				t.Errorf("count after cancellation: %v", err)
			}
			session.Finish()
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	obs, err := r.FenceAndWait(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if obs.Refundable || !obs.AdmissionFenced || obs.ActiveSessions != 0 ||
		obs.Bytes != (Bytes{Uplink: n, Downlink: 2 * n}) {
		t.Fatalf("race corrupted observation: %+v", obs)
	}
	// Some streams can finish before the fence acquires the lock; all
	// remaining callbacks run at most once each, never on retries.
	for i := 0; i < 8; i++ {
		again, err := r.FenceAndWait(context.Background(), s)
		if err != nil || again.Bytes != obs.Bytes || again.Refundable {
			t.Fatalf("non-idempotent fence: %+v, %v", again, err)
		}
	}
	if got := cancels.Load(); got > n {
		t.Fatalf("repeated fence cancelled %d streams", got)
	}
}
