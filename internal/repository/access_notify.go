package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Listen subscribes to NOTIFY capsule_access on a dedicated connection and calls fn(orgID) for every change (SPEC 12.2). It blocks
// until ctx is cancelled and reconnects with a short backoff when the connection drops. After every (re)connection fn is called once
// with uuid.Nil, meaning "flush every snapshot": notifications sent while disconnected are lost, and the TTL of 30 s is only the
// last resort. fn must not block for long (it runs on the listener goroutine). Payloads that are not UUIDs are ignored.
func (s *AccessStore) Listen(ctx context.Context, fn func(orgID uuid.UUID)) error {
	backoff := 200 * time.Millisecond
	for {
		err := s.listenOnce(ctx, fn)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = err // logged by the caller through the metrics of P3; here we only retry
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

func (s *AccessStore) listenOnce(ctx context.Context, fn func(uuid.UUID)) error {
	conn, err := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig.Copy())
	if err != nil {
		return err
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = conn.Close(cctx)
	}()
	if _, err := conn.Exec(ctx, "LISTEN "+AccessNotifyChannel); err != nil {
		return err
	}
	fn(uuid.Nil)
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		if id, perr := uuid.Parse(n.Payload); perr == nil {
			fn(id)
		}
	}
}
