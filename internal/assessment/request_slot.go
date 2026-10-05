// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import "context"

func (t *readTransport) acquireRequestSlot(ctx context.Context) error {
	for {
		if err := t.waitForBudget(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case t.budget.slots <- struct{}{}:
		}
		t.budget.mu.Lock()
		reset := t.budget.pauses[t.base.Host]
		t.budget.mu.Unlock()
		if reset.Sub(t.clock.Now()) <= 0 {
			return nil
		}
		// A different response may have published a pause while this worker queued.
		<-t.budget.slots
	}
}
