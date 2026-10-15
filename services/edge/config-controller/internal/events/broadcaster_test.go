package events

import (
	"sync"
	"testing"
	"time"
)

func TestBroadcaster_SubscribeAndReceive(t *testing.T) {
	b := NewBroadcaster()
	defer b.Close()

	chSin, cancelSin := b.Subscribe("singapore")
	defer cancelSin()

	chDhk, cancelDhk := b.Subscribe("dhaka")
	defer cancelDhk()

	if count := b.SubscriberCount("singapore"); count != 1 {
		t.Fatalf("expected 1 subscriber for singapore, got %d", count)
	}

	b.BroadcastConfigUpdate("singapore", "sha256-sin-01")

	select {
	case evt := <-chSin:
		if evt.Type != EventConfigUpdate {
			t.Errorf("expected EventConfigUpdate, got %s", evt.Type)
		}
		if evt.Checksum != "sha256-sin-01" {
			t.Errorf("expected checksum sha256-sin-01, got %s", evt.Checksum)
		}
		if evt.PoPID != "singapore" {
			t.Errorf("expected pop_id singapore, got %s", evt.PoPID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for event on singapore channel")
	}

	// Dhaka channel should receive nothing
	select {
	case evt := <-chDhk:
		t.Fatalf("unexpected event on dhaka channel: %+v", evt)
	case <-time.After(50 * time.Millisecond):
		// OK
	}
}

func TestBroadcaster_WildcardDelivery(t *testing.T) {
	b := NewBroadcaster()
	defer b.Close()

	chWild, cancelWild := b.Subscribe("*")
	defer cancelWild()

	chSin, cancelSin := b.Subscribe("singapore")
	defer cancelSin()

	b.BroadcastConfigUpdate("singapore", "sha256-sin-02")

	// Both should receive the event
	select {
	case evt := <-chSin:
		if evt.Checksum != "sha256-sin-02" {
			t.Errorf("chSin received wrong checksum: %s", evt.Checksum)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for event on chSin")
	}

	select {
	case evt := <-chWild:
		if evt.Checksum != "sha256-sin-02" {
			t.Errorf("chWild received wrong checksum: %s", evt.Checksum)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for event on chWild")
	}
}

func TestBroadcaster_GlobalWildcardBroadcast(t *testing.T) {
	b := NewBroadcaster()
	defer b.Close()

	chSin, cancelSin := b.Subscribe("singapore")
	defer cancelSin()

	chDhk, cancelDhk := b.Subscribe("dhaka")
	defer cancelDhk()

	// Broadcast globally to "*"
	b.BroadcastConfigUpdate("*", "sha256-global-01")

	select {
	case evt := <-chSin:
		if evt.Checksum != "sha256-global-01" {
			t.Errorf("chSin received wrong checksum: %s", evt.Checksum)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for event on chSin")
	}

	select {
	case evt := <-chDhk:
		if evt.Checksum != "sha256-global-01" {
			t.Errorf("chDhk received wrong checksum: %s", evt.Checksum)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for event on chDhk")
	}
}

func TestBroadcaster_UnsubscribeCleanup(t *testing.T) {
	b := NewBroadcaster()
	defer b.Close()

	ch, cancel := b.Subscribe("singapore")
	if b.TotalSubscribers() != 1 {
		t.Fatalf("expected 1 total subscriber, got %d", b.TotalSubscribers())
	}

	cancel()

	// Calling cancel twice should be idempotent
	cancel()

	if b.TotalSubscribers() != 0 {
		t.Fatalf("expected 0 total subscribers after cancel, got %d", b.TotalSubscribers())
	}

	// Channel should be closed
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel to be closed")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("channel was not closed in a timely manner")
	}
}

func TestBroadcaster_NonBlockingSlowConsumer(t *testing.T) {
	// Small buffer size of 2
	b := NewBroadcasterWithBufferSize(2)
	defer b.Close()

	chSlow, cancelSlow := b.Subscribe("singapore")
	defer cancelSlow()

	chFast, cancelFast := b.Subscribe("singapore")
	defer cancelFast()

	// Broadcast 5 events without draining chSlow
	for i := 0; i < 5; i++ {
		b.BroadcastConfigUpdate("singapore", "chk")
	}

	// chFast should still have received first 2 items without blocking
	countFast := 0
	for {
		select {
		case <-chFast:
			countFast++
		default:
			goto fastDone
		}
	}
fastDone:
	if countFast != 2 {
		t.Fatalf("expected chFast to have buffered 2 events, got %d", countFast)
	}

	// chSlow should have buffered 2 events, remaining 3 dropped
	countSlow := 0
	for {
		select {
		case <-chSlow:
			countSlow++
		default:
			goto slowDone
		}
	}
slowDone:
	if countSlow != 2 {
		t.Fatalf("expected chSlow to have buffered 2 events, got %d", countSlow)
	}
}

func TestBroadcaster_ConcurrentAccess(t *testing.T) {
	b := NewBroadcaster()
	defer b.Close()

	var wg sync.WaitGroup
	workers := 10

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ch, cancel := b.Subscribe("singapore")
			defer cancel()

			for j := 0; j < 50; j++ {
				b.BroadcastConfigUpdate("singapore", "chk-concurrent")
				select {
				case <-ch:
				case <-time.After(10 * time.Millisecond):
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestBroadcaster_Close(t *testing.T) {
	b := NewBroadcaster()
	ch1, _ := b.Subscribe("singapore")
	ch2, _ := b.Subscribe("dhaka")

	b.Close()

	if b.TotalSubscribers() != 0 {
		t.Errorf("expected 0 subscribers after Close, got %d", b.TotalSubscribers())
	}

	// Both channels should be closed
	_, ok1 := <-ch1
	_, ok2 := <-ch2
	if ok1 || ok2 {
		t.Fatal("expected channels to be closed upon broadcaster Close")
	}

	// Subscribing after close returns a closed channel
	ch3, cancel3 := b.Subscribe("frankfurt")
	defer cancel3()
	_, ok3 := <-ch3
	if ok3 {
		t.Fatal("expected newly subscribed channel to be immediately closed after Broadcaster.Close")
	}
}
