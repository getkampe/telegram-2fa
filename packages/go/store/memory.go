// Package store holds the bundled CodeStore and IdentityStore implementations.
package store

import (
	"sync"
	"time"

	telegram2fa "github.com/getkampe/telegram-2fa/packages/go"
)

// MemoryCodeStore is an in-process code store, for tests and single-process
// programs.
//
// Not for production behind more than one process: each would hold its own
// copy, so a code issued by one request would be invisible to the next. Use
// Redis, or a table with an expires_at column.
//
// Every mutation holds the mutex, and Take does its read and its delete inside
// one critical section. Go makes that failure mode easy to hit: goroutines are
// genuinely preemptible, so a read-then-delete pair without a lock lets two
// verifications observe the same record and both succeed. The tests run real
// goroutines through a sync.WaitGroup to prove it, and `go test -race` is part
// of CI.
type MemoryCodeStore struct {
	clock telegram2fa.Clock
	mu    sync.Mutex
	items map[string]memoryItem
}

type memoryItem struct {
	value     any
	expiresAt int64
}

// NewMemoryCodeStore returns an empty store. A nil clock means the system one.
func NewMemoryCodeStore(clock telegram2fa.Clock) *MemoryCodeStore {
	if clock == nil {
		clock = telegram2fa.SystemClock{}
	}

	return &MemoryCodeStore{clock: clock, items: map[string]memoryItem{}}
}

func (s *MemoryCodeStore) Get(key string) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.read(key), nil
}

func (s *MemoryCodeStore) Put(key string, value any, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.items[key] = memoryItem{value: value, expiresAt: s.clock.Now() + int64(ttl.Seconds())}

	return nil
}

func (s *MemoryCodeStore) Forget(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.items, key)

	return nil
}

func (s *MemoryCodeStore) Take(key string) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Read and delete in one critical section, so a second caller cannot
	// observe the value this one is removing.
	value := s.read(key)
	delete(s.items, key)

	return value, nil
}

func (s *MemoryCodeStore) Add(key string, value any, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.read(key) != nil {
		return false, nil
	}

	s.items[key] = memoryItem{value: value, expiresAt: s.clock.Now() + int64(ttl.Seconds())}

	return true, nil
}

// read requires the mutex to be held.
func (s *MemoryCodeStore) read(key string) any {
	item, ok := s.items[key]
	if !ok {
		return nil
	}

	if item.expiresAt <= s.clock.Now() {
		delete(s.items, key)

		return nil
	}

	return item.value
}

// MemoryIdentityStore is an in-memory identity store.
//
// It models both rules a real store must enforce: one chat belongs to one
// account, and a transition only applies when the stored generation is the one
// the caller expected. Rows survive unlinking, because the generation has to.
type MemoryIdentityStore struct {
	clock telegram2fa.Clock
	mu    sync.Mutex
	rows  map[string]telegram2fa.Identity
}

// NewMemoryIdentityStore returns an empty store. A nil clock means the system one.
func NewMemoryIdentityStore(clock telegram2fa.Clock) *MemoryIdentityStore {
	if clock == nil {
		clock = telegram2fa.SystemClock{}
	}

	return &MemoryIdentityStore{clock: clock, rows: map[string]telegram2fa.Identity{}}
}

func (s *MemoryIdentityStore) FindByUserID(userID string) (*telegram2fa.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	row, ok := s.rows[userID]
	if !ok {
		return nil, nil
	}

	copied := row

	return &copied, nil
}

func (s *MemoryIdentityStore) FindByChatID(chatID string) (*telegram2fa.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.findByChatID(chatID), nil
}

func (s *MemoryIdentityStore) Transition(
	userID, chatID, expected, next string,
) (*telegram2fa.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	currentGeneration := ""
	if row, ok := s.rows[userID]; ok {
		currentGeneration = row.Generation
	}

	if expected != telegram2fa.AnyGeneration && currentGeneration != expected {
		// The expectation failed, so the stored row is left exactly as it was.
		// Returning nil rather than an error lets the caller decide whether
		// this is a conflict or a stale token.
		return nil, nil
	}

	if chatID != "" {
		if holder := s.findByChatID(chatID); holder != nil && holder.UserID != userID {
			return nil, telegram2fa.ErrChatAlreadyLinked
		}
	}

	linkedAt := int64(0)
	if chatID != "" {
		linkedAt = s.clock.Now()
	}

	identity := telegram2fa.Identity{
		UserID:     userID,
		ChatID:     chatID,
		LinkedAt:   linkedAt,
		Generation: next,
	}

	s.rows[userID] = identity

	return &identity, nil
}

// Seed stores a verified enrollment without going through a link flow, for
// tests.
func (s *MemoryIdentityStore) Seed(userID, chatID, generation string) telegram2fa.Identity {
	s.mu.Lock()
	defer s.mu.Unlock()

	identity := telegram2fa.Identity{
		UserID:     userID,
		ChatID:     chatID,
		LinkedAt:   s.clock.Now(),
		Generation: generation,
	}

	s.rows[userID] = identity

	return identity
}

// findByChatID requires the mutex to be held.
func (s *MemoryIdentityStore) findByChatID(chatID string) *telegram2fa.Identity {
	for _, row := range s.rows {
		if row.ChatID != "" && row.ChatID == chatID {
			copied := row

			return &copied
		}
	}

	return nil
}
