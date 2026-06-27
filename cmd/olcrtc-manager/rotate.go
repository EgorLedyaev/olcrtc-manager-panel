package main

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"
)

// Phase 4 — autorotation.
//
// The Rotator periodically rotates each running location's jitsi room (and
// crypto key) so a leaked/known room does not stay valid forever. It mirrors
// QuotaEnforcer.Run (a steady tick) and defers all process/config mutation to
// Supervisor.ApplyRotation, which starts the NEW srv FIRST and keeps the OLD one
// running for a grace window so connected clients migrate without a gap.
//
// SHIP DORMANT + SAFE: rotation is OFF unless Config.RotateEvery (or a per-client
// Client.RotateEvery) is set, and even then the Rotator refuses to act unless
// RotateGrace >= 24h and RotateEvery >> RotateGrace.
const (
	rotateTickInterval = 60 * time.Second
	minRotateGrace     = 24 * time.Hour
	// minRotateRatio is the minimum RotateEvery : RotateGrace ratio (the ">>").
	minRotateRatio = 2
)

// parseRefreshDuration parses the validateRefresh grammar ("30s","10m","6h","7d")
// into a Duration, where "d" == 24h. Empty, "0", or any malformed value returns
// 0 (which callers treat as "disabled").
func parseRefreshDuration(s string) time.Duration {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return 0
	}
	unit := s[len(s)-1]
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n < 0 {
		return 0
	}
	switch unit {
	case 's':
		return time.Duration(n) * time.Second
	case 'm':
		return time.Duration(n) * time.Minute
	case 'h':
		return time.Duration(n) * time.Hour
	case 'd':
		return time.Duration(n) * 24 * time.Hour
	default:
		return 0
	}
}

type Rotator struct {
	configPath string
	supervisor *Supervisor
}

func NewRotator(configPath string, supervisor *Supervisor) *Rotator {
	return &Rotator{
		configPath: configPath,
		supervisor: supervisor,
	}
}

func (r *Rotator) Run(ctx context.Context) {
	timer := time.NewTimer(rotateTickInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			r.tick(ctx, time.Now())
			timer.Reset(rotateTickInterval)
		}
	}
}

func (r *Rotator) tick(ctx context.Context, now time.Time) {
	cfg, err := loadConfig(r.configPath)
	if err != nil {
		log.Printf("rotation: load config failed: %v", err)
		return
	}
	cfg.ensureClientsFormat()

	globalEvery := parseRefreshDuration(cfg.RotateEvery)
	if globalEvery <= 0 {
		return // dormant: autorotation disabled
	}
	grace := parseRefreshDuration(cfg.RotateGrace)
	if grace < minRotateGrace {
		log.Printf("rotation: disabled — rotate_grace %q must be >= 24h", cfg.RotateGrace)
		return
	}

	snapshot := r.supervisor.rotationSnapshot()
	rotations := make([]rotation, 0)

	for i := range cfg.Clients {
		client := cfg.Clients[i]
		every := globalEvery
		if raw := strings.TrimSpace(client.RotateEvery); raw != "" {
			every = parseRefreshDuration(raw)
		}
		if every <= 0 {
			continue // disabled for this client
		}
		if every < minRotateRatio*grace {
			log.Printf("rotation: skipping client %q — rotate_every must be >> rotate_grace (>= %s)",
				client.ClientID, (minRotateRatio * grace).String())
			continue
		}
		for j := range cfg.Clients[i].Locations {
			loc := cfg.Clients[i].Locations[j]
			key := locationKey(loc)
			cand, ok := snapshot[key]
			if !ok || !cand.running {
				continue // only rotate a location that is actually up
			}
			if now.Sub(cand.anchor) < every {
				continue // not due yet
			}
			newLoc, ok := rotatedLocation(loc, now)
			if !ok {
				continue // generation failed; retry next tick
			}
			rotations = append(rotations, rotation{
				oldKey: key,
				oldLoc: loc,
				newLoc: newLoc,
				grace:  grace,
				linger: strings.TrimSpace(loc.Carrier) == "jitsi",
			})
		}
	}

	if len(rotations) == 0 {
		return
	}

	// Gate: refuse to start anything unless the fully-rotated config validates.
	prospective := cfg
	prospective.Clients = cloneClients(cfg.Clients)
	for _, rot := range rotations {
		replaceLocation(&prospective, rot.oldKey, rot.newLoc)
	}
	prospective.Normalize()
	if err := prospective.Validate(); err != nil {
		log.Printf("rotation: aborting — rotated config invalid: %v", err)
		return
	}

	r.supervisor.ApplyRotation(ctx, r.configPath, cfg, rotations)
}

// rotation describes one location's pending rotation. linger is true for jitsi
// (the room itself changes, so locationKey changes and the OLD srv must overlap
// the NEW one for grace); false for non-jitsi key-only rotation (room unchanged,
// same locationKey, no overlap).
type rotation struct {
	oldKey string
	oldLoc Location
	newLoc Location
	grace  time.Duration
	linger bool
}

// rotatedLocation derives the post-rotation Location: jitsi rotates room+key;
// any other carrier rotates the crypto key only (room generation is unsupported).
// RotatedAt is stamped so the next age check anchors on it.
func rotatedLocation(loc Location, now time.Time) (Location, bool) {
	next := loc
	key, err := randomHex(32)
	if err != nil {
		log.Printf("rotation: key generation failed for %s: %v", locationKey(loc), err)
		return Location{}, false
	}
	if strings.TrimSpace(loc.Carrier) == "jitsi" {
		room, err := generateRoomIDForCarrier(loc.Carrier, loc.Endpoint.RoomID)
		if err != nil {
			log.Printf("rotation: room generation failed for %s: %v", locationKey(loc), err)
			return Location{}, false
		}
		next.Endpoint.RoomID = room
	}
	next.Endpoint.Key = key
	next.RotatedAt = now.UTC().Format(time.RFC3339)
	return next, true
}

// rotationCandidate is the running view of a location the Rotator ages against.
type rotationCandidate struct {
	loc     Location
	anchor  time.Time
	running bool
}

// rotationSnapshot returns, under RLock, the rotatable running locations keyed by
// locationKey. The age anchor is the persisted RotatedAt when set, else the
// process start time. Lingering OLD srvs are excluded (never rotate a rotation).
func (s *Supervisor) rotationSnapshot() map[string]rotationCandidate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]rotationCandidate, len(s.processes))
	for key, p := range s.processes {
		if p == nil {
			continue
		}
		if _, lingering := s.lingering[key]; lingering {
			continue
		}
		anchor := p.started
		if ra := strings.TrimSpace(p.location.RotatedAt); ra != "" {
			if t, err := time.Parse(time.RFC3339, ra); err == nil {
				anchor = t
			}
		}
		out[key] = rotationCandidate{
			loc:     p.location,
			anchor:  anchor,
			running: p.state().Running,
		}
	}
	return out
}

// ApplyRotation starts each NEW srv first; on a start error it leaves the OLD
// srv running, does NOT linger it, and lets the next tick retry. For jitsi it
// lingers the OLD key and schedules a grace teardown (overlap); for non-jitsi it
// swaps in place (no overlap). Only rotations that actually started are persisted
// (saveConfigWithoutBackup + audit). The reload stop-loop skips s.lingering keys.
func (s *Supervisor) ApplyRotation(ctx context.Context, configPath string, cfg Config, rotations []rotation) {
	s.mu.Lock()
	defer s.mu.Unlock()

	working := cfg
	working.Clients = cloneClients(cfg.Clients)

	appliedAny := false
	applied := make([]string, 0, len(rotations))

	for _, rot := range rotations {
		newKey := locationKey(rot.newLoc)
		p, err := s.start(ctx, s.olcrtcPath, rot.newLoc)
		if err != nil {
			log.Printf("rotation: start new srv for %s failed: %v (old %s left running, retry next tick)",
				newKey, err, rot.oldKey)
			continue
		}

		if rot.linger {
			// jitsi: distinct new key — keep the OLD one running for grace.
			s.registerQuotaLocked(rot.newLoc, quotaForClient(working, rot.newLoc.ClientID), p)
			s.processes[newKey] = p
			s.monitorProcess(ctx, newKey, p)

			s.lingering[rot.oldKey] = time.Now()
			oldKey, grace := rot.oldKey, rot.grace
			time.AfterFunc(grace, func() {
				s.mu.Lock()
				defer s.mu.Unlock()
				delete(s.lingering, oldKey)
				s.stopLocked(oldKey)
			})
		} else {
			// non-jitsi: same key (room unchanged) — stop old, swap new in place.
			s.stopLocked(rot.oldKey)
			s.registerQuotaLocked(rot.newLoc, quotaForClient(working, rot.newLoc.ClientID), p)
			s.processes[newKey] = p
			s.monitorProcess(ctx, newKey, p)
		}

		replaceLocation(&working, rot.oldKey, rot.newLoc)
		appliedAny = true
		applied = append(applied, rot.oldKey+" -> "+newKey)
	}

	if !appliedAny {
		return
	}

	working.Normalize()
	s.cfg = working
	if err := saveConfigWithoutBackup(configPath, working); err != nil {
		log.Printf("rotation: save config failed: %v", err)
	}
	appendAudit(configPath, "rotated", strings.Join(applied, "; "))
}

// cloneClients deep-copies the Clients slice and each client's Locations slice so
// callers can replace whole Location entries without aliasing the source config.
func cloneClients(in []Client) []Client {
	out := make([]Client, len(in))
	copy(out, in)
	for i := range out {
		locs := make([]Location, len(in[i].Locations))
		copy(locs, in[i].Locations)
		out[i].Locations = locs
	}
	return out
}

// replaceLocation swaps the location whose current locationKey == oldKey for
// newLoc (matches both jitsi room-change and non-jitsi key-only rotation, since
// the crypto key is not part of locationKey).
func replaceLocation(cfg *Config, oldKey string, newLoc Location) {
	for i := range cfg.Clients {
		for j := range cfg.Clients[i].Locations {
			if locationKey(cfg.Clients[i].Locations[j]) == oldKey {
				cfg.Clients[i].Locations[j] = newLoc
				return
			}
		}
	}
}
