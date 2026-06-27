package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Phase 4 — panel health monitor.
//
// HealthMonitor is a read-only supervisor of the Supervisor: every tick it takes
// a State() snapshot (which RLocks the Supervisor) and derives a per-location
// route health label without ever mutating supervisor state. It also emits
// debounced, flap-suppressed Telegram alerts on state changes, mirroring the
// existing vpn-healthcheck.sh "alert on state change" behaviour.
//
// Tunables (all relative to the ~20s tick):
//   - downAlertTicks: a bare running==false is only escalated to DOWN after this
//     many CONSECUTIVE ticks (~60s) so a normal restart (≤30s backoff window in
//     monitorProcess) never trips an alert.
//   - flapWindow / flapThreshold: positive restart deltas observed within
//     flapWindow; once threshold is reached the location reports Flapping and
//     DOWN alerts are suppressed (the flap ring is the louder signal).
//   - healthyResetWindow (shared with the Supervisor, 120s): a run of at least
//     this uptime clears the flap ring (a single flap after hours of uptime must
//     not count).
const (
	healthTickInterval = 20 * time.Second
	downAlertTicks     = 3
	startingWindow     = 25 * time.Second
	flapWindow         = 10 * time.Minute
	flapThreshold      = 3
)

// Telegram alert wiring. Creds come from env first (OLCRTC_ALERT_TG_TOKEN /
// OLCRTC_ALERT_TG_CHAT); the fallback scrapes the existing healthcheck script so
// we reuse the one bot+chat already approved for this box. Creds are NEVER
// written to config.json.
const (
	healthcheckScriptPath = "/usr/local/bin/vpn-healthcheck.sh"
	defaultAlertChatID    = "408156971"
)

var (
	tgTokenRe = regexp.MustCompile(`(\d{8,}:[A-Za-z0-9_-]{30,})`)
	tgChatRe  = regexp.MustCompile(`(?i)chat[_ ]?id["' =:]+(\d{6,})`)
)

// HealthSnapshot is the payload returned by GET /api/health.
type HealthSnapshot struct {
	GeneratedAt string           `json:"generated_at"`
	Summary     HealthSummary    `json:"summary"`
	Locations   []LocationHealth `json:"locations"`
}

type HealthSummary struct {
	Total     int `json:"total"`
	Connected int `json:"connected"`
	Idle      int `json:"idle"`
	Starting  int `json:"starting"`
	Flapping  int `json:"flapping"`
	Down      int `json:"down"`
	Stopped   int `json:"stopped"`
}

type LocationHealth struct {
	ClientID  string `json:"client_id"`
	Name      string `json:"name"`
	RoomID    string `json:"room_id"`
	Transport string `json:"transport"`
	Status    string `json:"status"`
	Running   bool   `json:"running"`
	PeerCount int    `json:"peer_count"`
	Restarts  int    `json:"restarts"`
	StartedAt string `json:"started_at,omitempty"`
	ExitError string `json:"exit_error,omitempty"`
}

// healthLocState is the per-location memory carried across ticks.
type healthLocState struct {
	downTicks    int
	lastRestarts int
	flaps        []time.Time
	flapping     bool
	alerted      bool // a problem alert is outstanding, awaiting a recovery alert
}

type HealthMonitor struct {
	configPath string
	supervisor *Supervisor

	mu        sync.Mutex
	locStates map[string]*healthLocState
	last      HealthSnapshot
}

func NewHealthMonitor(configPath string, supervisor *Supervisor) *HealthMonitor {
	return &HealthMonitor{
		configPath: configPath,
		supervisor: supervisor,
		locStates:  make(map[string]*healthLocState),
		last: HealthSnapshot{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Locations:   []LocationHealth{},
		},
	}
}

// Run mirrors QuotaEnforcer.Run: an immediate first pass so /api/health has data
// at once, then a steady tick. Read-only throughout.
func (h *HealthMonitor) Run(ctx context.Context) {
	h.tick(time.Now())
	timer := time.NewTimer(healthTickInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			h.tick(time.Now())
			timer.Reset(healthTickInterval)
		}
	}
}

// Snapshot returns the most recently computed health snapshot.
func (h *HealthMonitor) Snapshot() HealthSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last
}

func (h *HealthMonitor) tick(now time.Time) {
	state := h.supervisor.State() // READ-ONLY snapshot under the Supervisor RLock

	h.mu.Lock()
	defer h.mu.Unlock()

	snap := HealthSnapshot{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Locations:   make([]LocationHealth, 0),
	}
	seen := make(map[string]bool)

	for _, client := range state.Clients {
		for _, loc := range client.Locations {
			key := strings.Join([]string{client.ClientID, loc.RoomID, loc.Transport}, ":")
			seen[key] = true
			ls := h.locStates[key]
			if ls == nil {
				ls = &healthLocState{lastRestarts: loc.Runtime.Restarts}
				h.locStates[key] = ls
			}

			rt := loc.Runtime
			peers := 0
			if rt.PeerCount != nil {
				peers = *rt.PeerCount
			}

			// Flap ring: only POSITIVE restart deltas count.
			if rt.Restarts > ls.lastRestarts {
				for i := 0; i < rt.Restarts-ls.lastRestarts; i++ {
					ls.flaps = append(ls.flaps, now)
				}
			}
			ls.lastRestarts = rt.Restarts

			uptime := time.Duration(0)
			if rt.Running && rt.StartedAt != "" {
				if t, err := time.Parse(time.RFC3339, rt.StartedAt); err == nil {
					uptime = now.Sub(t)
				}
			}
			// A healthy run clears the flap memory.
			if rt.Running && uptime >= healthyResetWindow {
				ls.flaps = nil
			}
			ls.flaps = pruneOlderThan(ls.flaps, now.Add(-flapWindow))
			ls.flapping = len(ls.flaps) >= flapThreshold

			// DOWN debounce: count consecutive ticks where a process exists but
			// is not running. A "stopped" location (no process at all, e.g.
			// quota-blocked) is intentional and is NEVER counted as down.
			if rt.Status != "stopped" && !rt.Running {
				ls.downTicks++
			} else {
				ls.downTicks = 0
			}

			status := deriveHealthStatus(rt, peers, uptime, ls)
			h.maybeAlert(client.ClientID, loc, status, ls)

			snap.Locations = append(snap.Locations, LocationHealth{
				ClientID:  client.ClientID,
				Name:      loc.Name,
				RoomID:    loc.RoomID,
				Transport: loc.Transport,
				Status:    status,
				Running:   rt.Running,
				PeerCount: peers,
				Restarts:  rt.Restarts,
				StartedAt: rt.StartedAt,
				ExitError: rt.ExitError,
			})
			tallyHealth(&snap.Summary, status)
		}
	}

	// Forget state for locations that have disappeared (deleted/rotated away).
	for key := range h.locStates {
		if !seen[key] {
			delete(h.locStates, key)
		}
	}

	sort.Slice(snap.Locations, func(i, j int) bool {
		if snap.Locations[i].ClientID != snap.Locations[j].ClientID {
			return snap.Locations[i].ClientID < snap.Locations[j].ClientID
		}
		return snap.Locations[i].Name < snap.Locations[j].Name
	})
	h.last = snap
}

// deriveHealthStatus maps a runtime snapshot to a route-health label. idle /
// peer_count==0 is NEVER Down — an idle-but-running tunnel is healthy.
func deriveHealthStatus(rt RuntimeState, peers int, uptime time.Duration, ls *healthLocState) string {
	if rt.Status == "stopped" {
		return "Stopped"
	}
	if !rt.Running {
		if ls.flapping {
			return "Flapping"
		}
		if ls.downTicks >= downAlertTicks {
			return "Down"
		}
		// Within the restart-backoff window: treat as (re)starting, not Down.
		return "Starting"
	}
	if ls.flapping {
		return "Flapping"
	}
	if uptime > 0 && uptime < startingWindow {
		return "Starting"
	}
	if peers > 0 {
		return "Connected"
	}
	return "Idle"
}

func tallyHealth(s *HealthSummary, status string) {
	s.Total++
	switch status {
	case "Connected":
		s.Connected++
	case "Idle":
		s.Idle++
	case "Starting":
		s.Starting++
	case "Flapping":
		s.Flapping++
	case "Down":
		s.Down++
	case "Stopped":
		s.Stopped++
	}
}

// maybeAlert fires a Telegram alert on entry to a bad state (Down/Flapping) and a
// recovery alert once the location reaches a stable good state (Connected/Idle).
// Transient labels (Starting) neither raise nor clear an alert.
func (h *HealthMonitor) maybeAlert(clientID string, loc LocationState, status string, ls *healthLocState) {
	bad := status == "Down" || status == "Flapping"
	good := status == "Connected" || status == "Idle"
	switch {
	case bad && !ls.alerted:
		ls.alerted = true
		sendTelegramAlert(fmt.Sprintf("olcrtc DOWN: %s / %s [%s] %s (room %s)",
			clientID, loc.Name, loc.Transport, status, loc.RoomID))
	case good && ls.alerted:
		ls.alerted = false
		sendTelegramAlert(fmt.Sprintf("olcrtc OK: %s / %s [%s] recovered (%s)",
			clientID, loc.Name, loc.Transport, status))
	}
}

func pruneOlderThan(times []time.Time, cutoff time.Time) []time.Time {
	if len(times) == 0 {
		return times
	}
	out := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

// telegramAlertCreds resolves the bot token + chat id, env first then a regex
// scrape of the existing healthcheck script. Never persisted to config.json.
func telegramAlertCreds() (token, chat string) {
	token = strings.TrimSpace(os.Getenv("OLCRTC_ALERT_TG_TOKEN"))
	chat = strings.TrimSpace(os.Getenv("OLCRTC_ALERT_TG_CHAT"))
	if token != "" && chat != "" {
		return token, chat
	}
	if data, err := os.ReadFile(healthcheckScriptPath); err == nil {
		text := string(data)
		if token == "" {
			if m := tgTokenRe.FindStringSubmatch(text); m != nil {
				token = m[1]
			}
		}
		if chat == "" {
			if m := tgChatRe.FindStringSubmatch(text); m != nil {
				chat = m[1]
			}
		}
	}
	if chat == "" {
		chat = defaultAlertChatID
	}
	return token, chat
}

func sendTelegramAlert(msg string) {
	token, chat := telegramAlertCreds()
	if token == "" || chat == "" {
		return
	}
	form := url.Values{}
	form.Set("chat_id", chat)
	form.Set("text", msg)
	endpoint := "https://api.telegram.org/bot" + token + "/sendMessage"

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("health: telegram alert failed: %v", err)
		return
	}
	_ = resp.Body.Close()
}
