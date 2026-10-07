"""
MSFS PFD Bridge
Connects to MSFS via SimConnect + SimBrief for flight plan tracking.

Requirements:
    pip install -r requirements.txt

Usage:
    1. File a flight plan on SimBrief
    2. Start MSFS and load a flight (any spawn, no World Map plan needed)
    3. Run: python msfs_bridge.py
    4. Open http://<your-pc-local-ip>:5000 on your phone
"""

import json
import re
import threading
import time
import socket
import struct
import os
import sys
import math
import multiprocessing
import secrets
import traceback
import logging
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler
import requests
from flask import Flask, request, send_from_directory
from flask_sock import Sock

# Resolve base directory — works both as .py and as PyInstaller .exe
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_MAX_BYTES = 5 * 1024 * 1024  # 5MB per file
LOG_BACKUP_COUNT = 3             # + 3 rotated backups = 20MB ceiling per process's log

def setup_logging(name):
    # Bounded (unlike bridge.log/bridge.err.log, which are launch_pfd.ps1's
    # raw, unrotated stdout/stderr redirects of the MAIN process only — see
    # requirements.txt/infra notes for the staged launcher-side half of this).
    # One log file per PROCESS, not one shared file: simconnect_worker and
    # xplane_worker each run as their own OS process (multiprocessing.Process,
    # not a thread), and RotatingFileHandler's rename-based rotation isn't
    # safe with more than one process holding an independent handle to the
    # same file — giving each its own file sidesteps that entirely, at the
    # cost of the log stream being split across files instead of unified.
    # Must be called explicitly inside each multiprocessing worker function
    # (not left to run unguarded at module level), since Windows' spawn-based
    # multiprocessing re-imports this whole module in the child process —
    # anything at true module level runs in every worker too, which is
    # exactly the multi-process-same-file collision this avoids.
    logs_dir = os.path.join(BASE_DIR, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    file_handler = RotatingFileHandler(
        os.path.join(logs_dir, f"{name}.log"), maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    root.addHandler(file_handler)
    root.addHandler(stream_handler)  # keeps existing PowerShell stdout redirection working unchanged

try:
    from SimConnect import SimConnect, AircraftRequests, AircraftEvents
    SIMCONNECT_AVAILABLE = True
except ImportError:
    SIMCONNECT_AVAILABLE = False
    logging.warning("SimConnect not found. Running in demo mode.")

app = Flask(__name__, static_folder=None)
sock = Sock(app)

# Personal settings live in config.json next to this file (not committed).
# Copy config.example.json to config.json and fill in your SimBrief username.
def _load_config():
    path = os.path.join(BASE_DIR, "config.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logging.warning(f"[Config] Could not read config.json: {e}")
    return {}

CONFIG = _load_config()
SIMBRIEF_USERNAME = os.environ.get("SIMBRIEF_USERNAME") or CONFIG.get("simbrief_username", "")
SIMBRIEF_API = f"https://www.simbrief.com/api/xml.fetcher.php?username={SIMBRIEF_USERNAME}&json=1"

# Login password: gates only POST /login (and the break-glass POST /logout_all)
# rather than every request. Persisted to disk so it survives a bridge
# restart. Previously this same secret rode along on every single request as
# a ?key= query param (and lived forever in the bookmarked URL) — now it's
# only ever submitted once per device, over the POST body, to mint a session.
AUTH_TOKEN_PATH = os.path.join(BASE_DIR, "auth_token.txt")


_TOKEN_SHAPE_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _load_or_create_auth_token():
    if os.path.exists(AUTH_TOKEN_PATH):
        existing = open(AUTH_TOKEN_PATH, "r").read().strip()
        # str.strip() doesn't remove null bytes, so a file corrupted to nulls
        # (e.g. by two bridge processes racing to write it on startup) used
        # to read back as "non-empty" and get reused forever - the corrupted
        # token could never self-heal. token_urlsafe() output is always in
        # this charset, so anything outside it can only be corruption.
        if existing and _TOKEN_SHAPE_RE.match(existing):
            return existing
    token = secrets.token_urlsafe(24)
    with open(AUTH_TOKEN_PATH, "w") as f:
        f.write(token)
    return token


AUTH_TOKEN = _load_or_create_auth_token()
logging.info(f"[Auth] Password loaded. Log in once per device at the app's login screen (see launch_pfd.ps1 status window).")

# Session store: cookie-based, sliding-free flat TTL (simplest thing that
# actually satisfies "leaked link/session eventually stops working, and can
# be revoked"). Kept in memory as the source of truth and only flushed to
# disk on login/logout/logout_all — not on every one of the ~20/sec /data or
# /ws hits, which would otherwise turn every poll into a disk write.
SESSION_PATH = os.path.join(BASE_DIR, "sessions.json")
SESSION_TTL_SECONDS = 30 * 24 * 3600  # 30 days from login, flat (no sliding renewal)
EXEMPT_PATHS = ("/", "/login", "/logout_all", "/apple-touch-icon.png", "/plane-icon.png", "/logo.png")

sessions_lock = threading.Lock()


def _load_sessions():
    if os.path.exists(SESSION_PATH):
        try:
            data = json.load(open(SESSION_PATH))
            now = time.time()
            return {sid: exp for sid, exp in data.items() if isinstance(exp, (int, float)) and exp > now}
        except (json.JSONDecodeError, OSError, TypeError):
            pass
    return {}


def _save_sessions():
    with open(SESSION_PATH, "w") as f:
        json.dump(sessions, f)


sessions = _load_sessions()


def _set_session_cookie(response, sid=""):
    # The tray app polls its own status over plain http://localhost - a
    # Secure-flagged cookie set there would never be sent back (browsers/
    # WebRequestSession withhold Secure cookies on non-TLS connections),
    # which is exactly what caused perpetual 403s on local /data polls.
    # The phone always goes through the HTTPS tunnel/Worker, so it's
    # unaffected either way.
    is_local = request.host.split(":")[0] in ("localhost", "127.0.0.1", "::1", "[::1]")
    response.set_cookie(
        "session", sid,
        max_age=(SESSION_TTL_SECONDS if sid else 0),
        path="/", secure=not is_local, httponly=True, samesite="Lax",
    )
    return response


@app.before_request
def _require_session():
    if request.path in EXEMPT_PATHS:
        return
    sid = request.cookies.get("session", "")
    with sessions_lock:
        expires = sessions.get(sid)
    if not sid or not expires or expires < time.time():
        return app.response_class(
            response=json.dumps({"status": "error", "message": "unauthorized"}),
            status=403,
            mimetype="application/json",
        )

# SimConnect sample rate (also used as the AircraftRequests cache TTL, so the
# two stay in lockstep). 50ms = 20Hz — the main lever for PFD smoothness,
# since interpolation on the client can only be as good as the source data.
LOOP_INTERVAL_MS = 50
LOOP_INTERVAL_S = LOOP_INTERVAL_MS / 1000
WP_UPDATE_EVERY = 4  # recompute waypoint distances/ETE every 4th iteration (~200ms) — doesn't need PFD-rate updates

# MSFS pause ground-truth: ZULU_TIME (a real in-sim clock, seconds — confirmed
# present in the installed python-SimConnect's own RequestList.py, no library
# patching needed) stops advancing the instant MSFS enters ANY paused state
# (full Esc-menu pause or active/photo pause) — unlike MSFS's own pause
# *events*, which are documented-unreliable (see sim_paused_tracked's
# comment). Require a few consecutive unchanged readings, not one, so a
# single duplicate-frame delivery can't cause a one-tick false "paused" blip.
PAUSE_FREEZE_TICKS = 3

# MSFS reconnect: how many consecutive failed AIRSPEED_INDICATED reads before
# treating the SimConnect handle as dead and reconnecting (see
# simconnect_worker's per-tick liveness check). A short streak, not a single
# failed tick, so one transient SimConnect hiccup can't tear down and rebuild
# a perfectly fine connection.
LIVENESS_FAIL_STREAK = 3

# Idle throttling: python-SimConnect's AircraftRequests has no way to batch
# multiple simvars into one data definition/subscription — every one of the
# ~20 variables read per tick is its own independent, blocking
# RequestDataOnSimObjectType round trip (confirmed by reading the installed
# library's own RequestList.py/SimConnect.py, not assumed). At 20Hz that's
# ~400+ discrete requests/sec sustained the entire time the tray app is
# running, whether or not a phone is actually looking at the PFD. Neither
# MSFS's SimConnect server thread nor X-Plane's UDP responder need to be fed
# at that rate when nobody's watching, so both workers drop to a much lower
# rate whenever no client has hit /data or held /ws open recently — cut
# unconditionally, since a lower steady-state request rate against the sim
# is strictly safer than a higher one regardless of whether it was ever
# proven to matter for any specific past incident.
CLIENT_IDLE_TIMEOUT_S = 15   # no /data poll or open /ws in this long -> considered idle
IDLE_POLL_EVERY = 40         # while idle, simconnect_worker only fetches telemetry every Nth tick (40 * 50ms = 2s)

client_activity_lock = threading.Lock()
last_client_activity = 0.0   # time.monotonic(); 0 = no client seen yet this run


def mark_client_active():
    global last_client_activity
    with client_activity_lock:
        last_client_activity = time.monotonic()


def client_is_idle():
    with client_activity_lock:
        last = last_client_activity
    return last == 0.0 or (time.monotonic() - last) > CLIENT_IDLE_TIMEOUT_S

# Flight plan state
fpl_lock = threading.Lock()
fpl_waypoints = []   # list of {ident, lat, lon, alt_ft}
fpl_origin = ""
fpl_dest = ""
fpl_index = 0        # current active waypoint index

# Remote-pause state
DESCENT_GRADIENT_FT_PER_NM = 318  # ~3-degree glide path rule of thumb, used only to estimate TOD

pause_lock = threading.Lock()
pause_armed = False
pause_mode = None            # "distance" | "tod" | "time"
pause_threshold_nm = 0.0     # user-set, only meaningful in "distance" mode
pause_time_target = 0.0      # user-set unix epoch (UTC), only meaningful in "time" mode
pause_fired = False          # edge-trigger guard — reset only on re-arm

# Our own best-known pause state. Updated two ways: (1) the moment WE send a
# pause/resume command (see send_sim_command) — the immediate-feedback path,
# and the only source of truth while disconnected; (2) overridden each tick
# by real ground truth once connected — for X-Plane that's the
# sim/time/paused dataref, for MSFS it's the ZULU_TIME-freeze detection in
# simconnect_worker (see PAUSE_FREEZE_TICKS's comment). MSFS's own pause-state
# *events* (the "Paused"/"Unpaused" system events that python-SimConnect's
# sm.paused tracks, and SimConnect_RequestSystemState) are both documented as
# unreliable in current MSFS — sm.paused was tried and confirmed not updating
# in practice, and RequestSystemState crashed the worker process when tried
# (see simconnect_worker's comment) — which is why ground truth comes from
# the clock instead of an event.
sim_paused_lock = threading.Lock()
sim_paused_tracked = False

# Real-world testing (2026-08-11, live flight, Fenix A321) found the button
# effectively dead after any pause: the supervisor loop re-applies
# msfs_paused_ground_truth on every ~50ms tick (see its override below), and
# the ZULU_TIME freeze check evidently never reached PAUSE_FREEZE_TICKS
# consecutive equal reads in that session even though the sim WAS genuinely
# paused (confirmed via Dev Mode's own pause indicator) — so the just-issued
# command's optimistic True got stomped back to False within ~1 tick, the UI
# never showed "paused", and the button could never offer resume (had to be
# cleared from Dev Mode's own "Resume Simulation" instead). Root cause of the
# freeze check itself not firing is still unconfirmed (float jitter in
# ZULU_TIME vs. it genuinely not freezing for this pause path — needs live
# instrumentation to pin down, not guessed here). Until that's root-caused,
# give a manual command this grace window to stand before ground truth is
# trusted to override it, so a real command is never immediately overwritten
# by a heuristic that's demonstrated to default to "running" when unsure.
# Self-healing for pauses/resumes NOT initiated via this app's own button
# (e.g. the user hits Esc themselves) still works after the grace window.
PAUSE_GRACE_S = 6.0
last_manual_cmd_ts = 0.0

# Telemetry state
latest_data = {
    "ias": 0, "tas": 0, "gs": 0, "mach": 0,
    "pitch": 0, "bank": 0,
    "heading": 0, "altitude": 0, "vs": 0,
    "ap_speed": 0, "ap_altitude": 0, "ap_heading": 0,
    "ap_active": False, "fd_active": False, "at_active": False,
    "lnav_active": False,
    "ap_mode": "---", "roll_mode": "---", "pitch_mode": "---", "speed_mode": "---",
    "wp_next": "-----", "wp_distance": 0, "wp_ete": 0, "wp_bearing": 0,
    "wp_index": 0, "wp_total": 0,
    "dest": "----", "dest_distance": 0, "dest_ete": 0,
    "track_error": 0,
    "origin": "----", "origin_rwy": "",
    "aircraft_type": "", "aircraft_reg": "",
    "baro": 1013,
    "connected": False, "sim_running": False,
    "fpl_loaded": False,
    "pause_armed": False, "pause_mode": None, "pause_threshold_nm": 0,
    "pause_time_target": 0,
    "pause_estimated_tod_nm": 0,
    "sim_paused": False,
}

data_lock = threading.Lock()


# ─── Math helpers ─────────────────────────────────────────────────────────────

def haversine_nm(lat1, lon1, lat2, lon2):
    """Distance in nautical miles between two lat/lon points."""
    R = 3440.065  # Earth radius in nm
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))


def bearing(lat1, lon1, lat2, lon2):
    """True bearing in degrees from point 1 to point 2."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dlam = math.radians(lon2 - lon1)
    x = math.sin(dlam) * math.cos(phi2)
    y = math.cos(phi1)*math.sin(phi2) - math.sin(phi1)*math.cos(phi2)*math.cos(dlam)
    return (math.degrees(math.atan2(x, y)) + 360) % 360


def normalize(h):
    return h % 360


def track_error(desired_bearing, actual_track):
    """Signed track error: positive = right of course, negative = left."""
    err = (desired_bearing - actual_track + 540) % 360 - 180
    return round(err, 1)


def estimate_tod_distance_nm(cruise_alt_ft, dest_elev_ft):
    """
    Rough TOD estimate from a fixed descent gradient — not aircraft-FMC-derived,
    since no confirmed source for that exists yet across the aircraft this app
    targets. Deliberately conservative/simple rather than precise.
    """
    if cruise_alt_ft <= dest_elev_ft:
        return 0
    return (cruise_alt_ft - dest_elev_ft) / DESCENT_GRADIENT_FT_PER_NM


def current_tod_estimate_nm():
    """Distance-from-destination of SimBrief's own computed top-of-descent
    point, not a generic gradient guess. SimBrief inserts a fix literally
    named "TOD" into the navlog wherever its planning engine computes a
    descent profile for the filed aircraft/route (confirmed against a real
    fetched OFP, not assumed) — that point already accounts for the actual
    aircraft's performance profile and cruise altitude, which a fixed
    ft-per-nm gradient never can. Distance from it to destination is summed
    leg-by-leg exactly like dest_distance is elsewhere in this file.
    Falls back to the fixed-gradient estimate only if this particular OFP
    has no TOD fix (e.g. an incomplete performance profile on SimBrief's end)."""
    with fpl_lock:
        wpts = fpl_waypoints[:]
    if not wpts:
        return 0

    tod_idx = next((i for i, w in enumerate(wpts) if w["ident"].upper() == "TOD"), None)
    if tod_idx is not None:
        dist = 0.0
        for i in range(tod_idx, len(wpts) - 1):
            dist += haversine_nm(wpts[i]["lat"], wpts[i]["lon"], wpts[i + 1]["lat"], wpts[i + 1]["lon"])
        return round(dist, 1)

    cruise_alt = max(w["alt_ft"] for w in wpts)
    dest_elev = wpts[-1]["alt_ft"]
    return round(estimate_tod_distance_nm(cruise_alt, dest_elev), 1)


# worker_shared/worker_lock are set once the real SimConnect worker process is
# spawned (see _simconnect_supervisor_impl) — module-level so Flask route
# handlers (running in the main thread) can reach across into that process.
worker_shared = None
worker_lock = None

# xp_worker_shared/xp_worker_lock are the X-Plane 12 equivalent, set by
# _xplane_supervisor_impl. Both supervisors run concurrently and independently
# of each other (only one real sim is ever actually running at a time) —
# active_backend below is the arbitration that decides which one is allowed
# to write to latest_data, so the one that ISN'T actually connected can't
# stomp the other's live telemetry with "disconnected" on every tick.
xp_worker_shared = None
xp_worker_lock = None

active_backend_lock = threading.Lock()
active_backend = {"name": None}  # "msfs" | "xplane" | None


def _claim_backend(name):
    """True if `name` is (or becomes) the backend allowed to write to
    latest_data this tick. False if the other backend already holds it —
    caller should skip its data_lock write entirely rather than overwrite."""
    with active_backend_lock:
        if active_backend["name"] in (None, name):
            active_backend["name"] = name
            return True
        return False


def _release_backend(name):
    """Give up the claim on disconnect, but only if we're the one holding
    it — if the other backend is active, this is a no-op (nothing to
    release, and nothing should be written to latest_data either)."""
    with active_backend_lock:
        if active_backend["name"] == name:
            active_backend["name"] = None


def _write_disconnected_state(name, sim_paused_now):
    """Shared disconnected-branch logic for both sim backends: if the OTHER
    backend currently holds the claim (it's the one actually connected),
    skip entirely rather than stomp its live telemetry with "disconnected"
    on this backend's own polling tick."""
    with active_backend_lock:
        other_active = active_backend["name"] not in (None, name)
    if other_active:
        return
    _release_backend(name)
    with data_lock:
        latest_data["connected"] = False
        latest_data["sim_running"] = False
        latest_data["sim_paused"] = sim_paused_now


def send_sim_command(action):
    """Ask whichever sim backend is actually connected (see active_backend)
    to pause/resume, and update our own tracked pause state to match
    immediately — see sim_paused_tracked's comment for why we track our own
    commanded state rather than reading it back from the sim (MSFS's own
    pause signals are unreliable; X-Plane's sim/time/paused dataref actually
    works but isn't used here so both backends share one consistent
    frontend-facing behavior). In demo mode / no live worker, only the
    tracked state changes, so the pause/resume toggle is testable end-to-end
    without a real connection."""
    global sim_paused_tracked, last_manual_cmd_ts
    with sim_paused_lock:
        sim_paused_tracked = (action == "pause")
        last_manual_cmd_ts = time.monotonic()  # see PAUSE_GRACE_S's comment

    with active_backend_lock:
        backend = active_backend["name"]

    if backend == "xplane" and xp_worker_shared is not None and xp_worker_lock is not None:
        with xp_worker_lock:
            xp_worker_shared["_cmd"] = {"action": action, "nonce": time.monotonic()}
        return True

    if worker_shared is None or worker_lock is None:
        logging.info(f"[Pause] No active sim worker — simulated '{action}' (demo mode or sim not yet connected).")
        return True
    with worker_lock:
        worker_shared["_cmd"] = {"action": action, "nonce": time.monotonic()}
    return True


def check_auto_pause(dest_distance_nm, tod_estimate_nm, has_plan):
    """Fires the armed auto-pause exactly once when its active condition is
    met: a fixed nm value or the live TOD estimate (both need dest_distance_nm
    to cross the threshold), or wall-clock UTC reaching a fixed target time.
    has_plan guards against dest_distance_nm's "no flight plan loaded" default
    of 0 being mistaken for "arrived at destination" — without it, arming
    distance mode before a plan loads fires immediately (0 <= any threshold).
    Time mode has no such dependency on the flight plan, so it isn't gated by
    has_plan."""
    global pause_armed, pause_fired
    with pause_lock:
        if not pause_armed or pause_fired:
            return
        if pause_mode == "time":
            if time.time() < pause_time_target:
                return
            logging.info(f"[Pause] Target time reached (mode=time) — firing.")
        else:
            if not has_plan:
                return
            if pause_mode == "distance":
                threshold = pause_threshold_nm
            elif pause_mode == "tod":
                threshold = tod_estimate_nm
            else:
                return
            if threshold <= 0 or dest_distance_nm > threshold:
                return
            logging.info(f"[Pause] Threshold reached (dest_distance={dest_distance_nm:.1f}nm <= {threshold:.1f}nm, mode={pause_mode}) — firing.")
        pause_fired = True
        pause_armed = False
    send_sim_command("pause")


# ─── SimBrief ─────────────────────────────────────────────────────────────────

def fetch_simbrief():
    global fpl_waypoints, fpl_origin, fpl_dest, fpl_index
    logging.info("[SimBrief] Fetching latest OFP...")
    try:
        r = requests.get(SIMBRIEF_API, timeout=10)
        r.raise_for_status()
        ofp = r.json()

        origin     = ofp.get("origin", {}).get("icao_code", "????")
        origin_rwy = ofp.get("origin", {}).get("plan_rwy", "")
        dest       = ofp.get("destination", {}).get("icao_code", "????")

        # Build waypoint list from fixes
        fixes = ofp.get("navlog", {}).get("fix", [])
        wpts = []
        for fix in fixes:
            try:
                ident = fix.get("ident", "?")
                lat   = float(fix.get("pos_lat", 0))
                lon   = float(fix.get("pos_long", 0))
                alt   = float(fix.get("altitude_feet", 0))
                wpts.append({"ident": ident, "lat": lat, "lon": lon, "alt_ft": alt})
            except Exception:
                continue

        with fpl_lock:
            fpl_waypoints = wpts
            fpl_origin    = origin
            fpl_dest      = dest
            fpl_index     = 0

        with data_lock:
            latest_data["fpl_loaded"] = len(wpts) > 0
            latest_data["origin"]     = origin
            latest_data["origin_rwy"] = origin_rwy
            latest_data["dest"]       = dest
            latest_data["wp_total"]   = len(wpts)

        # ASCII arrow, not "→": Windows' console codec (cp1252/charmap) can't
        # encode that character, which was throwing here and — since it's
        # after the data is already saved but before `return True` — made
        # every successful fetch get reported as a failure.
        logging.info(f"[SimBrief] Loaded {origin}->{dest}, {len(wpts)} waypoints.")
        return True

    except Exception as e:
        logging.error(f"[SimBrief] Failed to fetch OFP: {e}")
        return False


def simbrief_loop():
    """Refresh SimBrief OFP every 5 minutes in case pilot re-files."""
    while True:
        fetch_simbrief()
        time.sleep(300)


# ─── Waypoint sequencing ──────────────────────────────────────────────────────

def update_waypoint_tracking(lat, lon, gs_kts, gnd_track):
    """
    Given current position, ground speed, and ground track, compute nav data
    against the active SimBrief flight plan waypoint, and auto-sequence.
    Returns dict of wp fields to merge into latest_data.
    """
    global fpl_index
    with fpl_lock:
        wpts_ref = fpl_waypoints  # the actual list object, not a copy - see write-back below
        wpts = wpts_ref[:]
        idx  = fpl_index

    if not wpts or idx >= len(wpts):
        return {
            "wp_next": "-----", "wp_distance": 0, "wp_ete": 0,
            "wp_bearing": 0, "wp_index": idx, "wp_total": len(wpts),
            "dest_distance": 0, "dest_ete": 0, "track_error": 0,
        }

    wp = wpts[idx]
    dist_nm  = haversine_nm(lat, lon, wp["lat"], wp["lon"])

    # Auto-sequence: advance once the active waypoint is no longer ahead of
    # the aircraft's actual direction of travel (ground track vs. bearing-to-
    # waypoint more than 90 degrees apart) — the standard GPS/FMS "TO/FROM"
    # method. NOT "advance once the next waypoint is closer than the current
    # one" (the previous approach): that sequences at the leg's perpendicular
    # bisector, which only lines up with the waypoint itself when consecutive
    # legs are similar length. Confirmed wrong against a real flight
    # (KSFO TRUKN->HYPEE, a short arrival into TRUKN followed by a long next
    # leg): the display kept TRUKN active until roughly that leg's midpoint,
    # well after actually passing the fix.
    # Ground track itself is too noisy/undefined below ~30kt (taxi, parked,
    # just-rotated) to trust for this, so sequencing is skipped entirely at
    # low speed rather than risk a false-advance on a stale/garbage track —
    # matches the old code's proximity gate never running before departure.
    # A while-loop (not a single if) lets it catch up past several stale
    # waypoints at once, e.g. right after this fix first takes effect.
    if gs_kts > 30:
        while idx + 1 < len(wpts):
            brg_to_wp = bearing(lat, lon, wp["lat"], wp["lon"])
            if abs((gnd_track - brg_to_wp + 180) % 360 - 180) <= 90:
                break
            idx += 1
            wp = wpts[idx]
            dist_nm = haversine_nm(lat, lon, wp["lat"], wp["lon"])
    with fpl_lock:
        # Only write back if fpl_waypoints is still the exact list we read at
        # the top of this function — fetch_simbrief() assigns a brand-new
        # list object on every refresh, so identity here means no refresh
        # landed mid-function. If one did, idx was computed against a plan
        # that's already gone; writing it back would stomp the fresh
        # fpl_index = 0 fetch_simbrief() just set. Skipping is safe: the next
        # tick recomputes idx from scratch against the new plan.
        #
        # Must compare against wpts_ref (the original list object), not wpts
        # (a [:] copy of it) - a copy is never the same object as the source
        # it was copied from, so comparing against wpts here always came out
        # False and this write-back silently never ran. fpl_index was
        # permanently stuck at 0 (or wherever it was last set), and every
        # single call was re-deriving the active waypoint from scratch via
        # the bearing-based while-loop above starting at idx=0 every time -
        # confirmed live against a real 82-waypoint EDDF->KDFW route, where
        # it happened to still land on the right waypoint each tick (the
        # re-derivation is self-correcting for a normal forward route), but
        # at real O(n) cost every tick instead of O(1), and only "happened to
        # work" rather than being guaranteed to for any route geometry.
        if fpl_waypoints is wpts_ref:
            fpl_index = idx

    brg      = bearing(lat, lon, wp["lat"], wp["lon"])
    ete_secs = int((dist_nm / gs_kts) * 3600) if gs_kts > 10 else 0

    # Destination distance-to-go: current position to the active waypoint,
    # plus the remaining flight-plan legs from there to the destination
    # (not a direct great-circle shot to the destination).
    dest_dist = dist_nm
    for i in range(idx, len(wpts) - 1):
        dest_dist += haversine_nm(wpts[i]["lat"], wpts[i]["lon"], wpts[i + 1]["lat"], wpts[i + 1]["lon"])
    dest_ete = int((dest_dist / gs_kts) * 3600) if gs_kts > 10 else 0

    # Build waypoint list for route tab (include dist/ete for each)
    wpt_list = []
    for i, w in enumerate(wpts):
        d_nm = haversine_nm(lat, lon, w["lat"], w["lon"])
        ete_s = int((d_nm / gs_kts) * 3600) if gs_kts > 10 else 0
        wpt_list.append({
            "ident": w["ident"],
            "dist_nm": round(d_nm, 1),
            "ete_secs": ete_s,
        })

    return {
        "wp_next":      wp["ident"],
        "wp_distance":  round(dist_nm, 1),
        "wp_ete":       ete_secs,
        "wp_bearing":   round(brg, 1),
        "wp_index":     idx + 1,
        "wp_total":     len(wpts),
        "dest_distance": round(dest_dist, 1),
        "dest_ete":     dest_ete,
        "waypoints":    wpt_list,
    }


# ─── SimConnect loop ──────────────────────────────────────────────────────────

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "localhost"


def simconnect_worker(shared, lock):
    """
    Runs in its own OS process, deliberately kept minimal: only the actual
    SimConnect connection and raw simvar reads happen here. python-SimConnect
    pumps messages on a background thread inside this process; if that thread
    (or the underlying DLL call) hangs, a Python thread can't be force-killed
    out of it — but a whole OS process can be (TerminateProcess), which is
    what the supervisor in the main process does if this stops heartbeating.
    Anything that depends on cross-process state (flight-plan waypoints) is
    deliberately NOT done here — it's done back in the main process, using
    the raw lat/lon/gs this writes out.
    """
    setup_logging("simconnect_worker")

    def heartbeat():
        with lock:
            shared["_ts"] = time.monotonic()

    last_cmd_nonce = None

    while True:
        try:
            logging.info("[SimConnect] Connecting to MSFS...")
            sm = SimConnect()
            aq = AircraftRequests(sm, _time=LOOP_INTERVAL_MS)
            ae = AircraftEvents(sm)
            # PAUSE_ON/PAUSE_OFF as separate events are documented as unreliable
            # in current MSFS (confirmed via multiple MSFS DevSupport reports —
            # PAUSE_ON firing but PAUSE_OFF not reversing it matches a known,
            # reported asymmetry). PAUSE_SET takes an explicit 1/0 value on a
            # single event instead, which is the more robust of the two options.
            #
            # State detection via SimConnect's own pause EVENTS isn't
            # attempted here, deliberately — both sm.paused (the library's own
            # event-driven tracking) and a raw RequestSystemState query were
            # tried and both failed in practice (the former just doesn't
            # update; the latter crashed this worker process outright). Real
            # pause detection instead comes from watching ZULU_TIME freeze,
            # per-tick, below (see PAUSE_FREEZE_TICKS's comment) — that result
            # is what overrides sim_paused_tracked (module-level, see its own
            # comment) once connected.
            pause_set_evt = ae.find("PAUSE_SET")

            # Constructing SimConnect()/AircraftRequests() only proves the
            # client-side handle opened - not that MSFS is actually running
            # and answering. A stale/zombie SimConnect service handle can let
            # the constructor succeed with nothing real on the other end, and
            # every per-tick read below goes through safe_get(), which
            # swallows all exceptions and returns a default - so if that were
            # the only check, a dead connection would report "connected"
            # forever with all-zero telemetry, never tripping this loop's own
            # except/reconnect branch. A real value read is the only thing
            # that actually proves liveness, so require one before declaring
            # connected. AIRSPEED_INDICATED reading exactly 0 while parked is
            # legitimate real data, not a failure - only a None/exception
            # counts as "not actually connected". This exact check is repeated
            # per-tick below (not just here at initial connect) — a handle
            # that dies mid-session (e.g. MSFS itself was closed) needs the
            # same proof-of-life check to trigger a reconnect, otherwise it
            # silently serves frozen telemetry forever while claiming
            # "connected" (this was the root cause of needing a manual bridge
            # restart after closing/reopening MSFS for a new flight).
            probe = aq.get("AIRSPEED_INDICATED")
            if probe is None:
                raise ConnectionError("SimConnect opened but returned no data - MSFS likely not actually running")

            logging.info("[SimConnect] Connected.")

            # Aircraft identity — fetched once per connection, not per tick:
            # ATC_TYPE/ATC_MODEL/ATC_ID are static for the loaded aircraft,
            # no reason to re-request them at 20Hz. python-SimConnect returns
            # String-typed simvars as raw bytes (verified against the
            # installed library's own SimConnect.py, not assumed), hence the
            # decode. ATC_TYPE holds the manufacturer as set in the
            # aircraft.cfg (e.g. "Boeing", "Airbus") - used to pick which
            # FMA vocabulary reads correctly below, since "LNAV"/"VNAV SPD"
            # are Boeing-specific terms that don't exist on an Airbus and
            # vice versa. This only distinguishes which WORDS are correct
            # for the airframe, not real distinct Airbus flight-phase
            # detection (CLB vs DES vs ALT CRZ) - that needs aircraft-
            # specific data (e.g. Fenix's own internal state) this generic
            # SimConnect approach doesn't have access to.
            def safe_str(name):
                try:
                    val = aq.get(name)
                    if val is None:
                        return ""
                    return val.decode("utf-8", errors="ignore").strip() if isinstance(val, bytes) else str(val).strip()
                except Exception:
                    return ""

            def clean_model_string(raw):
                # aircraft.cfg's atc_model is sometimes a raw, unresolved
                # localization token rather than a plain string - confirmed
                # against a real flight, where this came back as literally
                # "ATCCOM.AC_MODEL A321.0.text" instead of "A321".
                # python-SimConnect has no localization resolution (it just
                # hands back whatever raw bytes MSFS returned), so pull the
                # designator out ourselves. Anything not matching this token
                # shape is assumed to already be a plain value.
                m = re.search(r'AC_MODEL[\s_]+([A-Za-z0-9\-]+)', raw, re.IGNORECASE)
                return m.group(1) if m else raw

            atc_type = safe_str("ATC_TYPE")
            aircraft_type = clean_model_string(safe_str("ATC_MODEL"))
            aircraft_reg = safe_str("ATC_ID")
            manufacturer = "boeing" if "boeing" in atc_type.lower() else ("airbus" if "airbus" in atc_type.lower() else "generic")
            logging.info(f"[SimConnect] Aircraft: {atc_type} {aircraft_type} reg={aircraft_reg} (FMA vocabulary: {manufacturer})")

            with lock:
                shared["connected"] = True
                shared["sim_running"] = True
                shared["aircraft_type"] = aircraft_type
                shared["aircraft_reg"] = aircraft_reg
            heartbeat()

            poll_counter = 0
            # Per-tick liveness (Task 2) and pause ground-truth (Task 1) state
            # — reset on every fresh connection, see their checks below.
            ias_fail_streak = 0
            last_zulu = None
            frozen_ticks = 0
            while True:
                # Pending command from the main process (e.g. a remote pause
                # request) — the SimConnect handle only lives in this process,
                # so any command has to be picked up here rather than acted on
                # where it was requested. Nonce comparison makes this fire
                # exactly once per command even though it's polled every tick.
                with lock:
                    cmd = shared.get("_cmd")
                if cmd and cmd.get("nonce") != last_cmd_nonce:
                    last_cmd_nonce = cmd["nonce"]
                    if pause_set_evt is None:
                        logging.error("[Pause] PAUSE_SET event not found — cannot send pause/resume.")
                    elif cmd.get("action") == "pause":
                        logging.info("[Pause] Sending PAUSE_SET(1).")
                        pause_set_evt(1)
                    elif cmd.get("action") == "resume":
                        logging.info("[Pause] Sending PAUSE_SET(0).")
                        pause_set_evt(0)

                # Idle throttle (see IDLE_POLL_EVERY's comment up top): skip the
                # ~20-variable SimConnect fetch below on most ticks while no
                # client is watching, but still heartbeat every tick so the
                # supervisor's watchdog doesn't mistake low-rate idling for a
                # hung worker and force-restart it.
                poll_counter += 1
                with lock:
                    idle = shared.get("_client_idle", False)
                if poll_counter % (IDLE_POLL_EVERY if idle else 1) != 0:
                    heartbeat()
                    time.sleep(LOOP_INTERVAL_S)
                    continue

                def safe_get(name, default=0):
                    try:
                        val = aq.get(name)
                        return float(val) if val is not None else default
                    except Exception:
                        return default

                def raw_get(name):
                    # Like safe_get, but distinguishes "read failed" (None)
                    # from "read succeeded and the value is legitimately 0" —
                    # needed by both the liveness check and the pause-freeze
                    # check below, neither of which can afford to conflate
                    # the two the way safe_get's blanket 0-default does.
                    try:
                        return aq.get(name)
                    except Exception:
                        return None

                # Liveness (Task 2): the same proof-of-life check used at
                # initial connect (see its comment above), repeated every
                # tick. A stale/zombie handle (e.g. MSFS itself was closed
                # and a new instance opened) can otherwise sit here forever
                # returning None on every read while safe_get() silently
                # swallows that into 0.0 and the tick keeps claiming
                # "connected" — this is what used to require a manual bridge
                # restart after starting a new flight. Require a short streak
                # (LIVENESS_FAIL_STREAK), not one failed tick, so a single
                # transient SimConnect hiccup can't tear down a fine
                # connection. This is read-only — it never writes to the sim,
                # so it cannot itself cause a crash or a pause.
                _ias_raw = raw_get("AIRSPEED_INDICATED")
                ias_fail_streak = ias_fail_streak + 1 if _ias_raw is None else 0
                if ias_fail_streak >= LIVENESS_FAIL_STREAK:
                    raise ConnectionError(
                        f"SimConnect handle stale (AIRSPEED_INDICATED read failed {ias_fail_streak}x) — reconnecting"
                    )
                ias = float(_ias_raw) if _ias_raw is not None else 0.0

                # Pause ground truth (Task 1): ZULU_TIME is a real in-sim
                # clock (seconds) that stops advancing the instant MSFS
                # enters ANY paused state (full Esc-menu pause or
                # active/photo pause) — see PAUSE_FREEZE_TICKS's comment for
                # why this is used instead of MSFS's own pause events. Purely
                # a read + a shared-dict write for display; never sends
                # anything to the sim. Runs after the liveness check above so
                # a genuinely dead connection reconnects instead of getting
                # misread as "paused forever".
                zulu = raw_get("ZULU_TIME")
                if zulu is not None:
                    zulu = float(zulu)
                    was_frozen = frozen_ticks >= PAUSE_FREEZE_TICKS
                    frozen_ticks = frozen_ticks + 1 if (last_zulu is not None and zulu == last_zulu) else 0
                    # Diagnostic only (2026-08-11): the freeze check was found
                    # to never confirm a real, Dev-Mode-verified pause in live
                    # testing — root cause (float jitter in the reading vs.
                    # ZULU_TIME genuinely not freezing for that pause path)
                    # wasn't pinned down. Log every raw sample plus the
                    # transition so the next occurrence has real evidence
                    # instead of another guess. Safe to remove once root-caused.
                    if last_zulu is not None and zulu != last_zulu:
                        logging.info(f"[Pause][ZULU] {last_zulu} -> {zulu} (delta={zulu - last_zulu:.6f}, frozen_ticks was {frozen_ticks - 1} -> reset to 0)")
                    last_zulu = zulu
                    now_frozen = frozen_ticks >= PAUSE_FREEZE_TICKS
                    if now_frozen != was_frozen:
                        logging.info(f"[Pause][ZULU] ground truth -> {'FROZEN (paused)' if now_frozen else 'moving (not paused)'}")
                    with lock:
                        shared["msfs_paused_ground_truth"] = now_frozen
                # if zulu is None: leave the shared key untouched this tick rather than guessing

                tas      = safe_get("AIRSPEED_TRUE")
                gs       = safe_get("GROUND_VELOCITY")
                mach     = safe_get("AIRSPEED_MACH")
                # python-SimConnect requests each simvar in a specific unit (see
                # RequestList.py) and MSFS converts server-side to match, so only
                # variables actually requested in Radians need a degrees conversion here.
                pitch    = -safe_get("PLANE_PITCH_DEGREES") * (180 / 3.14159265)
                bank     = -safe_get("PLANE_BANK_DEGREES") * (180 / 3.14159265)
                heading  = safe_get("PLANE_HEADING_DEGREES_MAGNETIC") * (180 / 3.14159265)
                altitude = safe_get("INDICATED_ALTITUDE")
                # VERTICAL_SPEED is requested in feet/minute — always, regardless of aircraft
                vs_raw   = safe_get("VERTICAL_SPEED")
                vs       = max(-6000, min(6000, vs_raw))
                ap_speed = safe_get("AUTOPILOT_AIRSPEED_HOLD_VAR")
                ap_alt   = safe_get("AUTOPILOT_ALTITUDE_LOCK_VAR")
                ap_hdg   = safe_get("AUTOPILOT_HEADING_LOCK_DIR")  # already Degrees
                ap_active= bool(safe_get("AUTOPILOT_MASTER"))
                fd_active= bool(safe_get("AUTOPILOT_FLIGHT_DIRECTOR_ACTIVE"))
                at_active= bool(safe_get("AUTOTHROTTLE_ACTIVE"))
                lnav     = bool(safe_get("AUTOPILOT_NAV1_LOCK"))
                baro     = safe_get("KOHLSMAN_SETTING_MB")  # hPa == millibars
                lat      = safe_get("PLANE_LATITUDE")   # already Degrees
                lon      = safe_get("PLANE_LONGITUDE")  # already Degrees
                # GPS_GROUND_MAGNETIC_TRACK was reported frozen at a fixed
                # value on a real flight (Fenix A321) - track deviation
                # stuck at exactly 12.2 deg L for an extended period despite
                # actually being on-course. No code-level bug found (the
                # value flows through correctly, it's just never changing at
                # the source) - GPS_GROUND_MAGNETIC_TRACK is a legacy generic-
                # GPS-instrument simvar, and a deeply custom FMGS-modeled
                # addon like Fenix plausibly never drives it since it doesn't
                # use the stock GPS unit at all. Falling back to heading
                # (already read above, confirmed working) as the "current
                # track" reference instead - the real tradeoff is losing
                # wind-drift/crab-angle accuracy (heading != true ground
                # track in a crosswind), but a frozen, wrong-regardless-of-
                # reality number is worse than that approximation.
                gnd_track = heading

                # Same underlying booleans regardless of airframe - only the
                # WORDS change, matched to whichever manufacturer's FMA
                # vocabulary is actually correct for the loaded aircraft
                # (see manufacturer detection above).
                if manufacturer == "airbus":
                    roll_mode  = "NAV" if lnav else ("HDG" if ap_active else "")
                    pitch_mode = "ALT CRZ" if lnav else ("ALT" if ap_active else "")
                    speed_mode = "SPEED" if at_active else ("MANAGED" if lnav else "")
                    ap_mode    = "AP" if ap_active else ("FD" if fd_active else "")
                else:  # "boeing" or "generic" - Boeing vocabulary was the original default
                    roll_mode  = "LNAV" if lnav else ("HDG SEL" if ap_active else "")
                    pitch_mode = "VNAV SPD" if lnav else ("ALT HOLD" if ap_active else "")
                    speed_mode = "MCP SPD" if at_active else ("FMC SPD" if lnav else "")
                    ap_mode    = "CMD" if ap_active else ("FD" if fd_active else "")

                with lock:
                    shared.update({
                        "ias": round(ias, 1), "tas": round(tas, 1),
                        "gs": round(gs, 1), "mach": round(mach, 3),
                        "pitch": round(pitch, 2), "bank": round(bank, 2),
                        "heading": round(normalize(heading), 1),
                        "altitude": round(altitude, 1),
                        "vs": round(vs, 0),
                        "ap_speed": round(ap_speed, 0),
                        "ap_altitude": round(ap_alt, 0),
                        "ap_heading": round(normalize(ap_hdg), 0),
                        "ap_active": ap_active, "fd_active": fd_active,
                        "at_active": at_active, "lnav_active": lnav,
                        "ap_mode": ap_mode, "roll_mode": roll_mode,
                        "pitch_mode": pitch_mode, "speed_mode": speed_mode,
                        "baro": round(baro, 0),
                        "lat": lat, "lon": lon, "gnd_track": round(normalize(gnd_track), 1),
                        "connected": True, "sim_running": True,
                        "_ts": time.monotonic(),
                    })

                time.sleep(LOOP_INTERVAL_S)

        except Exception as e:
            logging.warning(f"[SimConnect] Worker error: {e}. Retrying in 5s...")
            with lock:
                shared["connected"] = False
                shared["sim_running"] = False
                # Reset so a stale "paused" reading from the connection that
                # just died can't linger and briefly misdisplay on reconnect.
                shared["msfs_paused_ground_truth"] = False
            # Sleep in small chunks, refreshing the heartbeat each time, so
            # this normal "waiting for MSFS to appear" backoff doesn't get
            # mistaken by the supervisor for a genuine hang.
            for _ in range(50):
                time.sleep(0.1)
                heartbeat()


def simconnect_supervisor():
    try:
        _simconnect_supervisor_impl()
    except Exception:
        logging.error("[Supervisor] CRASHED:")
        traceback.print_exc()


def _simconnect_supervisor_impl():
    global sim_paused_tracked
    if not SIMCONNECT_AVAILABLE:
        t = 0
        while True:
            t += 0.2
            lat, lon = 32.9 + t * 0.001, -97.0 + t * 0.001
            gs = 270
            wp_data = update_waypoint_tracking(lat, lon, gs, normalize(35 + t * 0.2))
            tod_estimate = current_tod_estimate_nm()
            check_auto_pause(wp_data.get("dest_distance", 0), tod_estimate, wp_data.get("wp_total", 0) > 0)
            with pause_lock:
                pause_snapshot = {
                    "pause_armed": pause_armed, "pause_mode": pause_mode,
                    "pause_threshold_nm": pause_threshold_nm,
                    "pause_time_target": pause_time_target,
                }
            with sim_paused_lock:
                sim_paused_now = sim_paused_tracked
            with data_lock:
                latest_data.update({
                    "ias": 250 + 10 * math.sin(t * 0.1),
                    "tas": 265, "gs": gs, "mach": 0.42,
                    "pitch": 2 + 3 * math.sin(t * 0.05),
                    "bank": 5 * math.sin(t * 0.03),
                    "heading": normalize(35 + t * 0.2),
                    "altitude": 10000 + 500 * math.sin(t * 0.02),
                    "vs": 200 * math.sin(t * 0.04),
                    "ap_speed": 250, "ap_altitude": 10000, "ap_heading": 40,
                    "ap_active": True, "fd_active": True, "at_active": True,
                    "lnav_active": True,
                    "ap_mode": "CMD", "roll_mode": "LNAV",
                    "pitch_mode": "VNAV SPD", "speed_mode": "MCP SPD",
                    "track_error": track_error(wp_data.get("wp_bearing", 0), normalize(35 + t * 0.2)),
                    "baro": 1013, "connected": True, "sim_running": True,
                    **wp_data,
                    **pause_snapshot,
                    "pause_estimated_tod_nm": tod_estimate,
                    "sim_paused": sim_paused_now,
                })
            time.sleep(0.2)
        return

    # Runs the actual SimConnect work in a separate process and monitors its
    # heartbeat, force-restarting it if it ever stops updating — a hang deep
    # inside SimConnect's own background thread can't be recovered any other
    # way (see simconnect_worker's docstring).
    HEARTBEAT_TIMEOUT = 2.5        # seconds of silence before assuming the worker is hung
    INITIAL_CONNECT_TIMEOUT = 10   # generous grace period for the very first connect

    manager = multiprocessing.Manager()
    shared = manager.dict()
    lock = manager.Lock()

    global worker_shared, worker_lock
    worker_shared = shared
    worker_lock = lock

    def spawn_worker():
        p = multiprocessing.Process(target=simconnect_worker, args=(shared, lock), daemon=True)
        p.start()
        return p, time.monotonic()

    proc, proc_start = spawn_worker()
    wp_data = {}
    tod_estimate = 0
    loop_iter = 0

    while True:
        # Once X-Plane already holds the claim, stop searching for MSFS
        # entirely instead of retrying SimConnect in the background forever -
        # kills the worker so there's no more connect attempts, no more log
        # spam, no more worker-process churn while X-Plane is the one actually
        # flying. Resumes automatically once the active sim disconnects and
        # releases the claim (see _release_backend/_write_disconnected_state).
        with active_backend_lock:
            other_active = active_backend["name"] not in (None, "msfs")

        if other_active:
            if proc is not None:
                proc.terminate()
                proc.join(timeout=2)
                if proc.is_alive():
                    proc.kill()
                    proc.join(timeout=2)
                with lock:
                    shared.clear()
                proc = None
            time.sleep(1)
            continue
        elif proc is None:
            proc, proc_start = spawn_worker()
            wp_data = {}
            tod_estimate = 0
            loop_iter = 0
            time.sleep(1)
            continue

        with lock:
            shared["_client_idle"] = client_is_idle()
            snap = dict(shared)

        ts = snap.get("_ts")
        now = time.monotonic()
        stuck = (now - proc_start) > INITIAL_CONNECT_TIMEOUT if ts is None else (now - ts) > HEARTBEAT_TIMEOUT

        if stuck:
            logging.warning(f"[Supervisor] SimConnect worker unresponsive — force-restarting it (pid={proc.pid}).")
            proc.terminate()
            proc.join(timeout=2)
            if proc.is_alive():
                proc.kill()
                proc.join(timeout=2)
            with lock:
                shared.clear()
            with sim_paused_lock:
                sim_paused_now = sim_paused_tracked
            _write_disconnected_state("msfs", sim_paused_now)
            proc, proc_start = spawn_worker()
            wp_data = {}
            tod_estimate = 0
            loop_iter = 0
            time.sleep(1)
            continue

        # sim_paused_tracked is "what we last commanded" (see send_sim_command)
        # and is meaningful regardless of whether the sim is actually
        # connected right now — synced into latest_data unconditionally so a
        # pause/resume tap while disconnected shows up on the very next poll
        # instead of sitting stale until the sim happens to reconnect.
        with sim_paused_lock:
            sim_paused_now = sim_paused_tracked

        if snap.get("connected") and _claim_backend("msfs"):
            # msfs_paused_ground_truth (ZULU_TIME-freeze detection, see
            # PAUSE_FREEZE_TICKS's comment) ONE-WAY resync: only ever trusted
            # to turn the paused state ON, never to turn it back OFF.
            #
            # Live testing (2026-08-11, real flight) found the freeze check
            # never confirmed a real, Dev-Mode-verified pause — root cause
            # (float jitter in ZULU_TIME vs. it genuinely not freezing for
            # that pause path) is still unconfirmed, see the diagnostic
            # logging above. Originally this resynced in BOTH directions
            # every tick (mirroring X-Plane's xp_paused override below, which
            # is fine there because that dataref is real, verified-working
            # ground truth) - for MSFS that meant an unconfirmed check
            # defaulting to "running" permanently overwrote a real, just-
            # confirmed pause back to "running" within ~50ms, so the button
            # could show "paused" for less than a tick and then never offer
            # resume again (had to be cleared from MSFS's own Dev Mode pause
            # menu instead). Trusting the ON direction only avoids that: a
            # false-positive ON just makes tapping "resume" a harmless no-op
            # on an already-running sim, which is a fine tradeoff against the
            # button being permanently stuck. PAUSE_GRACE_S still guards a
            # just-issued command from being immediately re-confirmed away
            # (belt-and-suspenders with the one-way change above).
            with sim_paused_lock:
                in_grace = (time.monotonic() - last_manual_cmd_ts) < PAUSE_GRACE_S
            if snap.get("msfs_paused_ground_truth") is True and not in_grace:
                sim_paused_now = True
                with sim_paused_lock:
                    sim_paused_tracked = sim_paused_now

            lat = snap.get("lat", 0)
            lon = snap.get("lon", 0)
            gs  = snap.get("gs", 0)
            gnd_track = snap.get("gnd_track", 0)

            loop_iter += 1
            if not wp_data or loop_iter % WP_UPDATE_EVERY == 0:
                wp_data = update_waypoint_tracking(lat, lon, gs, gnd_track)
                tod_estimate = current_tod_estimate_nm()
            te = track_error(wp_data.get("wp_bearing", 0), gnd_track)

            check_auto_pause(wp_data.get("dest_distance", 0), tod_estimate, wp_data.get("wp_total", 0) > 0)
            with pause_lock:
                pause_snapshot = {
                    "pause_armed": pause_armed, "pause_mode": pause_mode,
                    "pause_threshold_nm": pause_threshold_nm,
                    "pause_time_target": pause_time_target,
                }

            with data_lock:
                latest_data.update({k: v for k, v in snap.items() if k != "_ts"})
                latest_data.update({"track_error": te, **wp_data})
                latest_data.update(pause_snapshot)
                latest_data["pause_estimated_tod_nm"] = tod_estimate
                latest_data["sim_paused"] = sim_paused_now
        elif not snap.get("connected"):
            _write_disconnected_state("msfs", sim_paused_now)
        # else: snap says connected but X-Plane already holds the claim -
        # skip this tick without touching latest_data (see _claim_backend).

        time.sleep(LOOP_INTERVAL_S)


# ─── X-Plane 12 ─────────────────────────────────────────────────────────────
# Uses X-Plane's own UDP network protocol directly (stdlib socket/struct only
# — no extra package, unlike SimConnect). Wire format and dataref paths below
# were verified two ways, not guessed: the BECN/RREF/CMND packet structure
# against X-Plane's own published protocol docs, and every dataref path
# against this machine's actual installed X-Plane 12 Resources/plugins/
# DataRefs.txt. Values RREF returns are always float32 regardless of the
# dataref's real type, so lat/lon (natively double) lose a little precision
# over the wire — a few meters at most, fine for nm-scale waypoint distances,
# not fine for anything needing landing-grade position accuracy.
XP_BEACON_GROUP = "239.255.1.1"
XP_BEACON_PORT = 49707
XP_RREF_HZ = 20  # matches LOOP_INTERVAL_MS's 20Hz sample rate
XP_IDLE_RREF_HZ = 2  # dropped to this while no client is watching (see CLIENT_IDLE_TIMEOUT_S) — X-Plane pushes RREF unprompted, so a lower Hz here directly means fewer UDP packets sent, no client-side polling change needed

# (dataref path, latest_data-ish field name) — index in this list doubles as
# the RREF subscription index, so response packets map straight back to a
# field by position without needing a separate index<->name table.
XP_DATAREFS = [
    ("sim/flightmodel/position/indicated_airspeed", "ias"),                        # kias
    ("sim/cockpit2/gauges/indicators/true_airspeed_kts_pilot", "tas"),              # kt
    ("sim/flightmodel/position/groundspeed", "gs"),                                 # m/s
    ("sim/cockpit2/gauges/indicators/mach_pilot", "mach"),
    ("sim/flightmodel/position/true_theta", "pitch"),                              # deg, nose-up positive
    ("sim/flightmodel/position/true_phi", "bank"),                                 # deg, right-bank positive
    ("sim/flightmodel/position/mag_psi", "heading"),                               # deg magnetic
    ("sim/cockpit2/gauges/indicators/altitude_ft_pilot", "altitude"),              # ft indicated
    ("sim/flightmodel/position/vh_ind_fpm", "vs"),                                 # fpm
    ("sim/cockpit2/autopilot/airspeed_dial_kts_mach", "ap_speed"),
    ("sim/cockpit2/autopilot/altitude_dial_ft", "ap_altitude"),
    ("sim/cockpit2/autopilot/heading_dial_deg_mag_pilot", "ap_heading"),
    ("sim/cockpit2/autopilot/servos_on", "ap_servos_on"),                          # 0/1
    ("sim/cockpit2/autopilot/autothrottle_on", "at_on"),                           # 0/1
    ("sim/cockpit2/autopilot/nav_status", "nav_status"),                           # 0 off / 1 armed / 2 captured
    ("sim/cockpit2/autopilot/heading_status", "hdg_status"),                       # 0 off / 2 captured
    ("sim/cockpit2/autopilot/altitude_hold_status", "alt_status"),                 # 0 off / 1 armed / 2 captured
    ("sim/cockpit/misc/barometer_setting", "baro_inhg"),                           # inHg
    ("sim/flightmodel/position/latitude", "lat"),                                  # deg (float32-truncated)
    ("sim/flightmodel/position/longitude", "lon"),                                 # deg (float32-truncated)
    ("sim/flightmodel/position/hpath", "gnd_track"),                               # deg true ground track
    ("sim/time/paused", "xp_paused"),                                              # 0/1 ground truth pause state
]

HEARTBEAT_TIMEOUT_XP = 3.0  # X-Plane's RREF stream is push-based; a gap this long means it's gone


def xplane_find_beacon(timeout=5):
    """Listen for X-Plane's BECN multicast beacon. Returns (ip, port) of the
    live instance, or None if nothing answered within timeout — the beacon
    reports X-Plane's own configured UDP port rather than assuming the
    common default, since that's user-changeable in X-Plane's network
    settings."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", XP_BEACON_PORT))
    except OSError:
        sock.close()
        return None
    mreq = struct.pack("=4sl", socket.inet_aton(XP_BEACON_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(1024)
        if not data.startswith(b"BECN\x00"):
            return None
        # Header (5) + <BBiiIH (16 bytes): major/minor ver, host id, xplane
        # version, role, port. Only port and the sender's own IP matter here.
        _major, _minor, _host_id, _xp_ver, _role, port = struct.unpack("<BBiiIH", data[5:21])
        return (addr[0], port)
    except (socket.timeout, struct.error):
        return None
    finally:
        sock.close()


def xplane_worker(shared, lock):
    """Runs in its own process, mirroring simconnect_worker's shape: discover
    X-Plane, subscribe to the datarefs above via RREF, and loop forever
    parsing responses into `shared`. A pending pause/resume command (written
    by the main process into shared["_cmd"]) is sent as a CMND packet the
    same way simconnect_worker picks up commands from its own shared dict."""
    setup_logging("xplane_worker")

    def heartbeat():
        with lock:
            shared["_ts"] = time.monotonic()

    idx_to_field = {i: field for i, (_path, field) in enumerate(XP_DATAREFS)}
    last_cmd_nonce = None

    while True:
        logging.info("[X-Plane] Waiting for beacon...")
        beacon = xplane_find_beacon(timeout=10)
        heartbeat()
        if beacon is None:
            continue
        ip, port = beacon
        logging.info(f"[X-Plane] Found instance at {ip}:{port}.")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(HEARTBEAT_TIMEOUT_XP)
        try:
            def subscribe(hz):
                for i, (path, _field) in enumerate(XP_DATAREFS):
                    msg = struct.pack("<5sii400s", b"RREF\x00", hz, i, path.encode("utf-8"))
                    sock.sendto(msg, (ip, port))

            current_hz = XP_RREF_HZ
            subscribe(current_hz)
            last_rate_check = time.monotonic()

            values = {}
            while True:
                try:
                    data, _addr = sock.recvfrom(2048)
                except socket.timeout:
                    logging.warning("[X-Plane] No data for a while — assuming it closed/crashed, retrying discovery.")
                    break
                if not data.startswith(b"RREF,"):
                    continue
                body = data[5:]
                for off in range(0, len(body) - 7, 8):
                    idx, val = struct.unpack("<if", body[off:off + 8])
                    field = idx_to_field.get(idx)
                    if field:
                        values[field] = val
                heartbeat()

                # Idle throttle (see XP_IDLE_RREF_HZ's comment): re-subscribe at
                # a much lower Hz while no client is watching, so X-Plane itself
                # sends far fewer UDP packets rather than us discarding most of
                # a still-full-rate stream. Checked periodically, not per-packet,
                # since a Manager-dict read has its own IPC cost.
                now_m = time.monotonic()
                if now_m - last_rate_check > 2.0:
                    last_rate_check = now_m
                    with lock:
                        idle = shared.get("_client_idle", False)
                    target_hz = XP_IDLE_RREF_HZ if idle else XP_RREF_HZ
                    if target_hz != current_hz:
                        current_hz = target_hz
                        subscribe(current_hz)

                cmd = None
                with lock:
                    cmd = shared.get("_cmd")
                if cmd and cmd.get("nonce") != last_cmd_nonce:
                    last_cmd_nonce = cmd["nonce"]
                    wants_paused = (cmd.get("action") == "pause")
                    currently_paused = bool(values.get("xp_paused", 0))
                    # X-Plane only exposes a *toggle* command (pause_toggle), not an
                    # absolute set, so we only fire it when sim/time/paused (ground
                    # truth, just parsed above) actually disagrees with what was
                    # requested. Blindly toggling on every tap is what let a stale
                    # app-side belief about pause state flip the real sim the wrong
                    # way instead of just no-opping.
                    if wants_paused != currently_paused:
                        action = "sim/operation/pause_toggle"
                        logging.info(f"[X-Plane][Pause] Sending CMND {action} for '{cmd.get('action')}' (was {'paused' if currently_paused else 'unpaused'}).")
                        sock.sendto(b"CMND\x00" + action.encode("utf-8"), (ip, port))
                    else:
                        logging.info(f"[X-Plane][Pause] '{cmd.get('action')}' requested but X-Plane is already {'paused' if currently_paused else 'unpaused'} — skipping toggle.")

                if not values:
                    continue

                roll_mode  = "NAV" if values.get("nav_status", 0) == 2 else ("HDG" if values.get("hdg_status", 0) == 2 else "")
                pitch_mode = "ALT" if values.get("alt_status", 0) == 2 else ""
                speed_mode = "A/THR" if values.get("at_on", 0) else ""
                ap_active  = bool(values.get("ap_servos_on", 0))
                at_active  = bool(values.get("at_on", 0))
                lnav_active = values.get("nav_status", 0) >= 1

                with lock:
                    shared.update({
                        "ias": round(values.get("ias", 0), 1),
                        "tas": round(values.get("tas", 0), 1),
                        "gs": round(values.get("gs", 0) * 1.94384, 1),  # m/s -> kt
                        "mach": round(values.get("mach", 0), 3),
                        "pitch": round(values.get("pitch", 0), 2),
                        "bank": round(values.get("bank", 0), 2),
                        "heading": round(normalize(values.get("heading", 0)), 1),
                        "altitude": round(values.get("altitude", 0), 1),
                        "vs": round(values.get("vs", 0), 0),
                        "ap_speed": round(values.get("ap_speed", 0), 0),
                        "ap_altitude": round(values.get("ap_altitude", 0), 0),
                        "ap_heading": round(normalize(values.get("ap_heading", 0)), 0),
                        "ap_active": ap_active, "fd_active": ap_active,
                        "at_active": at_active, "lnav_active": lnav_active,
                        "ap_mode": "CMD" if ap_active else "", "roll_mode": roll_mode,
                        "pitch_mode": pitch_mode, "speed_mode": speed_mode,
                        "baro": round(values.get("baro_inhg", 29.92) * 33.8639, 0),  # inHg -> hPa
                        "lat": values.get("lat", 0), "lon": values.get("lon", 0),
                        "gnd_track": round(normalize(values.get("gnd_track", 0)), 1),
                        "xp_paused": bool(values.get("xp_paused", 0)),
                        "connected": True, "sim_running": True,
                        "_ts": time.monotonic(),
                    })
        finally:
            sock.close()


def xplane_supervisor():
    try:
        _xplane_supervisor_impl()
    except Exception:
        logging.error("[X-Plane Supervisor] CRASHED:")
        traceback.print_exc()


def _xplane_supervisor_impl():
    global sim_paused_tracked
    INITIAL_CONNECT_TIMEOUT = 15  # beacon discovery + subscribe round trip is slower than SimConnect's

    manager = multiprocessing.Manager()
    shared = manager.dict()
    lock = manager.Lock()

    global xp_worker_shared, xp_worker_lock
    xp_worker_shared = shared
    xp_worker_lock = lock

    def spawn_worker():
        p = multiprocessing.Process(target=xplane_worker, args=(shared, lock), daemon=True)
        p.start()
        return p, time.monotonic()

    proc, proc_start = spawn_worker()
    wp_data = {}
    tod_estimate = 0
    loop_iter = 0

    while True:
        # Once MSFS already holds the claim, stop searching for X-Plane
        # entirely instead of polling for its UDP beacon in the background
        # forever - kills the worker so there's no more connect attempts, no
        # more log spam, no more worker-process churn while MSFS is the one
        # actually flying. Resumes automatically once the active sim
        # disconnects and releases the claim (see
        # _release_backend/_write_disconnected_state).
        with active_backend_lock:
            other_active = active_backend["name"] not in (None, "xplane")

        if other_active:
            if proc is not None:
                proc.terminate()
                proc.join(timeout=2)
                if proc.is_alive():
                    proc.kill()
                    proc.join(timeout=2)
                with lock:
                    shared.clear()
                proc = None
            time.sleep(1)
            continue
        elif proc is None:
            proc, proc_start = spawn_worker()
            wp_data = {}
            tod_estimate = 0
            loop_iter = 0
            time.sleep(1)
            continue

        with lock:
            shared["_client_idle"] = client_is_idle()
            snap = dict(shared)

        ts = snap.get("_ts")
        now = time.monotonic()
        stuck = (now - proc_start) > INITIAL_CONNECT_TIMEOUT if ts is None else (now - ts) > HEARTBEAT_TIMEOUT_XP

        if stuck:
            logging.warning(f"[X-Plane Supervisor] worker unresponsive — force-restarting it (pid={proc.pid}).")
            proc.terminate()
            proc.join(timeout=2)
            if proc.is_alive():
                proc.kill()
                proc.join(timeout=2)
            with lock:
                shared.clear()
            with sim_paused_lock:
                sim_paused_now = sim_paused_tracked
            _write_disconnected_state("xplane", sim_paused_now)
            proc, proc_start = spawn_worker()
            wp_data = {}
            tod_estimate = 0
            loop_iter = 0
            time.sleep(1)
            continue

        with sim_paused_lock:
            sim_paused_now = sim_paused_tracked

        if snap.get("connected") and _claim_backend("xplane"):
            # sim/time/paused is real ground truth (unlike sim_paused_tracked's
            # self-reported memory) - resync on every tick so a stale tracked
            # value (bridge restart, pause toggled from inside X-Plane itself,
            # a stray duplicate bridge) self-heals without needing a button
            # press, instead of silently showing the wrong state indefinitely.
            if "xp_paused" in snap:
                sim_paused_now = bool(snap["xp_paused"])
                with sim_paused_lock:
                    sim_paused_tracked = sim_paused_now

            lat = snap.get("lat", 0)
            lon = snap.get("lon", 0)
            gs  = snap.get("gs", 0)
            gnd_track = snap.get("gnd_track", 0)

            loop_iter += 1
            if not wp_data or loop_iter % WP_UPDATE_EVERY == 0:
                wp_data = update_waypoint_tracking(lat, lon, gs, gnd_track)
                tod_estimate = current_tod_estimate_nm()
            te = track_error(wp_data.get("wp_bearing", 0), gnd_track)

            check_auto_pause(wp_data.get("dest_distance", 0), tod_estimate, wp_data.get("wp_total", 0) > 0)
            with pause_lock:
                pause_snapshot = {
                    "pause_armed": pause_armed, "pause_mode": pause_mode,
                    "pause_threshold_nm": pause_threshold_nm,
                    "pause_time_target": pause_time_target,
                }

            with data_lock:
                latest_data.update({k: v for k, v in snap.items() if k != "_ts"})
                latest_data.update({"track_error": te, **wp_data})
                latest_data.update(pause_snapshot)
                latest_data["pause_estimated_tod_nm"] = tod_estimate
                latest_data["sim_paused"] = sim_paused_now
        elif not snap.get("connected"):
            _write_disconnected_state("xplane", sim_paused_now)
        # else: MSFS already holds the claim - skip this tick untouched.

        time.sleep(LOOP_INTERVAL_S)


@app.route("/")
def index():
    response = send_from_directory(BASE_DIR, "pfd.html")
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/apple-touch-icon.png")
def apple_touch_icon():
    return send_from_directory(BASE_DIR, "apple-touch-icon.png")


@app.route("/plane-icon.png")
def plane_icon():
    return send_from_directory(BASE_DIR, "plane-icon.png")


@app.route("/logo.png")
def logo():
    return send_from_directory(BASE_DIR, "logo.png")


@app.route("/login", methods=["POST"])
def login_endpoint():
    body = request.get_json(silent=True) or {}
    supplied = str(body.get("password", ""))
    if not secrets.compare_digest(supplied, AUTH_TOKEN):
        time.sleep(0.3)  # cheap brute-force throttle
        return _json_response({"status": "error", "message": "wrong password"}, 403)

    sid = secrets.token_urlsafe(32)
    with sessions_lock:
        sessions[sid] = time.time() + SESSION_TTL_SECONDS
        _save_sessions()

    response = _json_response({"status": "ok"})
    return _set_session_cookie(response, sid)


@app.route("/logout", methods=["POST"])
def logout_endpoint():
    sid = request.cookies.get("session", "")
    with sessions_lock:
        sessions.pop(sid, None)
        _save_sessions()
    response = _json_response({"status": "ok"})
    return _set_session_cookie(response)


@app.route("/logout_all", methods=["POST"])
def logout_all_endpoint():
    # Break-glass: gated by the password directly (not EXEMPT_PATHS'd cookie
    # check) so it works even with zero valid sessions in hand — e.g. the
    # "I lost my phone, revoke everything from a fresh browser" case.
    body = request.get_json(silent=True) or {}
    supplied = str(body.get("password", ""))
    if not secrets.compare_digest(supplied, AUTH_TOKEN):
        time.sleep(0.3)
        return _json_response({"status": "error", "message": "wrong password"}, 403)

    with sessions_lock:
        sessions.clear()
        _save_sessions()
    response = _json_response({"status": "ok"})
    return _set_session_cookie(response)


@app.route("/refresh_simbrief", methods=["POST"])
def refresh_simbrief_endpoint():
    ok = fetch_simbrief()
    with fpl_lock:
        payload = json.dumps({
            "status": "ok" if ok else "error",
            "origin": fpl_origin, "dest": fpl_dest, "wp_total": len(fpl_waypoints),
        })
    response = app.response_class(
        response=payload,
        status=200 if ok else 502,
        mimetype="application/json"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _json_response(payload_dict, status=200):
    response = app.response_class(
        response=json.dumps(payload_dict),
        status=status,
        mimetype="application/json"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/pause/arm", methods=["POST"])
def pause_arm_endpoint():
    global pause_armed, pause_mode, pause_threshold_nm, pause_time_target, pause_fired

    mode = request.args.get("mode", "")
    if mode not in ("distance", "tod", "time"):
        return _json_response({"status": "error", "message": "mode must be 'distance', 'tod', or 'time'"}, 400)

    threshold = 0.0
    time_target = 0.0
    if mode == "distance":
        try:
            threshold = float(request.args.get("threshold_nm", ""))
        except ValueError:
            return _json_response({"status": "error", "message": "threshold_nm must be a number"}, 400)
        if threshold <= 0:
            return _json_response({"status": "error", "message": "threshold_nm must be > 0"}, 400)

        # Reject a threshold that's already been passed instead of silently
        # firing on the very next tick — this is exactly what happened when a
        # threshold got picked by eyeballing an unrelated "Distance" stat
        # elsewhere on screen (distance to the next waypoint, not to the
        # destination). dest_distance of 0 means no flight plan is loaded yet
        # (or genuinely at the destination) — can't validate against that, so
        # only reject when we have a real, current reading to check against.
        with data_lock:
            current_dest_distance = latest_data.get("dest_distance", 0)
        if current_dest_distance > 0 and threshold >= current_dest_distance:
            return _json_response({
                "status": "error",
                "message": f"already {current_dest_distance:.0f} nm from destination — enter a smaller distance",
            }, 400)

    elif mode == "time":
        at = request.args.get("at", "")
        m = re.match(r"^([0-9]{1,2}):([0-9]{2})$", at)
        if not m:
            return _json_response({"status": "error", "message": "at must be HH:MM (24h Zulu)"}, 400)
        hh, mm = int(m.group(1)), int(m.group(2))
        if hh > 23 or mm > 59:
            return _json_response({"status": "error", "message": "at must be a valid 24h time"}, 400)

        # A time-of-day pause is an alarm, not a one-shot deadline: if HH:MM
        # has already passed today (Zulu), roll it to tomorrow instead of
        # rejecting the arm request — matches how every alarm clock treats
        # "set for a time earlier than now".
        now = datetime.now(timezone.utc)
        target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        time_target = target.timestamp()

    with pause_lock:
        pause_armed = True
        pause_mode = mode
        pause_threshold_nm = threshold
        pause_time_target = time_target
        pause_fired = False

    logging.info(f"[Pause] Armed: mode={mode}, threshold_nm={threshold}, time_target={pause_time_target}")
    return _json_response({
        "status": "ok", "armed": True, "mode": mode,
        "threshold_nm": threshold, "time_target": pause_time_target,
    })


@app.route("/pause/disarm", methods=["POST"])
def pause_disarm_endpoint():
    global pause_armed
    with pause_lock:
        pause_armed = False
    logging.info("[Pause] Disarmed.")
    return _json_response({"status": "ok", "armed": False})


@app.route("/pause/now", methods=["POST"])
def pause_now_endpoint():
    ok = send_sim_command("pause")
    logging.info("[Pause] Manual pause requested." if ok else "[Pause] Manual pause requested but no worker is connected.")
    return _json_response({"status": "ok" if ok else "error"}, 200 if ok else 502)


@app.route("/pause/resume", methods=["POST"])
def pause_resume_endpoint():
    ok = send_sim_command("resume")
    logging.info("[Pause] Manual resume requested." if ok else "[Pause] Manual resume requested but no worker is connected.")
    return _json_response({"status": "ok" if ok else "error"}, 200 if ok else 502)


@app.route("/data")
def data_endpoint():
    mark_client_active()
    with data_lock:
        payload = json.dumps(latest_data)
    response = app.response_class(
        response=payload,
        status=200,
        mimetype="application/json"
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.errorhandler(Exception)
def handle_unexpected_error(e):
    # Flask already turns an uncaught exception into a bare 500 without this,
    # so a bug in a route wouldn't crash the process — but it also wouldn't
    # get logged anywhere useful. This just makes sure it's visible.
    logging.error(f"Unhandled exception in {request.path}: {e}", exc_info=True)
    return _json_response({"status": "error", "error": "internal error"}, 500)


@sock.route("/ws")
def websocket(ws):
    logging.info("[WS] Client connected.")
    try:
        while True:
            mark_client_active()
            with data_lock:
                payload = json.dumps(latest_data)
            ws.send(payload)
            time.sleep(LOOP_INTERVAL_S)
    except Exception:
        pass
    logging.info("[WS] Client disconnected.")


if __name__ == "__main__":
    multiprocessing.freeze_support()  # required for multiprocessing to work once this is a frozen .exe
    setup_logging("bridge")  # main-process-only: workers set up their own, see setup_logging's comment

    local_ip = get_local_ip()
    logging.info("=" * 50)
    logging.info("  MSFS PFD Bridge + SimBrief")
    logging.info("=" * 50)
    logging.info(f"  Open on your phone: http://{local_ip}:5000")
    logging.info("=" * 50)

    threading.Thread(target=simbrief_loop, daemon=True).start()
    threading.Thread(target=simconnect_supervisor, daemon=True).start()
    # Runs concurrently with the MSFS supervisor above regardless of which
    # sim (if either) is actually running - active_backend/_claim_backend
    # arbitrate so only the one that's genuinely connected writes telemetry.
    threading.Thread(target=xplane_supervisor, daemon=True).start()

    # threaded=True: without it, Werkzeug's dev server handles one request at
    # a time, so a long-lived /ws connection would block every other request
    # (including /data polling from other tabs, or the initial page load).
    app.run(host="::", port=5000, debug=False, threaded=True)
