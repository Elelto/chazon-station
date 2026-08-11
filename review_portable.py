#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
review_portable.py - the review station that runs off a USB stick, so volunteers
can help tick books without the catalog itself travelling.

The one rule that shapes everything here: THIS APP NEVER WRITES catalog.json.
It reads a snapshot and appends decisions to decisions/*.jsonl. That matters
because the batch loop at home owns catalog.json, and two writers on two machines
with no shared lock is how you silently lose work. An append-only journal merges
cleanly no matter what ran meanwhile, is a few KB instead of 19MB, and a lost
stick costs you one session's decisions rather than the library.

Merging back home:  python scripts/apply_decisions.py <path-to-decisions-dir>

Layout it expects (portable mode):
    STICK/
      review_portable.py
      python/            portable interpreter
      data/catalog.json  read-only snapshot
      data/crops/        one PNG per book
      data/duplicate_groups.json
      data/reviewers.json   password hash (created by SET-PASSWORD.bat)
      decisions/         output, one .jsonl per day
It also runs straight from the repo for testing, falling back to catalog/ and
crops/ when data/ is absent.

Access: the server binds 127.0.0.1 only - it is not reachable from the network,
so the threat model is somebody walking up to the keyboard, and a shared password
plus a named reviewer is proportionate to that. It is NOT real access control:
FAT32 has no permissions, so anyone holding the stick can read the JSON directly.
The password stops casual meddling through the app, nothing more.
"""
import json, os, re, sys, base64, hashlib, hmac, secrets, datetime, threading
import collections
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# Shown in the header of every session and printed at startup, so "which
# version is this stick running?" is always answerable by phone. Bump on every
# change that ships to a station; UPDATE.bat pulls whatever is published.
VERSION = "1.1 (2026-08-11)"

# Results channel: "שלח תוצאות" POSTs the station's whole journal to the
# owner's Google Form (which needs no login), one paragraph answer per chunk;
# the linked spreadsheet is where journals are collected at home. The form's
# questions are a leftover "Vision Planner" template - harmless, but the entry
# ids below are bound to those questions, so RENAMING questions is safe and
# DELETING them breaks sending. Chunks stay well under Google's answer cap.
SEND_FORM = ("https://docs.google.com/forms/d/e/"
             "1FAIpQLSfSFEAI1Cs1_d4G4b0aXYGQQGRUHxABqrvk0NH7z3mANes7qw"
             "/formResponse")
SEND_FIELD_STATION = "entry.2020053099"     # "full name" -> station + part
SEND_FIELD_DATA = "entry.155726175"         # paragraph   -> meta line + journal lines
SEND_CHUNK = 60_000

HERE = os.path.dirname(os.path.abspath(__file__))
# Overridable so a second copy can be run for testing without fighting the real
# one for the port - the instance guard below deliberately makes that fatal.
PORT = int(os.environ.get("REVIEW_PORT") or 8765)

# Portable layout first, repo layout as the fallback so this can be tested in place.
if os.path.exists(os.path.join(HERE, "data", "catalog.json")):
    ROOT = HERE
    DATA = os.path.join(HERE, "data")
    CATALOG = os.path.join(DATA, "catalog.json")
    CROPS = os.path.join(DATA, "crops")
    DUPS = os.path.join(DATA, "duplicate_groups.json")
    CONFIG = os.path.join(DATA, "reviewers.json")
    # Downscaled shelf photos + their ORIGINAL dimensions, written by
    # deploy_station.py. Originals are 4000x3000 and total 5.8GB; the crop bboxes
    # are in original coordinates, so keeping the true size lets the browser place
    # the highlight as a percentage and stay correct whatever we downscale to.
    PHOTOS = os.path.join(DATA, "photos")
    PHOTO_INDEX = os.path.join(DATA, "photo_index.json")
    PHOTO_DIRS = [PHOTOS]
    STATION_FILE = os.path.join(DATA, "station.json")
else:
    ROOT = os.path.dirname(HERE)
    CATALOG = os.path.join(ROOT, "catalog", "catalog.json")
    CROPS = os.path.join(ROOT, "crops")
    DUPS = os.path.join(ROOT, "catalog", "duplicate_groups.json")
    CONFIG = os.path.join(ROOT, "catalog", "reviewers.json")
    PHOTOS = os.path.join(ROOT, "photos", "processed")
    PHOTO_INDEX = os.path.join(ROOT, "catalog", "photo_index.json")
    # A photo can be in any of these depending on how far the loop got with it.
    PHOTO_DIRS = [os.path.join(ROOT, "photos", d)
                  for d in ("processed", "raw", "failed")]
    STATION_FILE = os.path.join(ROOT, "catalog", "station.json")

DECISIONS_DIR = os.path.join(ROOT, "decisions")

ERROR_TAGS = ("none", "missing_letter", "similar_letter", "stylized",
              "subtitle_confusion", "series_confusion", "inflection",
              "volume", "partial", "other")

ACTIONS = ("candidate", "freetext", "recrop", "skip", "dup_same", "dup_diff")

_WLOCK = threading.Lock()
_SESSIONS = {}          # token -> reviewer name
_CACHE = {"books": None, "dups": None}


# ---------------------------------------------------------------- passwords

def hash_password(pw, salt=None):
    """PBKDF2-HMAC-SHA256. Stdlib only, so the stick needs nothing installed."""
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 200_000)
    return base64.b64encode(salt).decode(), base64.b64encode(dk).decode()


def check_password(pw):
    if not os.path.exists(CONFIG):
        return False
    try:
        cfg = json.load(open(CONFIG, encoding="utf-8"))
        salt = base64.b64decode(cfg["salt"])
        _, want = hash_password(pw, salt)
        return hmac.compare_digest(want, cfg["hash"])   # constant time
    except Exception:
        return False


# ---------------------------------------------------------------- data

def load_station():
    """Which slice of the library this stick carries.

    Four sticks go out at once, each with a quarter of the books, and all four
    journals eventually land in one folder at home. Without a station name they
    are all called decisions-<today>.jsonl and the second copy overwrites the
    first - a whole volunteer's evening, gone silently. The name goes in the
    filename AND in every record, so a mixed-up folder can still be untangled."""
    if _CACHE.get("station") is None:
        try:
            d = json.load(open(STATION_FILE, encoding="utf-8"))
            _CACHE["station"] = {"name": re.sub(r"[^A-Za-z0-9_\-]", "",
                                                str(d.get("name") or ""))[:32],
                                 "label": str(d.get("label") or "")[:90]}
        except Exception:
            _CACHE["station"] = {"name": "", "label": ""}
    return _CACHE["station"]


def load_books():
    if _CACHE.get("books") is None:
        d = json.load(open(CATALOG, encoding="utf-8"))
        _CACHE["books"] = d.get("books", [])
        # The external-verification research (agy) keeps running at home AFTER
        # sticks ship. UPDATE.bat drops its newest findings next to the catalog
        # snapshot, and they are overlaid here IN MEMORY - the snapshot file
        # itself is never rewritten, so a bad update can never corrupt a
        # station: delete the overlay file and the stick is exactly as built.
        try:
            upd = json.load(open(os.path.join(os.path.dirname(CATALOG),
                                              "verification_updates.json"),
                                 encoding="utf-8"))
            over = upd.get("books", {})
            n = 0
            for b in _CACHE["books"]:
                u = over.get(b["id"])
                if u and isinstance(u.get("candidates"), list):
                    b["candidate_matches"] = u["candidates"]
                    n += 1
            if n:
                print("  verification updates: fresh findings for %d book(s)" % n)
        except FileNotFoundError:
            pass
        except Exception as e:
            print("  ! verification_updates.json ignored:", e)
    return _CACHE["books"]


def load_dups():
    if _CACHE.get("dups") is None:
        try:
            _CACHE["dups"] = json.load(open(DUPS, encoding="utf-8")).get("groups", [])
        except Exception:
            _CACHE["dups"] = []
    return _CACHE["dups"]


def load_photo_index():
    """filename -> [original_width, original_height]. Absent in repo mode, where
    the served file IS the original and its own dimensions already match."""
    if _CACHE.get("photos") is None:
        try:
            _CACHE["photos"] = json.load(open(PHOTO_INDEX, encoding="utf-8"))
        except Exception:
            _CACHE["photos"] = {}
    return _CACHE["photos"]


def load_wa_twins():
    """WhatsApp frame -> its pixel-verified camera original. The 29 WhatsApp
    frames are compressed COPIES of 20260705_* originals (both went through
    the loop), so for counting they are one photo and their records add up.
    Verified by fingerprint audit + visual checks, 2026-08-11 - never rebuild
    this mapping from shelf numbers, that is how 21/29 links came out wrong."""
    if _CACHE.get("watwins") is None:
        try:
            p = os.path.join(os.path.dirname(STATION_FILE),
                             "whatsapp_retake_map.json")
            d = json.load(open(p, encoding="utf-8"))
            _CACHE["watwins"] = {
                wa: v["twin_original"]
                for wa, v in (d.get("photos") or {}).items()
                if isinstance(v, dict) and v.get("twin_original")}
        except Exception:
            _CACHE["watwins"] = {}
    return _CACHE["watwins"]


def load_bad_bbox():
    """Ids whose bbox does not reliably locate the book in its photo (checked at
    deploy time against the real crop files). Their ring is suppressed - pointing
    confidently at the wrong spine is worse than showing no ring at all."""
    if _CACHE.get("badbbox") is None:
        try:
            p = os.path.join(os.path.dirname(PHOTO_INDEX), "bbox_unreliable.json")
            _CACHE["badbbox"] = set(json.load(open(p, encoding="utf-8")))
        except Exception:
            _CACHE["badbbox"] = set()
    return _CACHE["badbbox"]


def find_photo(name):
    if not name:
        return None
    for d in PHOTO_DIRS:
        fp = os.path.join(d, name)
        if os.path.exists(fp):
            return fp
    # deploy re-encodes to .jpg; the catalog may still name a .jpeg/.JPG original
    stem = os.path.splitext(name)[0]
    for d in PHOTO_DIRS:
        for ext in (".jpg", ".jpeg", ".JPG", ".png"):
            fp = os.path.join(d, stem + ext)
            if os.path.exists(fp):
                return fp
    return None


def decided_ids():
    """Ids already decided on THIS stick, so a reviewer is never shown a book a
    previous session already handled. Cheap to recompute - the journal is small."""
    seen = set()
    if not os.path.isdir(DECISIONS_DIR):
        return seen
    for fn in os.listdir(DECISIONS_DIR):
        if not fn.endswith(".jsonl"):
            continue
        try:
            with open(os.path.join(DECISIONS_DIR, fn), encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        seen.add(json.loads(line).get("id"))
        except Exception:
            continue        # a half-written line must never block the whole app
    return seen


def decided_shelf_keys():
    """Shelf-count tasks already answered - on this stick's journal, or settled
    at home before the stick was built (shipped as data/shelf_done.json)."""
    seen = set()
    try:
        p = os.path.join(os.path.dirname(STATION_FILE), "shelf_done.json")
        seen.update(json.load(open(p, encoding="utf-8")))
    except Exception:
        pass
    if not os.path.isdir(DECISIONS_DIR):
        return seen
    for fn in os.listdir(DECISIONS_DIR):
        if not fn.endswith(".jsonl"):
            continue
        try:
            with open(os.path.join(DECISIONS_DIR, fn), encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        r = json.loads(line)
                        if r.get("action") == "shelf_count" and r.get("shelf_key"):
                            seen.add(r["shelf_key"])
        except Exception:
            continue
    return seen


def is_confirmed(b):
    return bool(b.get("human_selected_candidate_id") or
                b.get("human_free_text_correction"))


def _sibling_row(sb, pindex, badbb):
    sp = os.path.basename(sb.get("source_photo") or "")
    sbb = sb.get("source_crop_bbox")
    if sb["id"] in badbb or not (isinstance(sbb, list) and len(sbb) == 4
                                 and all(isinstance(x, (int, float)) for x in sbb)):
        sbb = None
    return {"id": sb["id"],
            "title": (sb.get("title") or "").strip(),
            "shelf": str(sb.get("shelf_number", "") or ""),
            "photo": sp, "bbox": sbb, "photo_size": pindex.get(sp)}


def build_rows(filt="todo"):
    books = load_books()
    by_id = {b["id"]: b for b in books}
    done = decided_ids()

    # Map each book to its duplicate group so the card can show the siblings.
    gmap = {}
    for g in load_dups():
        for bid in g["book_ids"]:
            gmap.setdefault(bid, g)

    pindex = load_photo_index()
    badbb = load_bad_bbox()
    rows = []
    for b in books:
        bid = b["id"]
        if filt != "all":
            # station_hide: settled at home before the stick was built. Shipped
            # anyway (the shelf-count screen needs FULL shelves), but never
            # re-issued to a reviewer.
            if is_confirmed(b) or bid in done or b.get("station_hide"):
                continue
        if filt == "dups" and bid not in gmap:
            continue
        g = gmap.get(bid)
        pname = os.path.basename(b.get("source_photo") or "")
        bbox = b.get("source_crop_bbox")
        if bid in badbb or not (isinstance(bbox, list) and len(bbox) == 4
                                and all(isinstance(x, (int, float)) for x in bbox)):
            bbox = None
        rows.append({
            "id": bid,
            "photo": pname,
            # The sharp re-shoot of this book's shelf, for the 392 books whose
            # own source photo is a blurry WhatsApp frame. The strip still draws
            # from the source photo (the bbox lives in ITS coordinates); this
            # only adds readable pixels one click away.
            "retake": os.path.basename(b.get("retake_photo") or ""),
            # bbox is in ORIGINAL photo pixels; pairing it with the original size
            # lets the page position the highlight in percentages, so it stays
            # right no matter what resolution the photo was downscaled to.
            "bbox": bbox,
            "photo_size": pindex.get(pname),
            "shelf": str(b.get("shelf_number", "") or ""),
            "title": (b.get("title") or "").strip(),
            "author": (b.get("author") or "").strip(),
            "volume": str(b.get("volume", "") or ""),
            "publisher": (b.get("publisher") or "").strip(),
            "spine_text": (b.get("visible_spine_text") or "").strip(),
            "candidates": [{
                "cid": c.get("candidate_id", ""),
                "title": (c.get("title") or "").strip(),
                "author": (c.get("author") or "").strip(),
                "publisher": (c.get("publisher") or "").strip(),
                "source": (c.get("source") or "").strip(),
            } for c in (b.get("candidate_matches") or [])],
            "group": None if not g else {
                "group_id": g.get("group_id", ""),
                "relationship": g.get("relationship", "cross_photo"),
                "evidence": g.get("evidence", ""),
                # Each suspect ships with its own photo+bbox so the page can
                # show it ON ITS SHELF, ringed, next to its neighbours. A lone
                # spine crop cannot answer "is this the same physical book?" -
                # especially when the crop itself missed.
                "siblings": [_sibling_row(by_id[s], pindex, badbb)
                             for s in g["book_ids"] if s != bid and s in by_id],
            },
        })

    rows.sort(key=lambda r: int(r["id"][1:]) if r["id"][1:].isdigit() else 0)
    total = len(books)
    return {"rows": rows, "total": total,
            "confirmed": sum(1 for b in books if is_confirmed(b)),
            "decided_here": len(done)}


def build_shelf_tasks():
    """One task per PHOTO: 'this photo produced N records - count the spines'.

    The owner's rulings shaped this into its simplest form. One photo = one
    physical shelf, shot once (sticker numbers interleave across a row, so
    per-shelf-number counting is meaningless - count per photo). No per-book
    boxes and no highlight bands: both confused more than they helped. Show
    the WHOLE photo, say how many records came out of it, and let a person
    count everything on the shelf. A mismatch is typed in as a number;
    reconciling where it lives is the computer's job, at home. No merging of
    twin frames either (owner: "אתה מתבלבל תמיד ביניהם") - a double-shot row
    simply yields two counts that reconcile at home.

    The one display substitution: a record set sourced from a blurry WhatsApp
    frame is SHOWN via its sharp re-shoot (same shelf, owner-confirmed
    duplicate) - counting needs legible spines, and the numbers still refer to
    the WhatsApp frame's records."""
    done = decided_shelf_keys()

    # A station ships a PRE-BAKED task list (photo_count_tasks.json), computed
    # from the FULL catalog at build time. This station's catalog holds only
    # its quarter of the books, and a photo's records routinely split across
    # stations - deriving counts from the partial view would repeat the
    # "counted 16, זוהו 1" bug. Repo mode has the whole catalog, so it derives.
    try:
        pre = json.load(open(os.path.join(os.path.dirname(STATION_FILE),
                                          "photo_count_tasks.json"),
                             encoding="utf-8"))
    except Exception:
        pre = None
    if pre is not None:
        allt = pre.get("tasks", [])
        rows = [t for t in allt if t.get("key") not in done]
        return {"tasks": rows, "total": len(allt),
                "done": len(allt) - len(rows)}

    books = load_books()
    twins = load_wa_twins()

    tasks = collections.OrderedDict()
    for b in books:
        p = os.path.basename(b.get("source_photo") or "")
        if not p:
            continue        # 11 photo-less records; nothing on screen to count
        # A WhatsApp frame and its pixel-verified camera original are the SAME
        # photograph, so their records fold into ONE task under the original's
        # name. Without this, the owner counted 16 spines against "זוהו 1" -
        # the other 15 records were sitting under the WhatsApp twin.
        canon = twins.get(p, p)
        key = "photo:" + canon
        t = tasks.get(key)
        if t is None:
            t = tasks[key] = {"key": key, "photo": canon, "pid": None,
                              "route": None, "count": 0, "shelves": set()}
        t["count"] += 1
        # display the full-res original: served via /photo/ when a record was
        # sourced from it, else via the WhatsApp record's verified /retake/
        if p == canon and t["route"] != "photo":
            t["pid"], t["route"] = b["id"], "photo"
        elif t["route"] is None:
            t["pid"], t["route"] = b["id"], "retake"
        s = str(b.get("shelf_number", "") or "").strip()
        if s:
            t["shelves"].add(s)

    rows = []
    for t in tasks.values():
        if t["key"] in done:
            continue
        t["shelves"] = sorted(t["shelves"],
                              key=lambda x: (not x.isdigit(),
                                             int(x) if x.isdigit() else 0))
        rows.append(t)
    rows.sort(key=lambda t: t["photo"])     # shooting order = shelf order
    return {"tasks": rows, "total": len(tasks), "done": len(tasks) - len(rows)}


SHELF_VERDICTS = ("ok", "wrong", "skip")


def record_shelf(payload, reviewer):
    """A shelf-count verdict. Same journal, different shape: it is about a SHELF,
    not a book, so it carries shelf_key instead of id. `missed` points are in
    ORIGINAL photo pixels - each one says 'there is an uncataloged spine here',
    which is exactly what a later cataloging pass needs to go add it."""
    key = str(payload.get("shelf_key") or "").strip()[:120]
    if not key:
        return {"ok": False, "error": "bad shelf key"}
    verdict = payload.get("verdict")
    if verdict not in SHELF_VERDICTS:
        return {"ok": False, "error": "bad verdict"}
    mc = payload.get("model_count")
    mc = int(mc) if isinstance(mc, (int, float)) else None
    hc = payload.get("human_count")
    hc = int(hc) if isinstance(hc, (int, float)) and hc >= 0 else None
    missed = []
    for m in (payload.get("missed") or [])[:80]:
        if not isinstance(m, dict):
            continue
        ph = os.path.basename(str(m.get("photo") or ""))[:100]
        pt = m.get("point")
        if (ph and isinstance(pt, list) and len(pt) == 2
                and all(isinstance(x, (int, float)) and x >= 0 for x in pt)):
            missed.append({"photo": ph, "point": [round(pt[0]), round(pt[1])]})
    if verdict == "wrong" and hc is None and not missed:
        return {"ok": False, "error": "סמן את הספרים החסרים או הזן את המספר בפועל"}

    rec = {
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "reviewer": reviewer,
        "action": "shelf_count",
        "shelf_key": key,
        "model_count": mc,
        "verdict": verdict,
        "human_count": hc,
        "missed": missed or None,
        "note": (payload.get("note") or "").strip()[:300] or None,
        "station": load_station()["name"] or None,
    }
    os.makedirs(DECISIONS_DIR, exist_ok=True)
    fp = os.path.join(DECISIONS_DIR, "decisions-%s%s.jsonl" % (
        (load_station()["name"] + "-") if load_station()["name"] else "",
        datetime.date.today().isoformat()))
    with _WLOCK:
        with open(fp, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
    return {"ok": True, "shelf_key": key}


def record_decision(payload, reviewer):
    """Append one decision. Append-only on purpose: a crash mid-session loses at
    most the line being written, and a later merge can replay the whole file."""
    if payload.get("action") == "shelf_count":
        return record_shelf(payload, reviewer)
    bid = payload.get("id")
    action = payload.get("action")
    if not re.match(r"^b\d+$", bid or ""):
        return {"ok": False, "error": "bad id"}
    if action not in ACTIONS:
        return {"ok": False, "error": "unknown action"}
    etag = payload.get("error_type")
    if etag not in ERROR_TAGS:
        etag = None

    # Two different questions, and only one of them is the reviewer's job.
    #
    #   crop_ok  - "is the highlighted book the one this record describes?"
    #              REQUIRED. If the pointer is on the wrong spine the reviewer
    #              confirms another book's title onto this record, which corrupts
    #              the catalog silently. This is not a nicety.
    #
    #   cbox     - where the book actually is. Only ever sent alongside
    #              crop_ok=False, and it is no longer DRAWN: the page hands the
    #              reviewer the model's own frame and they drag it onto the right
    #              spine, so a correction costs a gesture rather than a
    #              construction. It arrives in ORIGINAL photo pixels.
    #
    #   cpt      - a bare point, from older clients that only pointed. Still
    #              accepted so an old stick's journal merges, but nothing produces
    #              one now.
    crop_ok = payload.get("crop_ok")
    if crop_ok not in (True, False, None):
        crop_ok = None
    cbox = payload.get("corrected_bbox")
    if not (isinstance(cbox, list) and len(cbox) == 4
            and all(isinstance(x, (int, float)) for x in cbox)
            and cbox[2] - cbox[0] >= 8 and cbox[3] - cbox[1] >= 8
            and min(cbox) >= 0):
        cbox = None
    # A single click on the right spine, in ORIGINAL photo pixels.
    cpt = payload.get("corrected_point")
    if not (isinstance(cpt, list) and len(cpt) == 2
            and all(isinstance(x, (int, float)) and x >= 0 for x in cpt)):
        cpt = None
    if action == "recrop" and crop_ok is None:
        # "the photo is bad / the book is not visible" IS a crop verdict.
        crop_ok = False
    if action != "skip":
        if crop_ok is None:
            return {"ok": False, "error": "crop verdict required"}
        if (crop_ok is False and cbox is None and cpt is None
                and action != "recrop"):
            return {"ok": False,
                    "error": "when the frame is wrong, click the right book"}

    rec = {
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "reviewer": reviewer,
        "id": bid,
        "action": action,
        "candidate_id": payload.get("candidate_id") or None,
        "text": (payload.get("text") or "").strip()[:300] or None,
        "error_type": etag,
        "note": (payload.get("note") or "").strip()[:300] or None,
        "group_id": payload.get("group_id") or None,
        "crop_ok": crop_ok,
        # "I vouch for the title, but author/subject are unknowable from the
        # spine" - routes the book into the external-verification queue instead
        # of letting a confirm overclaim knowledge the reviewer never had.
        "needs_verification": bool(payload.get("needs_verification")),
        # In ORIGINAL photo pixels - the same space every source_crop_bbox uses,
        # so a correction can sit beside the box it replaces as a training pair.
        "corrected_bbox": cbox,
        # Kept in the record rather than dropped: validating a field and then not
        # writing it is how a reviewer's work disappears silently.
        "corrected_point": cpt,
    }
    rec["station"] = load_station()["name"] or None
    os.makedirs(DECISIONS_DIR, exist_ok=True)
    fp = os.path.join(DECISIONS_DIR, "decisions-%s%s.jsonl" % (
        (load_station()["name"] + "-") if load_station()["name"] else "",
        datetime.date.today().isoformat()))
    with _WLOCK:
        with open(fp, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())    # a USB stick can be yanked without warning
    return {"ok": True, "id": bid, "action": action}


def send_results():
    """POST every journal line home through the owner's Google Form.

    Always sends EVERYTHING, not a diff: apply_decisions.py dedups by
    (ts, id/shelf_key, action), so a resend costs nothing and a partial earlier
    send can never lose work. The journal also stays on the stick - this is a
    copy home, not a move. Success is detected by the confirmation page having
    no <form> element (the error path re-renders the form), which is
    language-independent."""
    import urllib.request
    from urllib.parse import urlencode
    lines = []
    if os.path.isdir(DECISIONS_DIR):
        for fn in sorted(os.listdir(DECISIONS_DIR)):
            if fn.endswith(".jsonl"):
                with open(os.path.join(DECISIONS_DIR, fn), encoding="utf-8") as f:
                    lines += [l.rstrip("\n") for l in f if l.strip()]
    if not lines:
        return {"ok": False, "error": "אין עדיין החלטות לשלוח"}

    chunks, cur, size = [], [], 0
    for l in lines:
        if size + len(l) > SEND_CHUNK and cur:
            chunks.append(cur); cur, size = [], 0
        cur.append(l); size += len(l) + 1
    chunks.append(cur)

    st = load_station()["name"] or "?"
    now = datetime.datetime.now().isoformat(timespec="seconds")
    for i, ch in enumerate(chunks, 1):
        meta = json.dumps({"station": st, "sent": now, "part": i,
                           "of": len(chunks), "lines": len(ch)},
                          ensure_ascii=False)
        data = urlencode({
            SEND_FIELD_STATION: "%s - %d/%d" % (st, i, len(chunks)),
            SEND_FIELD_DATA: meta + "\n" + "\n".join(ch),
        }).encode("utf-8")
        req = urllib.request.Request(SEND_FORM, data=data, headers={
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                body = r.read(300_000).decode("utf-8", "replace")
                if r.status != 200 or "<form" in body:
                    return {"ok": False,
                            "error": "השליחה נדחתה בחלק %d מתוך %d - נסה שוב"
                                     % (i, len(chunks))}
        except Exception:
            return {"ok": False,
                    "error": "אין חיבור לאינטרנט - נסה שוב כשיש רשת"}
    return {"ok": True, "sent": len(lines), "parts": len(chunks)}


# ---------------------------------------------------------------- http

class Handler(BaseHTTPRequestHandler):
    server_version = "ReviewStation"

    def _send(self, code, body, ctype="application/json; charset=utf-8", cookie=None,
              nocache=False):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if nocache:
            self.send_header("Cache-Control", "no-store, must-revalidate")
        if cookie:
            self.send_header("Set-Cookie",
                             "sid=%s; Path=/; HttpOnly; SameSite=Strict" % cookie)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

    def _reviewer(self):
        raw = self.headers.get("Cookie") or ""
        m = re.search(r"sid=([A-Za-z0-9_\-]+)", raw)
        return _SESSIONS.get(m.group(1)) if m else None

    def do_GET(self):
        path = urlparse(self.path).path
        who = self._reviewer()

        if path == "/":
            # No-store on the HTML: the page carries all the app code, so a cached
            # copy silently pins a reviewer to an old version after an update.
            self._send(200, LOGIN if not who else PAGE, "text/html; charset=utf-8",
                       nocache=True)
        elif path == "/api/books":
            if not who:
                self._send(401, {"error": "login required"}); return
            q = parse_qs(urlparse(self.path).query)
            self._send(200, build_rows((q.get("filter") or ["todo"])[0]))
        elif path == "/api/shelves":
            if not who:
                self._send(401, {"error": "login required"}); return
            self._send(200, build_shelf_tasks())
        elif path == "/api/me":
            self._send(200, {"reviewer": who, "configured": os.path.exists(CONFIG),
                             "station": load_station()["label"],
                             "version": VERSION})
        elif path.startswith("/crop/"):
            if not who:
                self._send(401, b"", "text/plain"); return
            cid = path[len("/crop/"):]
            if not re.match(r"^b\d+$", cid):        # no path traversal via the id
                self._send(404, b"", "text/plain"); return
            fp = os.path.join(CROPS, cid + ".png")
            if not os.path.exists(fp):
                self._send(404, b"", "text/plain"); return
            with open(fp, "rb") as f:
                self._send(200, f.read(), "image/png")
        elif path.startswith("/photo/") or path.startswith("/retake/"):
            if not who:
                self._send(401, b"", "text/plain"); return
            field = "source_photo" if path.startswith("/photo/") else "retake_photo"
            cid = path.rsplit("/", 1)[1]
            if not re.match(r"^b\d+$", cid):
                self._send(404, b"", "text/plain"); return
            # Resolve through the catalog rather than trusting a filename from the
            # URL - the id is validated, an arbitrary path would not be.
            b = next((x for x in load_books() if x["id"] == cid), None)
            fp = find_photo(os.path.basename((b or {}).get(field, "") or ""))
            if not fp:
                self._send(404, b"", "text/plain"); return
            ctype = "image/png" if fp.lower().endswith(".png") else "image/jpeg"
            with open(fp, "rb") as f:
                self._send(200, f.read(), ctype)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            payload = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            self._send(400, {"error": "bad json"}); return

        if path == "/api/login":
            name = (payload.get("name") or "").strip()[:40]
            pw = payload.get("password") or ""
            if not name:
                self._send(400, {"error": "צריך למלא שם"}); return
            if not os.path.exists(CONFIG):
                self._send(400, {"error": "לא הוגדרה סיסמה - הרץ SET-PASSWORD.bat"}); return
            if not check_password(pw):
                self._send(403, {"error": "סיסמה שגויה"}); return
            tok = secrets.token_urlsafe(24)
            _SESSIONS[tok] = name
            self._send(200, {"ok": True, "reviewer": name}, cookie=tok)
            return

        who = self._reviewer()
        if not who:
            self._send(401, {"error": "login required"}); return
        if path == "/api/decide":
            self._send(200, record_decision(payload, who))
        elif path == "/api/send":
            self._send(200, send_results())
        else:
            self._send(404, {"error": "not found"})


LOGIN = r"""<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>כניסה - בדיקת קטלוג</title>
<style>
body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
background:#f4f1ea;color:#1f1e1b;font-family:"Segoe UI",Arial,sans-serif}
.box{background:#fff;border:1px solid #e3ddd0;border-radius:16px;padding:34px;width:340px}
h1{margin:0 0 6px;font-size:21px}p{margin:0 0 22px;color:#8a857a;font-size:13px}
label{display:block;font-size:13px;color:#8a857a;margin:14px 0 5px}
input{width:100%;padding:11px;border-radius:9px;border:1px solid #e3ddd0;background:#faf8f4;
color:#1f1e1b;font-size:15px}
button{width:100%;margin-top:22px;padding:12px;border:none;border-radius:9px;background:#1d9e75;
color:#fff;font-size:15px;font-weight:600;cursor:pointer}
.err{color:#d85a30;font-size:13px;margin-top:12px;min-height:18px}
</style></head><body>
<div class="box">
<h1>בדיקת קטלוג</h1><p>ספריית חזון יוסף</p>
<label>השם שלך</label><input id="n" autofocus autocomplete="off">
<label>סיסמה</label><input id="p" type="password">
<button onclick="go()">כניסה</button>
<div class="err" id="e"></div>
</div>
<script>
async function go(){
  const r = await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name:document.getElementById('n').value,
                         password:document.getElementById('p').value})});
  const j = await r.json();
  if(j.ok) location.reload(); else document.getElementById('e').textContent = j.error||'שגיאה';
}
addEventListener('keydown',e=>{if(e.key==='Enter')go()});
</script></body></html>"""


PAGE = r"""<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>בדיקת קטלוג</title>
<style>
/* One screen, one question, three buttons. The shelf strip IS the interface:
   the model's pick is ringed, and fixing a wrong pick is a single click on the
   correct spine. No draw tools, no zoom chrome, no side panels. */
:root{--bg:#f4f1ea;--card:#ffffff;--ink:#1f1e1b;--mut:#8a857a;--line:#e3ddd0;
--ok:#1d9e75;--okbg:#e1f5ee;--okink:#0f6e56;--bad:#d85a30;--acc:#4a7dbd}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font-family:"Segoe UI",Arial,sans-serif}
#bar{position:sticky;top:0;z-index:9;background:var(--bg);padding:8px 18px 6px;
display:flex;gap:14px;align-items:center}
#bar .mut{color:var(--mut);font-size:13px;white-space:nowrap}
.prog{flex:1;height:5px;background:#e6e1d6;border-radius:3px;overflow:hidden}
.prog i{display:block;height:100%;background:var(--ok)}
.wrap{max-width:860px;margin:0 auto;padding:4px 16px 8px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;
padding:12px 24px 10px;text-align:center}
.h{color:var(--mut);font-size:12.5px;margin:0 0 6px}
.t{font-size:26px;font-weight:600;margin:0;line-height:1.2;
font-family:"David","Frank Ruhl Libre",Georgia,serif}
.a{color:var(--mut);font-size:15px;margin:4px 0 0}
#ask{font-size:15px;color:#5c574c;margin:9px 0 7px;min-height:20px}
#sw{position:relative;display:flex;justify-content:center}
#strip{border-radius:10px;cursor:pointer;max-width:100%;background:#eee}
.crop1{max-height:46vh;max-width:240px;border-radius:10px;background:#000}
.hint{font-size:12.5px;color:var(--mut);margin-top:5px}
.btns{display:flex;gap:10px;margin-top:11px}
button{font-size:15px;border-radius:10px;border:1px solid var(--line);
background:#faf8f4;color:var(--ink);cursor:pointer;padding:0 16px;height:48px}
button:hover{border-color:#c9c2b2}
#ok{flex:2.2;font-size:17px;font-weight:600;background:var(--okbg);
border:1.5px solid var(--ok);color:var(--okink)}
#ok:hover{background:#d2efe4}
#wr{flex:1.2}
#sk{flex:0 0 86px;color:var(--mut)}
.links{margin-top:7px;font-size:13px}
.links a{color:var(--mut);text-decoration:underline;cursor:pointer;margin:0 10px}
#fix{display:none;text-align:right;border:1px solid var(--line);border-radius:12px;
padding:14px;margin-top:16px;background:#faf8f4}
#fix .q{font-size:14px;font-weight:600;margin:0 0 10px}
.cand{border:1px solid var(--line);background:#fff;border-radius:9px;
padding:6px 11px;margin-bottom:5px;cursor:pointer;font-size:14px;text-align:right}
.cand.on{border-color:var(--ok);background:var(--okbg)}
.cand .s{color:var(--mut);font-size:12px}
#fix input{width:100%;padding:11px;border-radius:9px;border:1px solid var(--line);
font-size:15px;background:#fff;color:var(--ink)}
#fix .row{display:flex;gap:8px;margin-top:10px}
#fix .row button{height:42px;font-size:14px}
#cands{max-width:600px;margin:8px auto 0;text-align:right;max-height:18vh;overflow-y:auto}
.q2{font-size:13px;font-weight:600;color:#5c574c;margin:0 0 7px}
#nv{display:block;max-width:600px;margin:9px auto 0;font-size:13.5px;color:#6a6559;
text-align:right;cursor:pointer}
#nv.warn{color:#a06a1e}
#nv input{vertical-align:-2px;margin-left:6px}
#fixok{background:var(--okbg);border-color:var(--ok);color:var(--okink);font-weight:600}
.dup{border:1px solid #e8c88a;background:#fbf4e4;border-radius:12px;
padding:12px;margin-top:16px;text-align:right}
.dup h4{margin:0 0 6px;font-size:14px;color:#8a6414}
.dup .mut{color:#8a857a;font-size:12.5px}
/* Comparing two spines is the whole decision, so the crops are BIG and every
   one zooms to full screen on click. This book's own crop stands first, ringed
   green, so the reviewer always compares against the right thing. */
.sib{display:flex;gap:14px;flex-wrap:wrap;margin:10px 0;justify-content:center}
.sib figure{margin:0;text-align:center}
.sib img,.sib canvas{max-height:300px;border-radius:7px;background:#eee;cursor:zoom-in}
.sib figure.me img,.sib figure.me canvas{outline:3px solid var(--ok);outline-offset:2px}
.sib figcaption{font-size:12.5px;color:var(--mut);margin-top:4px;max-width:230px}
.sib figure.me figcaption{color:var(--okink);font-weight:600}
#ov{position:fixed;inset:0;background:rgba(20,18,15,.95);display:none;
align-items:center;justify-content:center;z-index:50;cursor:grab;
touch-action:none;overflow:hidden}
#ov img{max-height:97vh;max-width:97vw;transform-origin:center center}
.dup .row{display:flex;gap:8px}
.dup .row button{height:40px;font-size:13.5px;flex:1}
#done{text-align:center;padding:80px 20px;color:var(--mut);font-size:18px}
kbd{background:#eee9dd;border:1px solid var(--line);border-radius:4px;
padding:0 5px;font-size:11px;color:#6a6559}
/* ---- the two jobs: book-by-book, and shelf counting ---- */
.tab{height:30px;padding:0 14px;font-size:13px;border-radius:15px;cursor:pointer;
background:transparent;border:1px solid var(--line);color:var(--mut)}
.tab.on{background:#fff;color:var(--ink);border-color:#c9c2b2;font-weight:600}
.bigct{font-size:15px;color:#5c574c;margin:4px 0 0}
.fnav{display:flex;gap:12px;align-items:center;justify-content:center;
font-size:13.5px;color:var(--mut);margin:0 0 10px}
.fnav button{height:36px;padding:0 16px;font-size:17px}
#shwrap{overflow-x:auto;border-radius:10px;background:#eee}
#shcv{display:block;cursor:zoom-in}
#shcap{min-height:20px;font-size:14px;color:var(--acc);margin-top:8px;font-weight:600}
details{margin:14px auto 0;max-width:680px;text-align:right}
summary{cursor:pointer;font-size:13.5px;color:var(--mut)}
.tl{font-size:13.5px;color:#5c574c;margin-top:8px;column-width:200px;column-gap:22px}
.tl div{break-inside:avoid;padding:1px 0}
#exc{display:none;border:1px solid var(--line);border-radius:12px;padding:14px;
margin-top:16px;background:#faf8f4}
#exc .q{font-size:14px;font-weight:600;margin:0 0 10px;text-align:right}
#exc .st{display:flex;gap:8px;justify-content:center;align-items:center}
#exc .st button{width:48px;height:48px;font-size:22px}
#exc input{width:96px;height:48px;text-align:center;font-size:21px;
border:1px solid var(--line);border-radius:9px;background:#fff;color:var(--ink)}
#exc .row{display:flex;gap:8px;margin-top:12px}
#exc .row button{height:42px;font-size:14px;flex:1}
</style></head><body>
<div id="bar">
  <b style="font-size:14px">בדיקת קטלוג</b>
  <span class="mut" id="who"></span>
  <button id="tabb" class="tab on" onclick="setMode('books')">ספרים</button>
  <button id="tabs" class="tab" onclick="setMode('shelves')">ספירת ספרים</button>
  <button id="sendb" class="tab" onclick="sendHome()"
    style="border-color:#1d9e75;color:#0f6e56">שלח תוצאות</button>
  <div class="prog"><i id="pb" style="width:0"></i></div>
  <span class="mut" id="cnt"></span>
</div>
<div class="wrap"><div id="app"></div></div>
<div id="ov"><img id="ovi" draggable="false"></div>
<script>
const $=s=>document.querySelector(s);
/* The zoom overlay pans and magnifies: wheel zooms toward the cursor (1-5x),
   dragging moves the image, a plain click (no drag) or Escape closes. The
   image starts fit-to-screen, so one wheel notch already adds real pixels. */
let ZS=1,ZX=0,ZY=0,ZD=null;
function applyZ(){$('#ovi').style.transform=
  'translate('+ZX+'px,'+ZY+'px) scale('+ZS+')';}
function zoom(s){$('#ovi').src=s;ZS=1;ZX=ZY=0;applyZ();
  $('#ov').style.display='flex';}
(function(){
  const ov=document.getElementById('ov');
  ov.addEventListener('wheel',function(e){
    e.preventDefault();
    const ns=Math.min(5,Math.max(1,ZS*(e.deltaY<0?1.25:0.8)));
    if(ns===ZS)return;
    // keep the point under the cursor fixed while scaling
    const cx=e.clientX-innerWidth/2, cy=e.clientY-innerHeight/2;
    ZX=cx-(cx-ZX)*ns/ZS; ZY=cy-(cy-ZY)*ns/ZS; ZS=ns;
    if(ZS===1){ZX=ZY=0}
    applyZ();
  },{passive:false});
  ov.addEventListener('pointerdown',function(e){
    ZD={x:e.clientX,y:e.clientY,ox:ZX,oy:ZY,moved:false};
    try{ov.setPointerCapture(e.pointerId)}catch(x){}
  });
  ov.addEventListener('pointermove',function(e){
    if(!ZD)return;
    const dx=e.clientX-ZD.x, dy=e.clientY-ZD.y;
    if(Math.abs(dx)+Math.abs(dy)>4)ZD.moved=true;
    if(ZD.moved){ZX=ZD.ox+dx;ZY=ZD.oy+dy;applyZ();}
  });
  ov.addEventListener('pointerup',function(e){
    const moved=ZD&&ZD.moved; ZD=null;
    if(!moved)ov.style.display='none';   // a click, not a drag, closes
  });
})();
let D=[],i=0,SEL=null,CLICK=null,MAP=null,WIDE=false;
let IMG=new Image(),IMGSRC='';
let SIBS=[],SIBIMG={};
/* photo-count mode: T=tasks (one per photo), ti=current, SHIMG=image cache */
let MODE='books',T=null,ti=0,SHMAP=null,SHIMG={};

async function boot(){
  const me=await (await fetch('/api/me')).json();
  $('#who').textContent=(me.reviewer||'')+(me.station?' · '+me.station:'')+
    (me.version?' · v'+me.version:'');
  const d=await (await fetch('/api/books?filter=todo')).json();
  D=d.rows; render();
}
let SENDING=false;
async function sendHome(){
  if(SENDING)return;
  if(!confirm('לשלוח הביתה את כל ההחלטות שנעשו בתחנה הזאת?\n'+
              'אפשר לשלוח כמה פעמים - כפילויות מסוננות בבית.'))return;
  SENDING=true;
  const b=$('#sendb'), t0=b?b.textContent:'';
  if(b){b.disabled=true;b.textContent='שולח...'}
  try{
    const r=await fetch('/api/send',{method:'POST',
      headers:{'Content-Type':'application/json'},body:'{}'});
    const j=await r.json();
    alert(j.ok?('נשלחו הביתה '+j.sent+' החלטות. תודה רבה!')
              :(j.error||'שגיאה בשליחה'));
  }catch(e){alert('שגיאה בשליחה - נסה שוב');}
  if(b){b.disabled=false;b.textContent=t0}
  SENDING=false;
}
async function setMode(m){
  MODE=m;
  $('#tabb').className='tab'+(m==='books'?' on':'');
  $('#tabs').className='tab'+(m==='shelves'?' on':'');
  if(m==='shelves'&&T===null){
    const d=await (await fetch('/api/shelves')).json();
    T=d.tasks; ti=0;
  }
  render();
}
function stat(){
  $('#cnt').textContent='נותרו '+(D.length-i);
  $('#pb').style.width=(D.length?100*i/D.length:0)+'%';
}
function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;')}

function render(){
  if(MODE==='shelves'){renderShelf();return}
  renderBook();
}

function renderBook(){
  stat(); SEL=null; CLICK=null; MAP=null; WIDE=false; SIBS=[];
  if(i>=D.length){$('#app').innerHTML='<div id="done">סיימת את כל הספרים. תודה רבה!'+
    '<br><br><button style="height:46px" onclick="setMode(\'shelves\')">'+
    'המשך לספירת הספרים</button> '+
    '<button style="height:46px;border-color:#1d9e75;color:#0f6e56" '+
    'onclick="sendHome()">שלח את התוצאות הביתה</button></div>';return}
  const c=D[i];
  const hasStrip=!!(c.photo&&c.bbox);
  let mid;
  if(hasStrip){
    mid='<div id="sw"><canvas id="strip"></canvas></div>'+
        '<div class="hint">המסגרת כמעט נכונה? גרור אותה מעט · ספר אחר לגמרי? לחץ עליו</div>';
  }else{
    mid='<div id="sw"><img class="crop1" src="/crop/'+c.id+'"></div>'+
        '<div class="hint">לספר הזה אין תמונת מדף - רואים רק את החיתוך</div>';
  }
  let dup='';
  if(c.group){
    // Every suspect is shown ON ITS SHELF with its neighbours, ringed - a lone
    // spine crop cannot answer "same physical book?", least of all when the
    // crop itself missed the spine.
    SIBS=[{id:c.id,title:'הספר הזה',shelf:c.shelf,photo:c.photo,bbox:c.bbox,
           photo_size:c.photo_size,me:true}].concat(c.group.siblings);
    const fig=s=>{
      const cap=(s.me?'הספר הזה':esc((s.title||'').slice(0,26)))+' · מדף '+esc(s.shelf||'—');
      const body=(s.photo&&s.bbox)
        ? '<canvas class="sibcv" data-sid="'+s.id+'"></canvas>'
        : '<img src="/crop/'+s.id+'" onclick="zoom(this.src)">';
      return '<figure'+(s.me?' class="me"':'')+'>'+body+
             '<figcaption>'+cap+'</figcaption></figure>';
    };
    dup='<div class="dup"><h4>ייתכן שזה אותו ספר שנרשם פעמיים</h4>'+
      '<div class="mut">'+esc(c.group.evidence)+'</div><div class="sib">'+
      SIBS.map(fig).join('')+
      '</div><div class="mut" style="font-size:12px">כל ספר מוצג על המדף שלו עם השכנים · לחיצה מגדילה למסך מלא</div>'+
      '<div class="row">'+
      '<button onclick="dupq(\'dup_same\')">אותו ספר - למזג</button>'+
      '<button onclick="dupq(\'dup_diff\')">ספרים שונים</button></div></div>';
  }
  // The external-verification findings (agy's web research) sit ON the card,
  // not behind a button. A spine that says only "בית פרץ" tells nobody who
  // wrote it or what it is - the candidates are the only added knowledge this
  // project has, so hiding them made every confirm an under-informed confirm.
  const cands=c.candidates.length?
    '<div id="cands"><p class="q2">האימות החיצוני מצא:</p>'+
    c.candidates.map((x,n)=>
      '<div class="cand" id="c'+n+'" onclick="pick('+n+')"><b>'+(n+1)+'. '+esc(x.title)+'</b>'+
      (x.author?' — '+esc(x.author):'')+
      '<div class="s">'+esc(x.publisher)+' '+esc(x.source)+'</div></div>').join('')+
    '</div>':'';
  // No author and no external findings = the בית פרץ case: the reviewer can
  // vouch for the TITLE but genuinely cannot know author or subject. The
  // checkbox lets them say exactly that instead of overclaiming.
  const bare=!c.author&&!c.candidates.length;
  const nv='<label id="nv"'+(bare?' class="warn"':'')+'>'+
    '<input type="checkbox" id="nvc"'+(bare?' checked':'')+'> '+
    'הכותרת מאושרת, אבל המחבר או הנושא לא ידועים - דרוש אימות חיצוני'+
    (bare?' <b>(אין מחבר ואין ממצאים)</b>':'')+'</label>';
  $('#app').innerHTML='<div class="card">'+
    '<p class="h">'+c.id+' · מדף '+esc(c.shelf||'—')+(c.volume?' · כרך '+esc(c.volume):'')+'</p>'+
    '<p class="t">'+(esc(c.title)||'<span style="color:#b8b2a4">(לא נקראה כותרת)</span>')+'</p>'+
    (c.author?'<p class="a">'+esc(c.author)+'</p>'
             :'<p class="a" style="color:#c58a3a">מחבר לא ידוע</p>')+
    cands+
    '<div id="ask"></div>'+mid+dup+
    '<div id="fix">'+
      '<p class="q">מה הכותרת הנכונה?</p>'+
      '<input id="ft" placeholder="הקלד את הכותרת כפי שהיא על הספר" autocomplete="off">'+
      '<div class="row"><button id="fixok" onclick="saveFix()">שמור</button>'+
      '<button onclick="closeFix()">ביטול</button></div>'+
    '</div>'+
    nv+
    '<div class="btns">'+
      '<button id="ok" onclick="confirmBook()"></button>'+
      '<button id="wr" onclick="openFix()">הכותרת שגויה <kbd>E</kbd></button>'+
      '<button id="sk" onclick="send({action:\'skip\'})">דלג <kbd>S</kbd></button>'+
    '</div>'+
    '<div class="links">'+
      (hasStrip?'<a onclick="zoomStrip()">תצוגה מקורבת <kbd>Z</kbd></a>':'')+
      (hasStrip?'<a onclick="WIDE=!WIDE;drawStrip()">הצג יותר מהמדף</a>':'')+
      (c.retake?'<a href="/retake/'+c.id+'" target="_blank" '+
        'style="color:var(--acc)">המדף בצילום חד ונקי</a>':'')+
      '<a onclick="send({action:\'recrop\',_bad:1})">הצילום גרוע / הספר לא נראה</a>'+
    '</div></div>';
  paint();
  if(hasStrip)loadStrip();
  loadSibs();
}

/* ---- duplicate suspects, each on its own shelf --------------------------- */
function loadSibs(){
  SIBS.filter(s=>s.photo&&s.bbox).forEach(function(s){
    const im=SIBIMG[s.id];
    if(im&&im.complete&&im.naturalWidth){drawSib(s,im,false);return}
    const img=new Image();
    img.onload=function(){SIBIMG[s.id]=img;drawSib(s,img,false)};
    img.src='/photo/'+s.id;
  });
}
function drawSib(s,img,big){
  const sz=s.photo_size||[img.naturalWidth,img.naturalHeight];
  const k=img.naturalWidth/sz[0], bb=s.bbox.map(v=>v*k);
  const bw=bb[2]-bb[0], bh=bb[3]-bb[1];
  // "This book" follows the reviewer's correction LIVE: once they drag or click
  // the main strip, the comparison ring moves to the corrected spine too -
  // otherwise the dup question would be asked about the wrong book.
  let ebb=bb, corr=false;
  if(s.me&&CLICK){
    const cx=CLICK[0]*k;
    ebb=[cx-bw/2,bb[1],cx+bw/2,bb[3]]; corr=true;
  }
  // ±2.2 books of context inline; the zoomed view widens to ±3.5. The zoom may
  // upscale to 3x, because the WhatsApp frames are small and "blurry but big"
  // still beats a thumbnail nobody can compare.
  const padx=(big?3.5:2.2)*bw, pady=0.08*bh;
  const x0=Math.max(0,ebb[0]-padx), x1=Math.min(img.naturalWidth,ebb[2]+padx);
  const y0=Math.max(0,ebb[1]-pady), y1=Math.min(img.naturalHeight,ebb[3]+pady);
  const dpr=Math.min(2,window.devicePixelRatio||1);
  const capH=(big?Math.min(1400,window.innerHeight*0.94):300)*dpr;
  const sc=Math.min(capH/(y1-y0),big?3:1.6);
  const W=Math.round((x1-x0)*sc), H=Math.round((y1-y0)*sc);
  const cv=big?document.createElement('canvas')
              :document.querySelector('.sibcv[data-sid="'+s.id+'"]');
  if(!cv)return null;
  cv.width=W; cv.height=H;
  if(!big){cv.style.width=(W/dpr)+'px';cv.style.height=(H/dpr)+'px';}
  const g=cv.getContext('2d');
  g.drawImage(img,x0,y0,x1-x0,y1-y0,0,0,W,H);
  g.lineWidth=Math.max(3,3*dpr);
  if(corr){
    // the model's original spot stays as a dashed ghost, same as the main strip
    g.strokeStyle='#e0443f'; g.setLineDash([8*dpr,6*dpr]);
    g.strokeRect((bb[0]-x0)*sc,(bb[1]-y0)*sc,bw*sc,bh*sc);
    g.setLineDash([]);
  }
  g.strokeStyle=s.me?'#1d9e75':'#e0443f';
  g.strokeRect((ebb[0]-x0)*sc,(ebb[1]-y0)*sc,(ebb[2]-ebb[0])*sc,(ebb[3]-ebb[1])*sc);
  return cv;
}
function syncMeSib(){
  const me=SIBS.find(x=>x.me&&x.photo&&x.bbox);
  if(me&&SIBIMG[me.id])drawSib(me,SIBIMG[me.id],false);
}
addEventListener('click',function(e){
  if(!e.target.classList||!e.target.classList.contains('sibcv'))return;
  const s=SIBS.find(x=>x.id===e.target.getAttribute('data-sid'));
  const im=s&&SIBIMG[s.id];
  if(!im)return;
  const big=drawSib(s,im,true);
  if(big)zoom(big.toDataURL('image/jpeg',0.9));
});

function paint(){
  const c=D[i], ok=$('#ok'), ask=$('#ask');
  if(!ok)return;
  syncMeSib();   // the dup comparison follows the correction in real time
  const sel=SEL!==null?' - עם ההצעה שנבחרה':'';
  if(CLICK){
    const ob=c.bbox, nudge=Math.abs(CLICK[0]-(ob[0]+ob[2])/2)<(ob[2]-ob[0]);
    ask.textContent=nudge?'הזזת את המסגרת. אשר אם עכשיו היא על הספר במדויק'
                         :'סימנת ספר אחר במדף. אשר, או לחץ במקום אחר לתקן';
    ok.innerHTML='אישור - הספר הוא זה שסימנתי'+sel+' <kbd>Enter</kbd>';
  }else if(c.photo&&c.bbox){
    ask.textContent='האם זה הספר המסומן במסגרת?';
    ok.innerHTML='כן, זה הספר'+sel+' <kbd>Enter</kbd>';
  }else{
    ask.textContent='האם הכותרת נכונה לספר שבתמונה?';
    ok.innerHTML='כן, נכון'+sel+' <kbd>Enter</kbd>';
  }
}

/* ---- the strip ---------------------------------------------------------- */
function loadStrip(){
  const c=D[i], src='/photo/'+c.id;
  if(IMGSRC===src&&IMG.complete&&IMG.naturalWidth){drawStrip();return}
  IMG=new Image(); IMGSRC=src; IMG.onload=drawStrip; IMG.src=src;
}
function drawStrip(){
  const c=D[i], cv=$('#strip');
  if(!cv||!IMG.naturalWidth)return;
  const sz=c.photo_size||[IMG.naturalWidth,IMG.naturalHeight];
  // bbox is in ORIGINAL pixels; the served photo may be a downscaled copy.
  const k=IMG.naturalWidth/sz[0];
  const bb=c.bbox.map(v=>v*k);
  const bw=bb[2]-bb[0], bh=bb[3]-bb[1];
  const padx=WIDE?60*bw:3.2*bw, pady=0.07*bh;
  const x0=Math.max(0,bb[0]-padx), x1=Math.min(IMG.naturalWidth,bb[2]+padx);
  const y0=Math.max(0,bb[1]-pady), y1=Math.min(IMG.naturalHeight,bb[3]+pady);
  const sw=$('#sw'), card=sw.closest('.card');
  const cssW=Math.max(300,sw.clientWidth||820);
  const dpr=Math.min(2,window.devicePixelRatio||1);
  // The strip gets exactly the height LEFT OVER at 100% zoom: viewport minus
  // what sits above it (title, candidates) and below it (buttons, links, dup
  // panel). A fixed 62% budget pushed the buttons off-screen whenever the
  // card carried candidates - the reviewer had to zoom the browser out to 67%
  // to see the whole card. Floor of 300px keeps spines readable; cards with a
  // big duplicate panel may still scroll, everything else fits one screen.
  const swTop=sw.getBoundingClientRect().top+window.scrollY;
  const below=card?card.getBoundingClientRect().bottom
                   -sw.getBoundingClientRect().bottom:120;
  const capH=Math.max(240,Math.round(window.innerHeight-swTop-below-18));
  let sc=Math.min((cssW*dpr)/(x1-x0), (capH*dpr)/(y1-y0), 1.5);
  const W=Math.round((x1-x0)*sc), H=Math.round((y1-y0)*sc);
  cv.width=W; cv.height=H;
  cv.style.width=(W/dpr)+'px'; cv.style.height=(H/dpr)+'px';
  const g=cv.getContext('2d');
  g.drawImage(IMG,x0,y0,x1-x0,y1-y0,0,0,W,H);
  MAP={x0,y0,sc,k,bb,bw,bh};
  const lw=Math.max(3,3*dpr);
  // the model's pick: solid red normally, dashed once the human overrode it
  g.lineWidth=lw; g.strokeStyle='#e0443f';
  if(CLICK)g.setLineDash([8*dpr,6*dpr]);
  g.strokeRect((bb[0]-x0)*sc,(bb[1]-y0)*sc,bw*sc,bh*sc);
  g.setLineDash([]);
  if(CLICK){
    const cx=(CLICK[0]*k-x0)*sc, w=bw*sc;
    const bx=cx-w/2, by=(bb[1]-y0)*sc, hh=bh*sc;
    g.fillStyle='rgba(29,158,117,.16)'; g.fillRect(bx,by,w,hh);
    g.lineWidth=lw; g.strokeStyle='#1d9e75'; g.strokeRect(bx,by,w,hh);
  }
}
// Zoom deliberately does NOT live on the strip itself - every press there
// already means "correct the book's position". A link (or Z) opens a STATIC
// fullscreen render at up to 3x, with the current rings drawn on it; close
// with a click or Escape, then adjust. No gesture ever collides.
function zoomStrip(){
  const c=D[i];
  if(!IMG.naturalWidth||!MAP||!c.bbox)return;
  const k=MAP.k, bb=MAP.bb, bw=MAP.bw, bh=MAP.bh;
  const ebb=CLICK?[CLICK[0]*k-bw/2,bb[1],CLICK[0]*k+bw/2,bb[3]]:bb;
  const padx=(WIDE?8:3.2)*bw, pady=0.10*bh;
  const x0=Math.max(0,Math.min(bb[0],ebb[0])-padx);
  const x1=Math.min(IMG.naturalWidth,Math.max(bb[2],ebb[2])+padx);
  const y0=Math.max(0,bb[1]-pady), y1=Math.min(IMG.naturalHeight,bb[3]+pady);
  const dpr=window.devicePixelRatio||1;
  const sc=Math.min((0.97*innerWidth*dpr)/(x1-x0),
                    (0.95*innerHeight*dpr)/(y1-y0),3);
  const W=Math.round((x1-x0)*sc), H=Math.round((y1-y0)*sc);
  const cv=document.createElement('canvas'); cv.width=W; cv.height=H;
  const g=cv.getContext('2d');
  g.drawImage(IMG,x0,y0,x1-x0,y1-y0,0,0,W,H);
  const lw=Math.max(3,3*dpr);
  g.lineWidth=lw; g.strokeStyle='#e0443f';
  if(CLICK)g.setLineDash([8*dpr,6*dpr]);
  g.strokeRect((bb[0]-x0)*sc,(bb[1]-y0)*sc,(bb[2]-bb[0])*sc,(bb[3]-bb[1])*sc);
  g.setLineDash([]);
  if(CLICK){
    const cx=(CLICK[0]*k-x0)*sc, w=bw*sc, bx=cx-w/2;
    const by=(bb[1]-y0)*sc, hh=bh*sc;
    g.fillStyle='rgba(29,158,117,.16)'; g.fillRect(bx,by,w,hh);
    g.strokeStyle='#1d9e75'; g.strokeRect(bx,by,w,hh);
  }
  zoom(cv.toDataURL('image/jpeg',0.92));
}
// Two gestures, matched to the two real cases:
//   drag  - "the frame is ALMOST right, nudge it" - by far the more common one.
//           Grab anywhere inside the frame and slide; the frame follows.
//   click - "the frame is on the WRONG book" - click the right one, the frame
//           jumps there. Click the model's own book to undo a correction.
// A drag under 4px counts as a click, so nobody has to aim perfectly still.
let DRAG=null;
function stripToOrig(e){
  const r=e.target.getBoundingClientRect(), f=e.target.width/r.width;
  return [((e.clientX-r.left)*f/MAP.sc+MAP.x0)/MAP.k,
          ((e.clientY-r.top)*f/MAP.sc+MAP.y0)/MAP.k];
}
addEventListener('pointerdown',function(e){
  if(e.target.id!=='strip'||!MAP)return;
  const ox=stripToOrig(e)[0];
  const ob=D[i].bbox, cx=CLICK?CLICK[0]:(ob[0]+ob[2])/2;
  const inside=Math.abs(ox-cx)<=((ob[2]-ob[0])/2)*1.2;
  DRAG={sx:e.clientX,c0:cx,inside:inside,moved:false,
        f:e.target.width/e.target.getBoundingClientRect().width};
  if(inside)try{e.target.setPointerCapture(e.pointerId)}catch(x){}
});
addEventListener('pointermove',function(e){
  if(!DRAG||!DRAG.inside||!MAP)return;
  const dx=e.clientX-DRAG.sx;
  if(Math.abs(dx)>4)DRAG.moved=true;
  if(!DRAG.moved)return;
  const ob=D[i].bbox;
  CLICK=[Math.round(DRAG.c0+dx*DRAG.f/MAP.sc/MAP.k),
         Math.round((ob[1]+ob[3])/2)];
  drawStrip(); paint();
});
addEventListener('pointerup',function(e){
  if(!DRAG)return;
  const d=DRAG; DRAG=null;
  if(!MAP)return;
  const ob=D[i].bbox;
  if(d.moved){
    // a nudge that ends back on the model's centre means "never mind"
    if(CLICK&&Math.abs(CLICK[0]-(ob[0]+ob[2])/2)<(ob[2]-ob[0])*0.05)CLICK=null;
    drawStrip(); paint(); return;
  }
  if(e.target.id!=='strip')return;
  const p=stripToOrig(e);
  if(p[0]>=ob[0]&&p[0]<=ob[2])CLICK=null;
  else CLICK=[Math.round(p[0]),Math.round(p[1])];
  drawStrip(); paint();
});

/* ---- photo counting ------------------------------------------------------
   One question per photo: this frame produced N records - count the spines.
   No per-book boxes (human testing showed they confuse more than they help);
   just ONE lit band around the exact region the records came from, a big
   number, and a stepper. Matching count -> Enter. Different -> type what you
   counted. Whose shelf a discrepancy belongs to is reconciled at home.  */
function statS(){
  $('#cnt').textContent='נותרו '+Math.max(0,T.length-ti)+' תמונות';
  $('#pb').style.width=(T&&T.length?100*ti/T.length:0)+'%';
}
function renderShelf(){
  statS(); SHMAP=null;
  if(!T||ti>=T.length){
    $('#app').innerHTML='<div id="done">נספרו כל התמונות בתחנה הזאת. תודה רבה!'+
      '<br><br><button style="height:46px;border-color:#1d9e75;color:#0f6e56" '+
      'onclick="sendHome()">שלח את התוצאות הביתה</button></div>';
    return}
  const t=T[ti];
  const sh=t.shelves.length?' · מדף '+t.shelves.map(esc).join(', '):'';
  $('#app').innerHTML='<div class="card">'+
    '<p class="h">תמונה '+(ti+1)+sh+'</p>'+
    '<p class="t">זוהו '+t.count+' ספרים בתמונה הזאת</p>'+
    '<div id="ask">ספור את הספרים שבמדף שבמרכז התמונה - האם יוצא אותו מספר?</div>'+
    '<div id="shwrap"><canvas id="shcv" title="לחיצה מגדילה"></canvas></div>'+
    '<div class="hint">לחיצה על התמונה מגדילה למסך מלא · מדף חתוך בקצה העליון '+
    'או התחתון אינו נספר - הוא שייך לתמונה אחרת</div>'+
    '<div class="st" style="display:flex;gap:8px;justify-content:center;align-items:center;margin-top:16px">'+
      '<button style="width:48px;height:48px;font-size:22px" onclick="bump(1)">+</button>'+
      '<input id="hc" type="number" min="0" style="width:96px;height:48px;text-align:center;'+
      'font-size:21px;border:1px solid var(--line);border-radius:9px;background:#fff;color:var(--ink)" '+
      'value="'+t.count+'" oninput="paintS()">'+
      '<button style="width:48px;height:48px;font-size:22px" onclick="bump(-1)">−</button>'+
    '</div>'+
    '<div class="btns">'+
      '<button id="ok" onclick="saveCount()"></button>'+
      '<button id="sk" onclick="sendShelf({verdict:\'skip\'})">דלג <kbd>S</kbd></button>'+
    '</div>'+
    '</div>';
  paintS();
  loadShelf();
}
function paintS(){
  const t=T[ti], ok=$('#ok'), ask=$('#ask');
  if(!ok||!t)return;
  const v=parseInt($('#hc').value,10);
  if(!isNaN(v)&&v!==t.count){
    ask.innerHTML='ספרת <b>'+v+'</b> במקום '+t.count+' - ההפרש יירשם לבדיקה';
    ok.innerHTML='שמור - ספרתי '+v+' <kbd>Enter</kbd>';
    ok.style.background='#fdf0e5'; ok.style.borderColor='#d85a30'; ok.style.color='#a34423';
  }else{
    ask.textContent='ספור את הספרים שבמדף שבמרכז התמונה - האם יוצא אותו מספר?';
    ok.innerHTML='המספר נכון - '+t.count+' ספרים <kbd>Enter</kbd>';
    ok.style.background=''; ok.style.borderColor=''; ok.style.color='';
  }
}
function shSrc(t){return (t.route==='retake'?'/retake/':'/photo/')+t.pid}
function loadShelf(){
  const t=T[ti];
  if(!t)return;
  const src=shSrc(t), im=SHIMG[src];
  if(im&&im.complete&&im.naturalWidth){drawShelf();return}
  const img=new Image();
  img.onload=function(){SHIMG[src]=img;drawShelf()};
  // a missing file must not leave a silent blank canvas under live buttons -
  // the reviewer would type a count against nothing
  img.onerror=function(){
    const a=$('#ask');
    if(a)a.textContent='התמונה לא נמצאה בתחנה הזאת - לחץ "דלג"';
  };
  img.src=src;
}
function drawShelf(){
  // the WHOLE photo, as shot. One photo = one shelf (owner's ruling), so
  // there is nothing to crop, ring or dim - the person just counts.
  const t=T[ti], cv=$('#shcv');
  if(!t||!cv)return;
  const im=SHIMG[shSrc(t)];
  if(!im||!im.naturalWidth)return;
  const dpr=Math.min(2,window.devicePixelRatio||1);
  const cssW=Math.max(300,$('#shwrap').clientWidth||820);
  const capH=Math.max(420,Math.round(window.innerHeight*0.62))*dpr;
  const sc=Math.min(capH/im.naturalHeight,(cssW*dpr)/im.naturalWidth,1);
  const W=Math.round(im.naturalWidth*sc), H=Math.round(im.naturalHeight*sc);
  cv.width=W; cv.height=H;
  cv.style.width=(W/dpr)+'px'; cv.style.height=(H/dpr)+'px';
  cv.getContext('2d').drawImage(im,0,0,W,H);
  SHMAP={sc};
}
addEventListener('click',function(e){
  // fullscreen shows the ORIGINAL file, not the canvas - counting wants
  // every pixel the camera captured, not a downscaled copy
  if(e.target.id==='shcv')zoom(shSrc(T[ti]));
});
function bump(d){
  const el=$('#hc'), v=parseInt(el.value,10);
  el.value=Math.max(0,(isNaN(v)?T[ti].count:v)+d);
  paintS();
}
function saveCount(){
  const t=T[ti], v=parseInt($('#hc').value,10);
  if(isNaN(v)||v<0){alert('הזן מספר');return}
  sendShelf(v===t.count?{verdict:'ok'}:{verdict:'wrong',human_count:v});
}
let SENDBUSY=false;
async function sendShelf(extra){
  // a double Enter must not journal the same shelf twice
  if(SENDBUSY)return;
  SENDBUSY=true;
  try{
    const t=T[ti];
    const body=Object.assign({action:'shelf_count',shelf_key:t.key,
                              model_count:t.count},extra);
    const r=await fetch('/api/decide',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const j=await r.json();
    if(!j.ok){alert(j.error||'שגיאה');return}
    ti++; renderShelf();
  }finally{SENDBUSY=false}
}

/* ---- answers ------------------------------------------------------------ */
function pick(n){SEL=(SEL===n?null:n);
  document.querySelectorAll('.cand').forEach((e,m)=>e.className='cand'+(SEL===m?' on':''));
  paint();}
function openFix(){$('#fix').style.display='block';$('#ft').focus();}
function closeFix(){$('#fix').style.display='none';SEL=null;
  document.querySelectorAll('.cand').forEach(e=>e.className='cand');}
function saveFix(){
  const t=($('#ft').value||'').trim();
  if(t)send({action:'freetext',text:t});
  else alert('הקלד את הכותרת, או בטל ובחר הצעה מהרשימה');
}
function confirmBook(){
  const c=D[i];
  // a selected external candidate wins: it carries author+publisher, which the
  // spine reading never has
  if(SEL!==null){send({action:'candidate',candidate_id:c.candidates[SEL].cid});return}
  if(!c.title){openFix();return}
  send({action:'freetext',text:c.title});
}
function dupq(a){send({action:a,group_id:D[i].group.group_id});}
async function send(extra){
  if(SENDBUSY)return;
  SENDBUSY=true;
  try{
  const body=Object.assign({id:D[i].id},extra);
  delete body._bad;
  if(extra.action!=='skip'){
    if(extra.action==='recrop'||extra._bad){body.crop_ok=false;}
    else{body.crop_ok=CLICK?false:true;}
    if(CLICK)body.corrected_point=CLICK;
    const nvc=$('#nvc');
    if(nvc&&nvc.checked)body.needs_verification=true;
  }
  const r=await fetch('/api/decide',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json();
  if(!j.ok){alert(j.error||'שגיאה');return}
  i++;render();
  }finally{SENDBUSY=false}
}
addEventListener('keydown',function(e){
  if($('#ov').style.display==='flex'){
    if(e.key==='Escape')$('#ov').style.display='none';
    return}
  if(MODE==='shelves'){
    if(!T||ti>=T.length)return;
    if(e.target.tagName==='INPUT'){
      if(e.key==='Enter')saveCount();
      return}
    if(e.key==='Enter'){e.preventDefault();saveCount();}
    else if(e.key==='s'||e.key==='S')sendShelf({verdict:'skip'});
    else if(e.key==='+'||e.key==='ArrowUp'){e.preventDefault();bump(1);}
    else if(e.key==='-'||e.key==='ArrowDown'){e.preventDefault();bump(-1);}
    return}
  if(i>=D.length)return;
  const fix=$('#fix')&&$('#fix').style.display==='block';
  if(e.target.tagName==='INPUT'){
    if(e.key==='Enter')saveFix();
    if(e.key==='Escape')closeFix();
    return}
  if(fix){
    if(e.key==='Escape'){closeFix();return}
    if(e.key==='Enter'){saveFix();return}
  }
  if(e.key>='1'&&e.key<='9'){const n=+e.key-1;if(D[i].candidates[n])pick(n);return}
  if(e.key==='Enter'){e.preventDefault();confirmBook();}
  // preventDefault, or the E that OPENS the box gets typed INTO the box
  else if(e.key==='e'||e.key==='E'){e.preventDefault();openFix();}
  else if(e.key==='s'||e.key==='S')send({action:'skip'});
  else if(e.key==='z'||e.key==='Z'){if(MAP)zoomStrip();}
});
addEventListener('resize',function(){
  if(MODE==='shelves'){if(SHMAP)drawShelf();return}
  if(MAP)drawStrip()});
boot();
</script></body></html>"""


class Server(ThreadingHTTPServer):
    # Python turns SO_REUSEADDR on by default. On Windows that does NOT mean
    # "reuse a dead socket" as it does on Unix - it lets a SECOND process bind a
    # port that is already being listened on, and the OS then hands each incoming
    # connection to one of them at random. Two review servers were observed
    # sharing 8765, answering alternate requests from different catalogs. A
    # volunteer double-clicking START.bat would hit exactly this, so refuse the
    # second instance instead of half-running it.
    allow_reuse_address = False


def main():
    if not os.path.exists(CATALOG):
        print("ERROR: no catalog at", CATALOG); sys.exit(1)
    if not os.path.exists(CONFIG):
        print("WARNING: no password set yet - run SET-PASSWORD.bat first.")
    n = len(load_books())
    print("Review station  v" + VERSION)
    print("  catalog   :", CATALOG, "(%d books, read-only)" % n)
    print("  crops     :", CROPS)
    print("  decisions :", DECISIONS_DIR)
    print("  open      :  http://localhost:%d" % PORT)
    print("  stop      :  close this window")
    try:
        srv = Server(("127.0.0.1", PORT), Handler)
    except OSError:
        print()
        print("  The review app is ALREADY RUNNING on port %d." % PORT)
        print("  Switch to the window that is already open, or close it and")
        print("  start again. Two copies would answer each other's requests.")
        try:
            input("  press Enter to close ")
        except (EOFError, KeyboardInterrupt):
            pass        # no console attached (launched non-interactively)
        sys.exit(1)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
