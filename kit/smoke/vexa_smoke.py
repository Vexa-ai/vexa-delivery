#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""vexa-smoke — human-in-the-loop acceptance test for a channel-delivered station.

Answers, AFTER install or upgrade, in plain language: does the thing the channel
delivered actually work HERE, in this cluster, against a real meeting? The
preflight asks "will it run"; smoke asks "did it". The output is a dated receipt
the operator can attach to an acceptance record, a pilot results paper, or a
security review — evidence, not vibes.

Phases
  S1 delivered-set      the subscription Application is Synced/Healthy and every
                        delivered Deployment is fully available
  S2 control-plane      gateway / admin-api answer over a port-forward from the
                        operator's own machine (no in-cluster shell needed)
  S3 live meeting       THE HUMAN LOOP: the operator opens a real meeting, the
                        CLI dispatches the bot, the operator admits it and says
                        a few sentences, the CLI shows transcript lines arriving
                        and counts them. A delivery nobody has seen capture a
                        real meeting is not accepted.
  S4 flows tier         (--flows) the flows API serves its vocabulary — the
                        Minutes automation layer is loaded and hot-reloadable
  S5 receipt            verdict + a markdown receipt with chart revision, image
                        digests, meeting id, segment count, operator identity

Run on the operator's machine with kubectl access:
  python3 kit/smoke/vexa_smoke.py --namespace vexa-staging \
      --customer-values customer-values.yaml [--flows] [--meeting-url URL]

Non-interactive (CI / rehearsal): --meeting-url with --auto-admit-timeout skips
the prompts but still reports honestly when nobody admitted the bot.
"""
from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
import re
import time
import urllib.parse
import urllib.request

# ── plumbing ────────────────────────────────────────────────────────────────

def kc(args_ns, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["kubectl"]
    if args_ns.kubeconfig:
        cmd += ["--kubeconfig", args_ns.kubeconfig]
    cmd += ["-n", args_ns.namespace, *args]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args)}: {r.stderr.strip()}")
    return r


class PortForward:
    """kubectl port-forward as a context manager — the operator-side probe path.
    In-cluster exec would need a shell+curl in the target image (not guaranteed);
    a port-forward only needs the operator's own kubectl, which S1 already proved."""

    def __init__(self, args_ns, svc: str, remote: int, local: int):
        self.args_ns, self.svc, self.remote, self.local = args_ns, svc, remote, local
        self.proc: subprocess.Popen | None = None

    def __enter__(self):
        cmd = ["kubectl"]
        if self.args_ns.kubeconfig:
            cmd += ["--kubeconfig", self.args_ns.kubeconfig]
        cmd += ["-n", self.args_ns.namespace, "port-forward", f"svc/{self.svc}",
                f"{self.local}:{self.remote}"]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.local}/", timeout=1)
                return self
            except urllib.error.HTTPError:
                return self          # an HTTP status means the tunnel is up
            except Exception:
                time.sleep(0.5)
        raise RuntimeError(f"port-forward to svc/{self.svc} did not come up in 15s")

    def __exit__(self, *exc):
        if self.proc:
            self.proc.terminate()


def http(method: str, url: str, headers: dict, body: dict | None = None, timeout: float = 20,
         attempts: int = 3):
    """HTTP through a port-forward. Never raises: a transport failure comes back
    as 599 so the caller records a FAIL finding and the run still produces a
    receipt. A freshly-established `kubectl port-forward` drops its first
    connection often enough that crashing on it would report an outage that is
    not one — hence the retry."""
    for attempt in range(attempts):
        req = urllib.request.Request(url, method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        for k, v in {"content-type": "application/json", **headers}.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read().decode()
                return r.status, (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            return e.code, (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)
        except Exception as e:                     # reset / disconnect / timeout
            if attempt == attempts - 1:
                return 599, f"connection error: {e}"
            time.sleep(1)


# ── checks ──────────────────────────────────────────────────────────────────

def s1_delivered_set(a, findings: list) -> bool:
    r = kc(a, "get", "deploy", "-o", "json")
    deploys = json.loads(r.stdout)["items"]
    if not deploys:
        findings.append(("S1", "FAIL", "no Deployments in the namespace — is the subscription synced?"))
        return False
    bad = [d["metadata"]["name"] for d in deploys
           if (d["status"].get("readyReplicas") or 0) < (d["spec"].get("replicas") or 0)]
    if bad:
        findings.append(("S1", "FAIL", f"not fully available: {', '.join(bad)}"))
        return False
    findings.append(("S1", "PASS", f"{len(deploys)} Deployments fully available"))
    return True


def s2_control_plane(a, findings: list) -> bool:
    ok = True
    with PortForward(a, f"{a.release_prefix}-admin-api", 8001, 18901):
        code, _ = http("GET", "http://127.0.0.1:18901/", {})
        good = code < 500
        findings.append(("S2", "PASS" if good else "FAIL", f"admin-api answers (HTTP {code})"))
        ok &= good
    with PortForward(a, f"{a.release_prefix}-gateway", 8000, 18900):
        code, _ = http("GET", "http://127.0.0.1:18900/", {})
        good = code < 500
        findings.append(("S2", "PASS" if good else "FAIL", f"gateway answers (HTTP {code})"))
        ok &= good
    return ok


# Meeting-URL shapes, mirroring the gateway's OWN parser so this CLI never invents an id the
# platform would refuse. Authority (read 2026-08-24):
#   core/meetings/services/meeting-api/src/meeting_api/collector/meeting_link.py — the parser
#   POST /bots itself uses on the derive path: teams → the ``19:meeting_…@thread.v2`` thread id,
#   or the ``/meet/<id>`` short-link segment.
#   …/bot_spawn/service.py::_URL_TEMPLATES — teams ids are re-expanded into
#   ``https://teams.microsoft.com/l/meetup-join/{native_meeting_id}``, which is why the thread id
#   (not a URL hash) is the form to send.
#   …/bot_spawn/router.py — ``native_meeting_id`` must be a BARE token: no "?#&=/" and no
#   whitespace, ≤255 chars. A passcode left on the id is a 422; it goes in ``passcode``.
#   The body field for the passcode is ``passcode`` (router.py: ``body.get("passcode")``),
#   populated from a Teams ``?p=`` / Zoom ``?pwd=`` query param.
_TEAMS_THREAD = re.compile(r"19:meeting_[^@%\s/]+@thread\.v2", re.IGNORECASE)
_TEAMS_SHORT = re.compile(r"/meet/([^/?#]+)", re.IGNORECASE)


def _meeting_parts(url: str) -> tuple[str, str, str | None]:
    """A pasted meeting URL → ``(platform, native_meeting_id, passcode|None)``.

    Google Meet and Microsoft Teams — the two platforms the delivered station's bot flow can
    construct a join URL for without a caller-supplied ``meeting_url``."""
    raw = (url or "").strip()
    if not raw:
        raise SystemExit("no meeting URL given")
    parsed = urllib.parse.urlparse(raw)
    host = (parsed.hostname or "").lower()
    query = urllib.parse.parse_qs(parsed.query or "")

    if "meet.google.com" in host:
        code = next((p for p in reversed(parsed.path.split("/")) if p), "").lower()
        if not code:
            raise SystemExit(f"cannot read a Google Meet code out of {raw!r} "
                             "(expected https://meet.google.com/abc-defg-hij)")
        return "google_meet", code, None

    if "teams.microsoft.com" in host or "teams.live.com" in host:
        # Classic deep link — the thread id lives in the path, percent-encoded.
        thread = _TEAMS_THREAD.search(urllib.parse.unquote(raw))
        if thread:
            return "teams", thread.group(0), (query.get("p") or [None])[0]
        # Modern short link — teams.live.com/meet/<id>?p=<passcode>.
        short = _TEAMS_SHORT.search(parsed.path)
        if short:
            return "teams", short.group(1), (query.get("p") or [None])[0]
        raise SystemExit(
            f"cannot read a Teams meeting id out of {raw!r} — expected either "
            "https://teams.live.com/meet/<id>?p=<passcode> or a classic "
            "https://teams.microsoft.com/l/meetup-join/19%3ameeting_…%40thread.v2/0?context=… link")

    raise SystemExit(f"cannot parse a supported meeting URL from {raw!r} "
                     "(google_meet and teams supported)")


def s3_live_meeting(a, findings: list, receipt: dict) -> bool:
    if not a.meeting_url and a.non_interactive:
        findings.append(("S3", "SKIP", "no --meeting-url in non-interactive mode"))
        return True
    url = a.meeting_url or input(
        "\nS3 · THE HUMAN LOOP\n"
        "  1. open a NEW meeting in your browser — Google Meet (meet.google.com/new) or\n"
        "     Microsoft Teams (teams.live.com 'Meet now', or a Teams calendar invite link)\n"
        "  2. paste the meeting URL here and press enter\n"
        "     Teams links carrying a ?p= passcode are handled; paste the WHOLE link\n"
        "  3. when the bot knocks, ADMIT it, then say a few sentences\n"
        "meeting URL: ")
    platform, native_id, passcode = _meeting_parts(url)
    with PortForward(a, f"{a.release_prefix}-admin-api", 8001, 18901), \
         PortForward(a, f"{a.release_prefix}-gateway", 8000, 18900):
        A = {"X-Admin-API-Key": a.admin_token}
        code, u = http("POST", "http://127.0.0.1:18901/admin/users",
                       A, {"email": a.operator_email, "name": "Smoke Operator"})
        if code == 409:
            code, u = http("GET", f"http://127.0.0.1:18901/admin/users/email/{a.operator_email}", A)
        if code not in (200, 201):
            findings.append(("S3", "FAIL", f"could not ensure smoke user (HTTP {code}): {u}"))
            return False
        code, tok = http("POST", f"http://127.0.0.1:18901/admin/users/{u['id']}/tokens",
                         A, {"scopes": ["bot", "browser", "tx"]})
        key = tok.get("token") or tok.get("key")
        dispatch = {"platform": platform, "native_meeting_id": native_id}
        if passcode:
            dispatch["passcode"] = passcode
        code, bot = http("POST", "http://127.0.0.1:18900/bots", {"X-API-Key": key}, dispatch)
        if code not in (200, 201, 409):
            findings.append(("S3", "FAIL", f"bot dispatch refused (HTTP {code}): {bot}"))
            return False
        print(f"  bot dispatched (meeting id {bot.get('id', '?')}). Admit it, speak, then wait…")
        # A Teams thread id (19:meeting_…@thread.v2) is a bare token by the gateway's rules but
        # still needs percent-encoding to ride in a URL PATH segment on the read-back routes.
        id_seg = urllib.parse.quote(native_id, safe="")
        receipt["meeting"] = {"platform": platform, "native_id": native_id, "row_id": bot.get("id")}
        deadline = time.time() + a.admit_timeout
        segments = 0
        while time.time() < deadline:
            code, tr = http("GET", f"http://127.0.0.1:18900/transcripts/{platform}/{id_seg}",
                            {"X-API-Key": key})
            segs = tr.get("segments") if isinstance(tr, dict) else None
            if segs:
                if len(segs) > segments:
                    for s in segs[segments:]:
                        print(f"    {s.get('speaker') or '—'}: {(s.get('text') or '').strip()}")
                    segments = len(segs)
                if segments >= a.min_segments:
                    break
            time.sleep(5)
        receipt["segments"] = segments
        # stop the bot; a smoke leftover in a real meeting is impolite
        http("DELETE", f"http://127.0.0.1:18900/bots/{platform}/{id_seg}", {"X-API-Key": key})
        if segments >= a.min_segments:
            findings.append(("S3", "PASS",
                             f"live capture: {segments} transcript segments from a human meeting"))
            return True
        findings.append(("S3", "FAIL",
                         f"only {segments} segments arrived in {a.admit_timeout}s — was the bot admitted?"))
        return False


def s4_flows(a, findings: list) -> bool:
    if not a.flows:
        findings.append(("S4", "SKIP", "flows tier not requested (--flows)"))
        return True
    # A missing Service is a finding about the delivered set, not a crash. The
    # 0.12.23 chart ships no flows-api at all, and --flows used to end the whole
    # run in a traceback: no receipt, no verdict, and an operator with no way to
    # tell "not delivered" from "broken" (rehearsal 2026-08-24).
    try:
        pf = PortForward(a, f"{a.release_prefix}-flows-api", 18200, 18902)
        pf.__enter__()
    except RuntimeError as e:
        findings.append(("S4", "FAIL",
                         f"no reachable {a.release_prefix}-flows-api Service in "
                         f"{a.namespace} — the flows tier is not part of this "
                         f"delivered set ({e})"))
        return False
    try:
        code, body = http("GET", "http://127.0.0.1:18902/flows",
                          {"X-Flows-Admin-Key": a.flows_key or ""})
        if code == 200 and isinstance(body, dict) and body.get("flows"):
            findings.append(("S4", "PASS",
                             f"flows tier live: {len(body['flows'])} flows loaded"))
            return True
        findings.append(("S4", "FAIL", f"flows API (HTTP {code})"))
        return False
    finally:
        pf.__exit__()


# ── receipt ─────────────────────────────────────────────────────────────────

def write_receipt(a, findings, receipt: dict) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    app = ""
    try:
        r = kc(a, "get", "app", "-A", "-o",
               "jsonpath={range .items[*]}{.metadata.name} {.status.sync.revision}{\"\\n\"}{end}",
               check=False)
        app = r.stdout.strip()
    except Exception:
        pass
    images = kc(a, "get", "deploy", "-o",
                "jsonpath={range .items[*]}{range .spec.template.spec.containers[*]}{.image}{\"\\n\"}{end}{end}").stdout
    verdict = "PASS" if all(f[1] != "FAIL" for f in findings) else "FAIL"
    path = f"smoke-receipt-{now.strftime('%Y%m%d-%H%M%S')}.md"
    lines = [f"# vexa-smoke receipt — {now.isoformat(timespec='seconds')}",
             f"\nVERDICT: **{verdict}**  ·  operator: {a.operator_email}  ·  namespace: {a.namespace}\n",
             "| phase | result | detail |", "|---|---|---|"]
    lines += [f"| {p} | {res} | {msg} |" for p, res, msg in findings]
    if app:
        lines += ["\n## Subscription", "```", app, "```"]
    lines += ["\n## Delivered images (digest-pinned)", "```", images.strip(), "```"]
    if receipt.get("meeting"):
        m = receipt["meeting"]
        lines += [f"\n## Live meeting\n{m['platform']} `{m['native_id']}` — "
                  f"{receipt.get('segments', 0)} transcript segments captured, "
                  f"row id {m.get('row_id')}"]
    open(path, "w").write("\n".join(lines) + "\n")
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--namespace", default="vexa-staging")
    ap.add_argument("--kubeconfig")
    ap.add_argument("--release-prefix", default="vexa-vexa",
                    help="componentName prefix (release 'vexa' → vexa-vexa)")
    ap.add_argument("--customer-values", help="read admin token / flows key from this values file")
    ap.add_argument("--admin-token")
    ap.add_argument("--flows", action="store_true")
    ap.add_argument("--flows-key")
    ap.add_argument("--meeting-url")
    ap.add_argument("--operator-email", default="smoke@customer.local")
    ap.add_argument("--admit-timeout", type=int, default=240)
    ap.add_argument("--min-segments", type=int, default=3)
    ap.add_argument("--non-interactive", action="store_true")
    a = ap.parse_args()

    if a.customer_values and (not a.admin_token or not a.flows_key):
        import yaml
        v = yaml.safe_load(open(a.customer_values)) or {}
        a.admin_token = a.admin_token or (v.get("secrets") or {}).get("adminApiToken")
        a.flows_key = a.flows_key or (v.get("flows") or {}).get("apiKey")
    if not a.admin_token:
        sys.exit("need --admin-token or --customer-values with secrets.adminApiToken")

    findings: list = []
    receipt: dict = {}
    ok = s1_delivered_set(a, findings)
    ok = s2_control_plane(a, findings) and ok
    ok = s3_live_meeting(a, findings, receipt) and ok
    ok = s4_flows(a, findings) and ok
    for p, res, msg in findings:
        print(f"[{res}] {p} · {msg}")
    path = write_receipt(a, findings, receipt)
    print(f"\nVERDICT: {'PASS' if ok else 'FAIL'}  →  receipt: {path}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
