# engine/engine.py
"""Orchestrator for bughunter-lite.

Wires the deterministic core (scope, state, recon, skill_map) to the single LLM
seam (agent). The DEFAULT run is read-only recon -> rank -> map (writes an
arsenal and stops). --hunt adds the operator-in-the-loop phases: hunt ->
validate -> report, each governed by rules of engagement that are ALSO enforced
in code (scope gate, read-only methods, never exercise credentials). Mock mode
runs the whole flow offline with no network and no LLM calls.

A live methodology checklist (checklist.md) is regenerated as each class is
hunted, so the operator can watch which skill ran and its result in real time.
"""

import argparse
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scope as scope_mod      # noqa: E402
import state as state_mod      # noqa: E402
import recon as recon_mod      # noqa: E402
import skill_map               # noqa: E402
import agent                   # noqa: E402

ALL_PHASES = ["recon", "rank", "map", "hunt", "validate", "report"]
DEFAULT_PHASES = ["recon", "rank", "map"]

_URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+")
_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


class Engine:
    """Drives an engagement through its phases against one scope."""

    def __init__(self, scope_path, base, max_hunts, mock, allow_intrusive, model):
        self.scope = scope_mod.Scope.load(scope_path)
        self.eng = state_mod.Engagement(base, self.scope.name or "engagement")
        self.max_hunts = max_hunts
        self.mock = mock
        self.allow_intrusive = allow_intrusive
        self.model = model
        self.candidates = []
        self._current_class = None
        self.log = self.eng.log

    # --- phases --------------------------------------------------------

    def recon(self):
        """Collect the surface (mock demo, or the recon adapter)."""
        self.eng.set_phase("recon")
        if self.mock:
            seed = self.scope.seeds[0] if self.scope.seeds else ""
            targets = [{
                "seed": seed,
                "host": scope_mod._host_of(seed),
                "status": 200,
                "tech": ["nextjs"],
                "js_files": [],
                "inline_js_blocks": 0,
                "endpoints": ["/api/v1/users/42", "/graphql", "/download"],
                "params": ["redirect_url", "order_id", "file"],
                "secrets": [{"type": "aws_access_key", "value": "[REDACTED - verify]"}],
                "high_entropy": 0,
                "out_dir": self.eng.dir,
            }]
        else:
            targets = recon_mod.recon(self.scope, log=self.log)
        self.eng.state["targets"] = targets
        self.eng.save()
        self.log("recon: %d target(s)" % len(targets))

    def rank(self):
        """Classify the surface into ranked hunt candidates."""
        self.eng.set_phase("rank")
        self.candidates = skill_map.classify(self.eng.state.get("targets", []), self.scope)
        self.eng.state["candidates"] = self.candidates
        self.eng.save()
        self.log("rank: %d candidate(s)" % len(self.candidates))
        for c in self.candidates[:12]:
            self.log("  [%3d] %-14s %s  %s" % (
                c["weight"], c["class"], c["where"], ", ".join(c["skills"])))

    def map(self):
        """Write the arsenal; the default (read-only) run ends here."""
        self.eng.set_phase("map")
        skill_map.write_arsenal(self.candidates, self.eng.arsenal_path)
        self.log("map: arsenal -> %s" % self.eng.arsenal_path)
        self.log("DEFAULT run ends here. Pass --hunt to attempt operator-in-the-loop validation.")
        self._write_checklist()

    def hunt(self):
        """Attempt to confirm each candidate via the LLM seam (or a mock)."""
        self.eng.set_phase("hunt")
        roe = self._roe()
        findings = []
        batch = self.candidates[:self.max_hunts]
        for i, c in enumerate(batch, 1):
            task = self._task(roe, c)

            # Mark this class in-progress BEFORE the dispatch.
            self._current_class = c["class"]
            self._write_checklist()

            if self.mock:
                finding = {
                    "class": c["class"], "host": c["host"], "confirmed": False,
                    "severity": "info", "request": c["curl"],
                    "evidence": "mock run - no requests sent",
                    "proof_note": "mock mode",
                }
                result_text = json.dumps(finding)
            else:
                out = agent.run_agent(task, model=self.model)
                result_text = out.get("result") or ""
                finding = agent.extract_json(result_text) or {
                    "class": c["class"], "host": c["host"], "confirmed": False,
                    "severity": "info", "request": c["curl"],
                    "evidence": "no structured output",
                    "proof_note": out.get("error") or "parse failed",
                }

            content = result_text or json.dumps(finding, indent=2)
            ev = self.eng.evidence_file("hunt_%02d_%s.json" % (i, c["class"]), content or "{}")
            finding["_evidence_file"] = ev
            finding["_scope_violations"] = self._scope_audit(finding)

            findings.append(finding)
            self.eng.state["findings"] = findings
            self.eng.save()

            # Mark this class done (with its result) AFTER saving, then clear.
            self._write_checklist()
            self._current_class = None

            self.log("hunt %d/%d: %s %s confirmed=%s%s" % (
                i, len(batch), c["class"], c["where"], finding.get("confirmed"),
                " SCOPE-VIOLATION" if finding["_scope_violations"] else ""))

    def validate(self):
        """Keep confirmed findings with no scope violation."""
        self.eng.set_phase("validate")
        validated = [f for f in self.eng.state.get("findings", [])
                     if f.get("confirmed") and not f.get("_scope_violations")]
        self.eng.state["validated"] = validated
        self.eng.save()
        self.log("validate: %d confirmed, in-scope finding(s)" % len(validated))
        self._write_checklist()

    def report(self):
        """Write report.md from the validated findings."""
        self.eng.set_phase("report")
        validated = self.eng.state.get("validated", [])
        lines = [
            "# bughunter-lite report: %s" % self.scope.name,
            "",
            "- engagement dir: %s" % self.eng.dir,
            "- validated findings: %d" % len(validated),
            "",
        ]
        if not validated:
            lines.append("_No confirmed, in-scope findings. Review arsenal.md and evidence/ for leads._")
        for i, f in enumerate(validated, 1):
            lines += [
                "## %d. %s on %s" % (i, f.get("class", "?"), f.get("host", "?")),
                "- severity: %s" % f.get("severity", "?"),
                "- request: `%s`" % f.get("request", ""),
                "",
                "Evidence:",
                "",
                "```",
                str(f.get("evidence", ""))[:2000],
                "```",
                "",
                "> %s" % f.get("proof_note", ""),
                "",
            ]
        with open(self.eng.report_path, "w", encoding="utf-8") as fp:
            fp.write("\n".join(lines) + "\n")
        self.log("report: %s" % self.eng.report_path)

    # --- helpers -------------------------------------------------------

    def _roe(self):
        """Rules of engagement (also enforced in code) handed to the model."""
        in_s = ", ".join(self.scope.in_scope) or "(none)"
        out_s = ", ".join(self.scope.out_of_scope) or "(none)"
        method_rule = ("- Intrusive methods permitted by operator." if self.allow_intrusive
                       else "- READ-ONLY: GET/HEAD/OPTIONS only.")
        return "\n".join([
            "RULES OF ENGAGEMENT (enforced in code; repeated here for the model):",
            "- Authorized engagement '%s'." % self.scope.name,
            "- In-scope hosts ONLY: %s" % in_s,
            "- Out-of-scope (never touch): %s" % out_s,
            method_rule,
            "- NEVER exercise discovered credentials/secrets; note them for manual verification.",
            "- Do not follow redirects off-scope. Stop and report if scope would be exceeded.",
        ])

    def _task(self, roe, c):
        """Build the per-candidate task prompt for the agent."""
        return "\n".join([
            roe,
            "",
            "TARGET CANDIDATE:",
            "- class: %s" % c["class"],
            "- where: %s" % c["where"],
            "- host:  %s" % c["host"],
            "- starter curl: %s" % c["curl"],
            "",
            "Investigate ONLY within the rules above. Report the issue only if you can confirm "
            "it with evidence captured from in-scope requests.",
            'End with a ```json``` block: '
            '{"class","host","confirmed","severity","request","evidence","proof_note"}.',
        ])

    def _scope_audit(self, finding):
        """Grep a finding's PoC for hosts and flag any that are out of scope."""
        blob = " ".join(str(finding.get(k, "")) for k in ("request", "evidence", "proof_note"))
        bad = []
        for url in _URL_RE.findall(blob):
            if not self.scope.in_scope_host(url):
                h = scope_mod._host_of(url)
                if h and h not in bad:
                    bad.append(h)
        return bad

    def _write_checklist(self):
        """Regenerate checklist.md from current state (live methodology view)."""
        state = self.eng.state
        phase = state.get("phase")
        targets = state.get("targets", []) or []
        candidates = state.get("candidates", []) or []
        findings = state.get("findings", []) or []

        confirmed = [f for f in findings if f.get("confirmed")]

        # --- header ---
        lines = [
            "# Methodology — %s" % self.scope.name,
            "",
            "_Updated %s · phase: %s · %d confirmed_" % (
                time.strftime("%H:%M:%S", time.localtime()), phase, len(confirmed)),
            "",
        ]

        # --- recon ---
        ne = sum(len(t.get("endpoints", []) or []) for t in targets)
        np = sum(len(t.get("params", []) or []) for t in targets)
        ns = sum(len(t.get("secrets", []) or []) for t in targets)
        lines.append("## Recon")
        if targets:
            lines.append("- [x] recon + map — %d endpoints, %d params, %d secrets" % (ne, np, ns))
        else:
            lines.append("- [ ] recon + map — pending")
        lines.append("")

        # --- hunt (impact-ranked, one line per unique class) ---
        lines.append("## Hunt (impact-ranked)")
        by_class = {}
        for c in candidates:
            cls = c.get("class")
            w = c.get("weight", 0)
            if cls not in by_class or w > by_class[cls]["weight"]:
                by_class[cls] = {"weight": w, "skills": c.get("skills", [])}
        for cls, info in sorted(by_class.items(), key=lambda kv: -kv[1]["weight"]):
            skills = ", ".join(info["skills"])
            cls_findings = [f for f in findings if f.get("class") == cls]
            cls_confirmed = [f for f in cls_findings if f.get("confirmed")]
            if cls_findings:
                if cls_confirmed:
                    highest = max(cls_confirmed,
                                  key=lambda f: _SEV_RANK.get((f.get("severity") or "info").lower(), 0))
                    sev = (highest.get("severity") or "info").title()
                    lines.append("- [x] hunt-%s (%s) → %d CONFIRMED (%s)" % (
                        cls, skills, len(cls_confirmed), sev))
                else:
                    lines.append("- [x] hunt-%s (%s) → killed" % (cls, skills))
            elif self._current_class == cls:
                lines.append("- [~] hunt-%s (%s) → in progress" % (cls, skills))
            else:
                lines.append("- [ ] hunt-%s (%s) → pending" % (cls, skills))
        lines.append("")

        # --- findings summary ---
        counts = {}
        for f in confirmed:
            s = (f.get("severity") or "info").title()
            counts[s] = counts.get(s, 0) + 1
        breakdown = ", ".join("%d %s" % (counts[s], s) for s in _SEV_ORDER if counts.get(s))
        if confirmed:
            lines.append("## Findings: %d confirmed (%s)" % (len(confirmed), breakdown))
        else:
            lines.append("## Findings: 0 confirmed")

        path = os.path.join(self.eng.dir, "checklist.md")
        with open(path, "w", encoding="utf-8") as fp:
            fp.write("\n".join(lines) + "\n")
        return path

    # --- driver --------------------------------------------------------

    def run(self, phases):
        """Run the named phases in order; return the engagement directory."""
        for name in phases:
            fn = getattr(self, name, None)
            if fn is None or name not in ALL_PHASES:
                self.log("unknown phase: %s" % name)
                continue
            fn()
        return self.eng.dir


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="bughunter-lite orchestrator")
    ap.add_argument("--scope", required=True, help="path to scope JSON")
    ap.add_argument("--base", default="~/.bughunter-engagements", help="engagements base dir")
    ap.add_argument("--hunt", action="store_true", help="run all six phases")
    ap.add_argument("--mock", action="store_true", help="offline demo (no network, no LLM)")
    ap.add_argument("--allow-intrusive", action="store_true", help="permit state-changing methods")
    ap.add_argument("--max-hunts", type=int, default=8, help="max candidates to hunt")
    ap.add_argument("--model", help="LLM model override")
    ap.add_argument("--phases", help="comma-separated phase override")
    args = ap.parse_args()

    engine = Engine(args.scope, args.base, args.max_hunts, args.mock,
                    args.allow_intrusive, args.model)
    if args.phases:
        phases = [p.strip() for p in args.phases.split(",") if p.strip()]
    elif args.hunt:
        phases = list(ALL_PHASES)
    else:
        phases = list(DEFAULT_PHASES)

    out_dir = engine.run(phases)
    print("engagement dir:", out_dir)
