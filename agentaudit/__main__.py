"""Command-line interface.

    python -m agentaudit list
    python -m agentaudit run --backend scripted --seeds 3 --out results/sim
    python -m agentaudit run --backend openai --seeds 5 --out results/gpt   (needs AAB_* env vars)
    python -m agentaudit report results/sim/runs.csv
    python -m agentaudit aibom --out aibom.json
    python -m agentaudit verify-log results/sim/logs/A01__all__seed0.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys

from .aibom import build_aibom
from .defences import AuditLog
from .llm import OpenAICompatibleLLM
from .pipeline import PRESETS
from .report import build_report, load
from .runner import RunOptions, run_matrix
from .scenarios import ALL_SCENARIOS


def _split(v: str, universe: list[str]) -> list[str]:
    if v == "all":
        return universe
    items = [x.strip() for x in v.split(",") if x.strip()]
    bad = [x for x in items if x not in universe]
    if bad:
        sys.exit(f"Unknown: {bad}. Choose from {universe}")
    return items


def cmd_list(_):
    print("Scenarios:")
    for s in ALL_SCENARIOS.values():
        extra = f"  CERT-In: {', '.join(s.cert_in)} | OWASP: {', '.join(s.owasp)}" if s.kind == "attack" else ""
        print(f"  {s.id} [{s.kind}] {s.title}{extra}")
    print("\nDefence configurations:")
    for name, c in PRESETS.items():
        print(f"  {name:14s} {'+'.join(c.layers()) or 'no controls'}")


def cmd_run(a):
    opt = RunOptions(backend=a.backend, judge=a.judge, approver_miss_rate=a.miss_rate,
                     follow_spotlighted=a.follow_spotlighted, max_steps=a.max_steps,
                     log_dir=(f"{a.out}/logs" if a.save_logs else None))
    if a.backend == "openai":
        opt.llm_factory = lambda: OpenAICompatibleLLM.from_env("AAB")
        opt.llm_factory()  # fail fast if env vars are missing
    if a.judge == "llm":
        opt.judge_factory = lambda: OpenAICompatibleLLM.from_env("AAB_JUDGE")
        opt.judge_factory()
    rows = run_matrix(_split(a.scenarios, list(ALL_SCENARIOS)), _split(a.configs, list(PRESETS)),
                      a.seeds, opt, a.out)
    report = build_report([{k: str(v) for k, v in r.items()} for r in rows])
    with open(f"{a.out}/report.md", "w") as f:
        f.write(report)
    print(f"\nWrote {a.out}/runs.csv, runs.jsonl and report.md")


def cmd_report(a):
    md = build_report(load(a.runs))
    if a.out:
        with open(a.out, "w") as f:
            f.write(md)
        print(f"Wrote {a.out}")
    else:
        print(md)


def cmd_aibom(a):
    if a.backend == "openai":
        llm = OpenAICompatibleLLM.from_env("AAB")
        name, provider = llm.name, llm.provider
    else:
        name, provider = "scripted-compromisable-v1", "local-simulator"
    bom = build_aibom(name, provider, PRESETS[a.config], a.judge_model)
    with open(a.out, "w") as f:
        json.dump(bom, f, indent=2)
    print(f"Wrote {a.out} ({len(bom['components'])} components)")


def cmd_verify(a):
    log = AuditLog()
    with open(a.path) as f:
        log.entries = [json.loads(line) for line in f if line.strip()]
    ok, idx = log.verify()
    print("Chain intact." if ok else f"Chain BROKEN at entry {idx}.")
    sys.exit(0 if ok else 1)


def main(argv=None):
    p = argparse.ArgumentParser(prog="agentaudit", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(fn=cmd_list)

    r = sub.add_parser("run", help="run the experiment matrix")
    r.add_argument("--backend", choices=["scripted", "openai"], default="scripted")
    r.add_argument("--scenarios", default="all", help="comma list or 'all'")
    r.add_argument("--configs", default="all", help="comma list of presets or 'all'")
    r.add_argument("--seeds", type=int, default=3)
    r.add_argument("--judge", choices=["rule", "llm"], default="rule")
    r.add_argument("--miss-rate", type=float, default=0.0, help="simulated reviewer rubber-stamp probability")
    r.add_argument("--follow-spotlighted", type=float, default=1.0,
                   help="simulator only: chance a compromised model still follows delimited payloads")
    r.add_argument("--max-steps", type=int, default=14)
    r.add_argument("--save-logs", action="store_true")
    r.add_argument("--out", required=True)
    r.set_defaults(fn=cmd_run)

    rp = sub.add_parser("report", help="rebuild report.md from runs.csv")
    rp.add_argument("runs")
    rp.add_argument("--out")
    rp.set_defaults(fn=cmd_report)

    b = sub.add_parser("aibom", help="write an AI bill of materials")
    b.add_argument("--backend", choices=["scripted", "openai"], default="scripted")
    b.add_argument("--config", default="all", choices=list(PRESETS))
    b.add_argument("--judge-model", default="")
    b.add_argument("--out", default="aibom.json")
    b.set_defaults(fn=cmd_aibom)

    v = sub.add_parser("verify-log", help="verify an audit log's hash chain")
    v.add_argument("path")
    v.set_defaults(fn=cmd_verify)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
