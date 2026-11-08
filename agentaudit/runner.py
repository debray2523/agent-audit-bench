"""Experiment runner: scenarios x defence configurations x seeds."""
from __future__ import annotations

import csv
import json
import os
import random
from dataclasses import dataclass
from typing import Callable, Optional

from .agent import run_session
from .defences import LLMJudge, OracleApprover, RuleJudge, reconstructable
from .env import World
from .llm import ScriptedLLM
from .pipeline import PRESETS, ControlPipeline, DefenceConfig
from .scenarios import ALL_SCENARIOS, Scenario
from .types import RunTrace


@dataclass
class RunOptions:
    backend: str = "scripted"                  # "scripted" | "openai"
    llm_factory: Optional[Callable] = None     # returns a fresh model client per session
    judge: str = "rule"                        # "rule" | "llm"
    judge_factory: Optional[Callable] = None
    approver_miss_rate: float = 0.0
    follow_spotlighted: float = 1.0            # simulator only
    max_steps: int = 14
    log_dir: Optional[str] = None


def run_one(scn: Scenario, cfg: DefenceConfig, seed: int, opt: RunOptions) -> dict:
    rng = random.Random(seed)
    world = World()
    scn.setup(world)
    if cfg.name.startswith("guard"):
        from .guard_bridge import GuardPipeline
        pipeline = GuardPipeline(world, cfg, opt.approver_miss_rate, seed,
                                 judge_llm=opt.judge_factory() if opt.judge == "llm" else None)
    else:
        judge = None
        if cfg.judge:
            judge = LLMJudge(opt.judge_factory()) if opt.judge == "llm" else RuleJudge()
        pipeline = ControlPipeline(world, cfg, judge=judge,
                                   approver=OracleApprover(opt.approver_miss_rate, random.Random(seed + 7919)))
    trace = RunTrace(scn.id, cfg.name, seed)

    def hook(step, ctx):
        if scn.suspend_after_step is not None and trace.suspended_at_step is None \
                and step > scn.suspend_after_step:
            trace.suspended_at_step = step  # the operator *asks* to stop here
            pipeline.operator_suspend(None, step)

    hijacked = False
    model_name = "scripted-compromisable-v1"
    for i, sess in enumerate(scn.sessions):
        if opt.backend == "scripted":
            llm = ScriptedLLM(sess.task.plan, scn.hijack if i == scn.hijack_session else None,
                              opt.follow_spotlighted, rng)
        else:
            llm = opt.llm_factory()
            model_name = getattr(llm, "name", "model")
        run_session(sess, f"s{i + 1}", llm, pipeline, trace, max_steps=opt.max_steps, step_hook=hook)
        hijacked = hijacked or getattr(llm, "was_hijacked", False)

    if opt.log_dir:
        os.makedirs(opt.log_dir, exist_ok=True)
        pipeline.log.to_jsonl(os.path.join(opt.log_dir, f"{scn.id}__{cfg.name}__seed{seed}.jsonl"))

    actions = [s for s in trace.steps if s.action is not None]
    return {
        "scenario": scn.id,
        "kind": scn.kind,
        "config": cfg.name,
        "layers": "+".join(cfg.layers()) or "none",
        "seed": seed,
        "backend": opt.backend,
        "model": model_name,
        "judge": (pipeline.judge.name if pipeline.judge else ""),
        "attack_success": (bool(scn.attack_success(world, trace)) if scn.kind == "attack" else ""),
        "task_success": bool(scn.task_success(world, trace)),
        "proposed_actions": len(actions),
        "executed_actions": len(world.exec_log),
        "blocked_actions": len(pipeline.blocks),
        "blocked_by": "|".join(sorted({b["layer"] for b in pipeline.blocks})),
        "quarantined_lines": len(pipeline.quarantined),
        "simulated_hijack": hijacked if opt.backend == "scripted" else "",
        "reconstructable": reconstructable(pipeline.log, world.exec_log),
        "llm_calls": trace.llm_calls,
        "judge_calls": trace.judge_calls,
        "prompt_tokens": trace.prompt_tokens,
        "completion_tokens": trace.completion_tokens,
        "latency_ms": round(trace.latency_ms, 2),
    }


def write_run_metadata(out_dir: str, scenario_ids: list[str], config_names: list[str], seeds: int,
                       opt: RunOptions) -> dict:
    """Record what was run, on what, before the first model call (preregistration §3).
    Never records API keys. AAB_MODEL_NOTE carries facts only the operator knows, such as
    the Azure model version shown in the portal or the Ollama model digest."""
    import datetime as dt
    import platform
    import subprocess
    import sys
    from urllib.parse import urlparse

    from . import __version__

    def git(*args: str) -> str:
        try:
            return subprocess.run(["git", *args], capture_output=True, text=True, timeout=10,
                                  cwd=os.path.dirname(os.path.abspath(__file__))).stdout.strip()
        except Exception:  # noqa: BLE001
            return ""

    meta = {
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "agentaudit_version": __version__,
        "git_commit": git("rev-parse", "HEAD"),
        "git_tags_at_commit": git("tag", "--points-at", "HEAD").split(),
        "git_dirty": bool(git("status", "--porcelain")),
        "backend": opt.backend,
        "model": os.environ.get("AAB_MODEL", "scripted-compromisable-v1" if opt.backend == "scripted" else ""),
        "endpoint_host": urlparse(os.environ.get("AAB_BASE_URL", "")).hostname or "",
        "azure_api_version": os.environ.get("AAB_AZURE_API_VERSION", ""),
        "model_note": os.environ.get("AAB_MODEL_NOTE", ""),
        "judge": opt.judge,
        "approver_miss_rate": opt.approver_miss_rate,
        "max_steps": opt.max_steps,
        "seeds": seeds,
        "scenarios": scenario_ids,
        "configs": config_names,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }
    with open(os.path.join(out_dir, "model.json"), "w") as f:
        json.dump(meta, f, indent=2)
    return meta


def _error_row(scn: Scenario, cfg: DefenceConfig, seed: int, opt: RunOptions, err: str) -> dict:
    return {"scenario": scn.id, "kind": scn.kind, "config": cfg.name, "layers": "+".join(cfg.layers()) or "none",
            "seed": seed, "backend": opt.backend, "model": os.environ.get("AAB_MODEL", ""), "judge": "",
            "attack_success": "", "task_success": "", "proposed_actions": 0, "executed_actions": 0,
            "blocked_actions": 0, "blocked_by": "", "quarantined_lines": 0, "simulated_hijack": "",
            "reconstructable": "", "llm_calls": 0, "judge_calls": 0, "prompt_tokens": 0,
            "completion_tokens": 0, "latency_ms": 0, "error": err}


def run_matrix(scenario_ids: list[str], config_names: list[str], seeds: int, opt: RunOptions,
               out_dir: str, progress: bool = True, resume: bool = False) -> list[dict]:
    """Run every scenario x configuration x seed.

    Per the preregistration, a run that fails with an exception is re-run once; if it fails
    again it is recorded with an `error` and excluded from the report. With resume=True,
    runs already in runs.jsonl (without an error) are kept and skipped, so an interrupted
    session can continue where it stopped.
    """
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "runs.jsonl")
    done: dict[tuple, dict] = {}
    if resume and os.path.exists(path):
        with open(path) as f:
            for line in f:
                if line.strip():
                    r = json.loads(line)
                    if not r.get("error"):
                        done[(r["config"], r["scenario"], int(r["seed"]))] = r
    if not done:
        write_run_metadata(out_dir, scenario_ids, config_names, seeds, opt)
    rows: list[dict] = []
    total = len(scenario_ids) * len(config_names) * seeds
    n = 0
    with open(path, "w") as jsonl:
        for cname in config_names:
            cfg = PRESETS[cname]
            for sid in scenario_ids:
                for seed in range(seeds):
                    n += 1
                    key = (cname, sid, seed)
                    if key in done:
                        row = done[key]
                    else:
                        row = None
                        for attempt in (1, 2):
                            try:
                                row = run_one(ALL_SCENARIOS[sid], cfg, seed, opt)
                                row["error"] = ""
                                break
                            except Exception as e:  # noqa: BLE001 -- recorded, not hidden
                                if attempt == 2:
                                    row = _error_row(ALL_SCENARIOS[sid], cfg, seed, opt,
                                                     f"{type(e).__name__}: {e}"[:300])
                    rows.append(row)
                    jsonl.write(json.dumps(row) + "\n")
                    jsonl.flush()
                    if progress:
                        tag = "resumed" if key in done else ("ERROR " + row["error"][:60] if row["error"] else "")
                        print(f"[{n}/{total}] {cname:14s} {sid} seed={seed} "
                              f"attack={row['attack_success']!s:5s} task={row['task_success']!s:5s} "
                              f"blocked={row['blocked_by'] or '-'} {tag}")
    with open(os.path.join(out_dir, "runs.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return rows
