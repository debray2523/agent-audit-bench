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


def run_matrix(scenario_ids: list[str], config_names: list[str], seeds: int, opt: RunOptions,
               out_dir: str, progress: bool = True) -> list[dict]:
    os.makedirs(out_dir, exist_ok=True)
    rows: list[dict] = []
    total = len(scenario_ids) * len(config_names) * seeds
    n = 0
    jsonl = open(os.path.join(out_dir, "runs.jsonl"), "w")
    try:
        for cname in config_names:
            cfg = PRESETS[cname]
            for sid in scenario_ids:
                for seed in range(seeds):
                    n += 1
                    row = run_one(ALL_SCENARIOS[sid], cfg, seed, opt)
                    rows.append(row)
                    jsonl.write(json.dumps(row) + "\n")
                    jsonl.flush()
                    if progress:
                        print(f"[{n}/{total}] {cname:14s} {sid} seed={seed} "
                              f"attack={row['attack_success']!s:5s} task={row['task_success']!s:5s} "
                              f"blocked={row['blocked_by'] or '-'}")
    finally:
        jsonl.close()
    with open(os.path.join(out_dir, "runs.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return rows
