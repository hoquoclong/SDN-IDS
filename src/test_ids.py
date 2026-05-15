#!/usr/bin/env python3
"""
Live precision/recall evaluator for SDN-IDS.

Run after starting Ryu from the project root:
  sudo python3.8 src/test_ids.py --output test_results.json
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import requests

from ids_detector import get_alert_log_file, read_alert_log


PROJECT_ROOT = Path(__file__).resolve().parents[1]
IDS_SCRIPT = PROJECT_ROOT / "src" / "ids_detector.py"
RYU_API_URL = "http://127.0.0.1:8080"
VICTIM_IP = "10.0.0.1"
DEFAULT_WARMUP_SECONDS = 2
DEFAULT_POST_WAIT_SECONDS = 8
DEFAULT_ATTACK_SECONDS = 30


SCENARIOS = [
    {
        "name": "benign_ping",
        "expected": [],
        "kind": "benign_ping",
        "duration": 0,
        "post_wait": 8,
    },
    {
        "name": "single_dos",
        "expected": [("DoS", "10.0.0.21")],
        "kind": "hping_flood",
        "hosts": ["h_atk1"],
        "duration": DEFAULT_ATTACK_SECONDS,
    },
    {
        "name": "distributed_ddos",
        "expected": [
            ("Distributed_DDoS", "10.0.0.21"),
            ("Distributed_DDoS", "10.0.0.22"),
            ("Distributed_DDoS", "10.0.0.23"),
        ],
        "kind": "hping_flood",
        "hosts": ["h_atk1", "h_atk2", "h_atk3"],
        "duration": DEFAULT_ATTACK_SECONDS,
    },
    {
        "name": "port_scan",
        "expected": [("Port_Scan", "10.0.0.24")],
        "kind": "port_scan",
        "host": "h_atk4",
        "duration": 0,
        "post_wait": 28,
    },
    {
        "name": "port_scan_rate",
        "expected": [("Suspected_Port_Scan_Rate", "10.0.0.25")],
        "kind": "port_scan_rate",
        "host": "h_atk5",
        "duration": DEFAULT_ATTACK_SECONDS,
    },
    {
        "name": "arp_spoofing",
        "expected": [("ARP_SPOOFING", "10.0.0.26")],
        "kind": "arp_spoof",
        "host": "h_atk6",
        "spoofed_ip": "10.0.0.11",
        "duration": 8,
        "post_wait": 5,
    },
    {
        "name": "arp_unknown_binding",
        "expected": [("ARP_UNKNOWN_BINDING", "10.0.0.27")],
        "kind": "arp_spoof",
        "host": "h_atk7",
        "spoofed_ip": "10.0.0.2",
        "duration": 8,
        "post_wait": 5,
    },
]


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def tuple_to_dict(item):
    attack_type, attacker_ip = item
    return {"attack_type": attack_type, "attacker_ip": attacker_ip}


def metric_counts(expected, observed):
    expected_set = set(expected)
    observed_set = set(observed)
    tp = expected_set & observed_set
    fp = observed_set - expected_set
    fn = expected_set - observed_set
    return tp, fp, fn


def metric_values(tp_count, fp_count, fn_count):
    precision = tp_count / (tp_count + fp_count) if tp_count + fp_count else 1.0
    recall = tp_count / (tp_count + fn_count) if tp_count + fn_count else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def calculate_metrics(scenario_results):
    by_type = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    overall = {"tp": 0, "fp": 0, "fn": 0}

    for result in scenario_results:
        if result["status"] == "skipped":
            continue
        for bucket_name, items in (
            ("tp", result["true_positives"]),
            ("fp", result["false_positives"]),
            ("fn", result["false_negatives"]),
        ):
            for item in items:
                attack_type = item["attack_type"]
                by_type[attack_type][bucket_name] += 1
                overall[bucket_name] += 1

    metrics_by_type = {}
    for attack_type, counts in sorted(by_type.items()):
        metrics_by_type[attack_type] = {
            **counts,
            **metric_values(counts["tp"], counts["fp"], counts["fn"]),
        }

    return {
        "overall": {
            **overall,
            **metric_values(overall["tp"], overall["fp"], overall["fn"]),
        },
        "by_attack_type": metrics_by_type,
    }


def alert_keys(alerts):
    keys = set()
    for alert in alerts:
        attack_type = alert.get("attack_type")
        if not attack_type:
            continue

        attacker_ips = alert.get("attacker_ips") or []
        expanded = False
        for item in attacker_ips:
            if isinstance(item, dict):
                attacker_ip = item.get("ip")
            else:
                attacker_ip = item
            if attacker_ip:
                keys.add((attack_type, attacker_ip))
                expanded = True

        if not expanded and alert.get("attacker_ip"):
            keys.add((attack_type, alert["attacker_ip"]))
    return sorted(keys)


def check_root():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise SystemExit("Live evaluator must run as root: sudo python3.8 src/test_ids.py")


def check_tools():
    missing = [tool for tool in ("hping3", "nmap", "arpspoof") if not shutil.which(tool)]
    if missing:
        raise SystemExit(f"Missing required tool(s): {', '.join(missing)}")


def check_ryu_ready(timeout=3):
    try:
        res = requests.get(f"{RYU_API_URL}/stats/switches", timeout=timeout)
        res.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise SystemExit(
            "Ryu REST API is not ready. Start Ryu first with the command in README.md. "
            f"Details: {exc}"
        )


def wait_for_switch(timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            res = requests.get(f"{RYU_API_URL}/stats/switches", timeout=3)
            res.raise_for_status()
            if 1 in res.json() or "1" in res.json():
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(1)
    return False


def flow_stats_have_port_fields():
    try:
        res = requests.get(f"{RYU_API_URL}/stats/flow/1", timeout=5)
        res.raise_for_status()
        flows = res.json().get("1", [])
    except requests.exceptions.RequestException:
        return False

    for flow in flows:
        match = flow.get("match", {})
        if "tcp_dst" in match or "udp_dst" in match:
            return True
    return False


def clear_alert_log():
    path = Path(get_alert_log_file())
    if path.exists():
        path.unlink()


def start_ids_process():
    env = os.environ.copy()
    env["IDS_DISABLE_MITIGATION"] = "1"
    env["IDS_ALERT_LOG_FILE"] = str(PROJECT_ROOT / "alerts.log")
    env["PYTHONUNBUFFERED"] = "1"
    return subprocess.Popen(
        [sys.executable, str(IDS_SCRIPT)],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


def stop_process(proc, timeout=3):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=timeout)


def stop_processes(processes):
    for proc in processes:
        stop_process(proc)


def run_for_duration(processes, seconds):
    if seconds > 0:
        time.sleep(seconds)
    stop_processes(processes)


def start_hping_flood(host, target_ip=VICTIM_IP, target_port="80", interval=None):
    cmd = ["hping3", "-S", "-p", target_port]
    if interval:
        cmd.extend(["-i", interval])
    else:
        cmd.append("--flood")
    cmd.append(target_ip)
    return host.popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_scenario_traffic(scenario, hosts):
    kind = scenario["kind"]
    duration = scenario.get("duration", DEFAULT_ATTACK_SECONDS)

    if kind == "benign_ping":
        for host_name in ("h_ben1", "h_ben2", "h_ben3"):
            hosts[host_name].cmd(f"ping -c 3 -W 1 {VICTIM_IP}")
        return

    if kind == "hping_flood":
        processes = [start_hping_flood(hosts[name]) for name in scenario["hosts"]]
        run_for_duration(processes, duration)
        return

    if kind == "port_scan":
        host = hosts[scenario["host"]]
        host.cmd(f"nmap -p 1-1000 -T4 -n {VICTIM_IP}")
        return

    if kind == "port_scan_rate":
        host = hosts[scenario["host"]]
        processes = [start_hping_flood(host, interval="u20000")]
        run_for_duration(processes, duration)
        return

    if kind == "arp_spoof":
        host = hosts[scenario["host"]]
        interface = f"{scenario['host']}-eth0"
        processes = [
            host.popen(
                ["arpspoof", "-i", interface, "-t", VICTIM_IP, scenario["spoofed_ip"]],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        ]
        run_for_duration(processes, duration)
        return

    raise ValueError(f"Unknown scenario kind: {kind}")


def evaluate_scenario(scenario, args):
    from topology import start_ids_network

    start_index = len(read_alert_log())
    status = "completed"
    skip_reason = None
    net = None
    ids_proc = None

    try:
        net, hosts = start_ids_network(verify=False, wait_seconds=args.switch_wait)
        if not wait_for_switch(timeout=args.switch_timeout):
            raise RuntimeError("Switch s1 did not appear in Ryu REST /stats/switches")

        ids_proc = start_ids_process()
        time.sleep(args.warmup)

        run_scenario_traffic(scenario, hosts)
        time.sleep(scenario.get("post_wait", DEFAULT_POST_WAIT_SECONDS))

        alerts = read_alert_log()[start_index:]
        observed = alert_keys(alerts)
        expected = sorted(scenario["expected"])

        if scenario["name"] == "port_scan":
            observed_has_port_scan = any(item[0] == "Port_Scan" for item in observed)
            if not observed_has_port_scan and not flow_stats_have_port_fields():
                status = "skipped"
                skip_reason = "Ryu flow stats do not expose tcp_dst/udp_dst fields"

        if status == "skipped":
            tp, fp, fn = set(), set(), set()
        else:
            tp, fp, fn = metric_counts(expected, observed)

        return {
            "name": scenario["name"],
            "status": status,
            "skip_reason": skip_reason,
            "expected": [tuple_to_dict(item) for item in expected],
            "observed": [tuple_to_dict(item) for item in observed],
            "true_positives": [tuple_to_dict(item) for item in sorted(tp)],
            "false_positives": [tuple_to_dict(item) for item in sorted(fp)],
            "false_negatives": [tuple_to_dict(item) for item in sorted(fn)],
            "metrics": metric_values(len(tp), len(fp), len(fn)),
            "alerts": alerts,
        }
    except Exception as exc:
        return {
            "name": scenario["name"],
            "status": "failed",
            "error": str(exc),
            "expected": [tuple_to_dict(item) for item in sorted(scenario["expected"])],
            "observed": [],
            "true_positives": [],
            "false_positives": [],
            "false_negatives": [tuple_to_dict(item) for item in sorted(scenario["expected"])],
            "metrics": metric_values(0, 0, len(scenario["expected"])),
            "alerts": read_alert_log()[start_index:],
        }
    finally:
        stop_process(ids_proc)
        if net is not None:
            net.stop()


def write_results(results, output_path):
    path = Path(output_path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
        f.write("\n")


def parse_args():
    parser = argparse.ArgumentParser(description="Run live SDN-IDS precision/recall scenarios.")
    parser.add_argument("--output", default="test_results.json", help="Path to write JSON results.")
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP_SECONDS, help="Seconds to wait after IDS starts.")
    parser.add_argument("--switch-wait", type=int, default=3, help="Seconds topology waits after net.start().")
    parser.add_argument("--switch-timeout", type=int, default=20, help="Seconds to wait for switch in Ryu REST.")
    parser.add_argument(
        "--scenario",
        action="append",
        choices=[scenario["name"] for scenario in SCENARIOS],
        help="Run only this scenario; can be passed multiple times.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    os.chdir(PROJECT_ROOT)
    started_at = now()
    check_root()
    check_tools()
    check_ryu_ready()
    clear_alert_log()

    selected = SCENARIOS
    if args.scenario:
        selected = [scenario for scenario in SCENARIOS if scenario["name"] in set(args.scenario)]

    scenario_results = []
    for scenario in selected:
        print(f"[{now()}] Running scenario: {scenario['name']}")
        result = evaluate_scenario(scenario, args)
        scenario_results.append(result)
        print(f"[{now()}] {scenario['name']}: {result['status']}")

    results = {
        "started_at": started_at,
        "finished_at": now(),
        "mode": "live_mininet",
        "metric_unit": "attack_type + attacker_ip",
        "scenarios": scenario_results,
        "metrics": calculate_metrics(scenario_results),
    }
    write_results(results, args.output)
    print(f"[{now()}] Wrote results to {args.output}")


if __name__ == "__main__":
    main()
