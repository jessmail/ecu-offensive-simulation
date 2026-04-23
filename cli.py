"""
ECU Offensive Simulation Framework - CLI Interface.

Command-line tool for ECU security testing via UDS/DoIP protocols.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from src.protocols.can_interface import CANInterface, CANFilter, BusSpeed
from src.attacks.replay import ReplayAttack
from src.attacks.fuzzer import ECUFuzzer, FuzzStrategy
from src.attacks.negative_testing import NegativeTester
from src.attacks.security_access import SecurityAccessAnalyzer
from src.reporting.report_generator import ReportGenerator

console = Console()


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with rich output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


def load_ecu_profile(profile_path: str) -> dict:
    """Load an ECU profile from a YAML file."""
    with open(profile_path) as f:
        return yaml.safe_load(f)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
@click.option("--config", "-c", type=click.Path(exists=True), help="ECU profile YAML.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, config: str) -> None:
    """ECU Offensive Simulation Framework.

    Security testing tool for automotive ECUs via UDS/DoIP protocols.
    """
    setup_logging(verbose)
    ctx.ensure_object(dict)

    if config:
        ctx.obj["profile"] = load_ecu_profile(config)
    else:
        ctx.obj["profile"] = {
            "ecu": {
                "can_id_tx": 0x7E0,
                "can_id_rx": 0x7E8,
            },
            "interface": {
                "type": "virtual",
                "channel": "vcan0",
                "bitrate": 500000,
            },
        }


@cli.command()
@click.option("--interface", "-i", default="vcan0", help="CAN interface name.")
@click.option("--duration", "-d", type=float, default=60.0, help="Recording duration (seconds).")
@click.option("--output", "-o", default="captures/session.json", help="Output file path.")
@click.option("--arb-id", type=str, default=None, help="Filter by arbitration ID (hex, e.g., 0x7E0).")
@click.pass_context
def record(ctx: click.Context, interface: str, duration: float, output: str, arb_id: str) -> None:
    """Record CAN/UDS traffic from the bus."""
    profile = ctx.obj["profile"]
    tx_id = profile["ecu"]["can_id_tx"]
    rx_id = profile["ecu"]["can_id_rx"]

    console.print(f"[bold]Recording traffic on {interface} for {duration}s[/bold]")
    console.print(f"  TX ID: 0x{tx_id:03X}, RX ID: 0x{rx_id:03X}")

    filters = []
    if arb_id:
        filter_id = int(arb_id, 16)
        filters.append(CANFilter(can_id=filter_id))

    can = CANInterface(
        interface=profile.get("interface", {}).get("type", "virtual"),
        channel=interface,
        bitrate=profile.get("interface", {}).get("bitrate", BusSpeed.SPEED_500K),
        filters=filters,
    )

    with can:
        replay = ReplayAttack(can, tx_id=tx_id, rx_id=rx_id)
        exchanges = replay.record_session(duration)
        replay.save_session(output)

    console.print(f"\n[green]Recorded {len(exchanges)} exchanges to {output}[/green]")


@cli.command()
@click.option("--capture", "-f", required=True, type=click.Path(exists=True), help="Capture file.")
@click.option("--interface", "-i", default="vcan0", help="CAN interface name.")
@click.option("--preserve-timing", is_flag=True, help="Preserve original timing.")
@click.option("--output", "-o", default="results/replay_results.json", help="Output file.")
@click.pass_context
def replay(ctx: click.Context, capture: str, interface: str, preserve_timing: bool, output: str) -> None:
    """Replay captured CAN/UDS traffic."""
    profile = ctx.obj["profile"]
    tx_id = profile["ecu"]["can_id_tx"]
    rx_id = profile["ecu"]["can_id_rx"]

    console.print(f"[bold]Replaying capture: {capture}[/bold]")

    with open(capture) as f:
        session_data = json.load(f)

    # Reconstruct exchanges from saved data
    from src.attacks.replay import CapturedExchange
    exchanges = []
    for ex_data in session_data.get("exchanges", []):
        exchanges.append(CapturedExchange(
            request=bytes.fromhex(ex_data["request"]),
            response=bytes.fromhex(ex_data["response"]),
            timestamp_request=ex_data["timestamp_request"],
            timestamp_response=ex_data["timestamp_response"],
            service_id=int(ex_data["service_id"], 16),
        ))

    can = CANInterface(
        interface=profile.get("interface", {}).get("type", "virtual"),
        channel=interface,
        bitrate=profile.get("interface", {}).get("bitrate", BusSpeed.SPEED_500K),
    )

    with can:
        attack = ReplayAttack(can, tx_id=tx_id, rx_id=rx_id)
        results = attack.replay_sequence(exchanges, preserve_timing=preserve_timing)
        attack.save_session(output)

    # Display results table
    table = Table(title="Replay Results")
    table.add_column("#", style="dim")
    table.add_column("Request")
    table.add_column("Outcome")
    table.add_column("Response")

    for r in results:
        outcome_style = "green" if r["outcome"] == "SUCCESS" else "red"
        table.add_row(
            str(r["index"]),
            r["original_request"][:16] + "...",
            f"[{outcome_style}]{r['outcome']}[/{outcome_style}]",
            (r.get("replay_response") or "None")[:16],
        )

    console.print(table)
    console.print(f"\n[green]Results saved to {output}[/green]")


@cli.command()
@click.option("--target", "-t", default="0x7E0", help="Target ECU arbitration ID (hex).")
@click.option("--service", "-s", default="0x27", help="UDS service ID to fuzz (hex).")
@click.option("--strategy", type=click.Choice(["random", "sequential", "smart", "boundary"]), default="random")
@click.option("--iterations", "-n", type=int, default=1000, help="Number of fuzz iterations.")
@click.option("--interface", "-i", default="vcan0", help="CAN interface name.")
@click.option("--output", "-o", default="results/fuzz_results.json", help="Output file.")
@click.option("--config", "fuzz_config", type=click.Path(exists=True), help="Fuzzer config YAML.")
@click.pass_context
def fuzz(
    ctx: click.Context,
    target: str,
    service: str,
    strategy: str,
    iterations: int,
    interface: str,
    output: str,
    fuzz_config: str,
) -> None:
    """Fuzz ECU UDS services with generated payloads."""
    profile = ctx.obj["profile"]
    tx_id = int(target, 16)
    rx_id = tx_id + 0x08  # Standard offset
    service_id = int(service, 16)

    strategy_map = {
        "random": FuzzStrategy.RANDOM,
        "sequential": FuzzStrategy.SEQUENTIAL,
        "smart": FuzzStrategy.SMART,
        "boundary": FuzzStrategy.BOUNDARY,
    }
    fuzz_strategy = strategy_map[strategy]

    if fuzz_config:
        with open(fuzz_config) as f:
            fconfig = yaml.safe_load(f)
        iterations = fconfig.get("iterations", iterations)

    console.print(f"[bold]Fuzzing SID 0x{service_id:02X} on 0x{tx_id:03X}[/bold]")
    console.print(f"  Strategy: {strategy}, Iterations: {iterations}")

    can = CANInterface(
        interface=profile.get("interface", {}).get("type", "virtual"),
        channel=interface,
        bitrate=profile.get("interface", {}).get("bitrate", BusSpeed.SPEED_500K),
    )

    with can:
        fuzzer = ECUFuzzer(can, tx_id=tx_id, rx_id=rx_id)

        with console.status("[bold green]Fuzzing in progress..."):
            session = fuzzer.fuzz_service(
                service_id=service_id,
                strategy=fuzz_strategy,
                iterations=iterations,
            )

        fuzzer.save_results(output)

    # Display summary
    summary = session.summary()
    table = Table(title="Fuzz Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Total Iterations", str(summary["total_iterations"]))
    table.add_row("Interesting Findings", str(summary["interesting_count"]))
    table.add_row("Crashes Detected", str(summary["crashes_detected"]))
    table.add_row("Duration", f"{summary['duration_seconds']}s")
    table.add_row("Speed", f"{summary['iterations_per_second']} iter/s")

    console.print(table)

    if summary["interesting_count"] > 0:
        console.print(f"\n[yellow]Found {summary['interesting_count']} interesting responses![/yellow]")

    console.print(f"\n[green]Results saved to {output}[/green]")


@cli.command()
@click.option("--target", "-t", default="0x7E0", help="Target ECU arbitration ID (hex).")
@click.option("--mode", type=click.Choice(["seed-entropy", "seed-reuse", "key-derivation", "brute-force"]),
              default="seed-entropy")
@click.option("--samples", "-n", type=int, default=100, help="Number of seed samples.")
@click.option("--interface", "-i", default="vcan0", help="CAN interface name.")
@click.option("--output", "-o", default="results/analysis_results.json", help="Output file.")
@click.pass_context
def analyze(ctx: click.Context, target: str, mode: str, samples: int, interface: str, output: str) -> None:
    """Analyze SecurityAccess implementation security."""
    profile = ctx.obj["profile"]
    tx_id = int(target, 16)
    rx_id = tx_id + 0x08

    console.print(f"[bold]SecurityAccess analysis: {mode}[/bold]")
    console.print(f"  Target: 0x{tx_id:03X}, Samples: {samples}")

    can = CANInterface(
        interface=profile.get("interface", {}).get("type", "virtual"),
        channel=interface,
        bitrate=profile.get("interface", {}).get("bitrate", BusSpeed.SPEED_500K),
    )

    with can:
        analyzer = SecurityAccessAnalyzer(can, tx_id=tx_id, rx_id=rx_id)

        if mode == "seed-entropy":
            with console.status("[bold green]Collecting seeds..."):
                seeds = analyzer.collect_seeds(count=samples)
            entropy = analyzer.analyze_entropy()
            console.print(f"\n  Unique seeds: {entropy.unique_seeds}/{entropy.total_samples}")
            console.print(f"  Estimated entropy: {entropy.estimated_entropy_bits:.1f} / "
                          f"{entropy.theoretical_max_entropy_bits:.1f} bits")
            console.print(f"  Vulnerability: [bold]{entropy.vulnerability_rating}[/bold]")

        elif mode == "seed-reuse":
            with console.status("[bold green]Testing seed reuse..."):
                result = analyzer.detect_seed_reuse(count=samples)
            if result["reuse_detected"]:
                console.print(f"\n[red bold]SEED REUSE DETECTED[/red bold]")
                console.print(f"  Duplicates: {len(result['duplicates'])}")
            else:
                console.print(f"\n[green]No seed reuse detected in {samples} samples[/green]")

        elif mode == "key-derivation":
            with console.status("[bold green]Testing key derivation algorithms..."):
                results = analyzer.test_key_derivations()
            found = [r for r in results if r.accepted]
            if found:
                console.print(f"\n[red bold]KEY DERIVATION FOUND[/red bold]")
                for r in found:
                    console.print(f"  Algorithm: {r.algorithm_name}, Param: {r.parameter}")
            else:
                console.print(f"\n[green]No known key derivation matched[/green]")

        elif mode == "brute-force":
            with console.status("[bold green]Brute forcing..."):
                result = analyzer.brute_force(max_attempts=samples)
            if result.key_found:
                console.print(f"\n[red bold]KEY FOUND: {result.key.hex()}[/red bold]")
            else:
                console.print(f"\nKey not found in {result.attempts} attempts "
                              f"({result.keys_per_second:.1f} keys/s)")

        analyzer.save_results(output)

    console.print(f"\n[green]Results saved to {output}[/green]")


@cli.command()
@click.option("--input", "-i", "input_dir", default="results/", help="Input results directory.")
@click.option("--format", "-f", "fmt", type=click.Choice(["markdown", "json"]), default="markdown")
@click.option("--output", "-o", default="report.md", help="Output report file.")
@click.option("--project", default="ECU Security Assessment", help="Project name.")
@click.option("--target-name", default="Target ECU", help="ECU name for the report.")
@click.pass_context
def report(ctx: click.Context, input_dir: str, fmt: str, output: str, project: str, target_name: str) -> None:
    """Generate an ISO 21434 compliant security report."""
    console.print(f"[bold]Generating {fmt} report[/bold]")

    generator = ReportGenerator(
        project_name=project,
        assessor="Security Engineering Team",
        target_ecu=target_name,
    )

    # Load results from input directory
    results_path = Path(input_dir)
    if results_path.exists():
        for result_file in results_path.glob("*.json"):
            console.print(f"  Loading: {result_file.name}")
            with open(result_file) as f:
                data = json.load(f)

            # Auto-detect result type and create findings
            _process_result_file(generator, data, result_file.name)

    generator.save(output, fmt=fmt)

    # Display summary
    report_data = generator.generate_json()
    summary = report_data["executive_summary"]

    table = Table(title="Report Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Total Findings", str(summary["total_findings"]))
    table.add_row("Overall Risk", summary["overall_risk"])

    for sev, count in summary["severity_distribution"].items():
        table.add_row(f"  {sev}", str(count))

    console.print(table)
    console.print(f"\n[green]Report saved to {output}[/green]")


@cli.command("negative-test")
@click.option("--target", "-t", default="0x7E0", help="Target ECU arbitration ID (hex).")
@click.option("--interface", "-i", default="vcan0", help="CAN interface name.")
@click.option("--output", "-o", default="results/negative_test_results.json", help="Output file.")
@click.pass_context
def negative_test(ctx: click.Context, target: str, interface: str, output: str) -> None:
    """Run negative / edge-case tests against the target ECU."""
    profile = ctx.obj["profile"]
    tx_id = int(target, 16)
    rx_id = tx_id + 0x08

    console.print(f"[bold]Running negative tests on 0x{tx_id:03X}[/bold]")

    can = CANInterface(
        interface=profile.get("interface", {}).get("type", "virtual"),
        channel=interface,
        bitrate=profile.get("interface", {}).get("bitrate", BusSpeed.SPEED_500K),
    )

    with can:
        tester = NegativeTester(can, tx_id=tx_id, rx_id=rx_id)

        with console.status("[bold green]Running negative tests..."):
            suite = tester.run_all()

        tester.save_results(output)

    summary = suite.summary()
    table = Table(title="Negative Test Results")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Total Tests", str(summary["total"]))
    table.add_row("Pass", f"[green]{summary['pass']}[/green]")
    table.add_row("Fail", f"[red]{summary['fail']}[/red]" if summary["fail"] > 0 else "0")
    table.add_row("Warning", str(summary["warning"]))
    table.add_row("Error", str(summary["error"]))
    table.add_row("Pass Rate", f"{summary['pass_rate']}%")

    console.print(table)
    console.print(f"\n[green]Results saved to {output}[/green]")


def _process_result_file(generator: ReportGenerator, data: dict, filename: str) -> None:
    """Auto-detect result type and add findings to the report."""
    if "seed_analysis" in data:
        seed_info = data["seed_analysis"]
        if seed_info.get("reuse_count", 0) > 0:
            generator.add_finding_from_template(
                "seed_reuse",
                evidence=f"Seed reuse detected: {seed_info['reuse_count']} duplicates "
                         f"in {seed_info['total_seeds']} samples "
                         f"(unique ratio: {seed_info['unique_ratio']})",
                affected_component="SecurityAccess (SID 0x27)",
            )

    if "summary" in data and "crashes_detected" in data["summary"]:
        fuzz_summary = data["summary"]
        if fuzz_summary["crashes_detected"] > 0:
            generator.add_finding_from_template(
                "ecu_crash",
                evidence=f"ECU crashed {fuzz_summary['crashes_detected']} times "
                         f"during {fuzz_summary['total_iterations']} fuzz iterations",
                affected_component="Diagnostic Handler",
            )

    if "results" in data:
        for result in data.get("results", []):
            if result.get("verdict") == "FAIL" and result.get("category") == "UNAUTHORIZED_ACCESS":
                generator.add_finding_from_template(
                    "unauthorized_write",
                    evidence=f"Request {result['request']} accepted without authentication",
                    affected_component=result.get("description", "Unknown"),
                )


if __name__ == "__main__":
    cli()
