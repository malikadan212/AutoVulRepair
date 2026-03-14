"""
INTREPAIR — Main Pipeline Runner
End-to-end: Scan → Detect → Repair → Validate → Write

Usage (CLI):
    python -m src.intrepair.pipeline path/to/file.c [--output path/to/repaired.c]

Usage (Python API):
    from src.intrepair.pipeline import IntRepairPipeline
    pipeline = IntRepairPipeline("vulnerable.c")
    result = pipeline.run()
    print(result)
"""

import os
import sys
import json
import logging
import argparse
from dataclasses import dataclass, field, asdict
from typing import List, Optional

from .scanner import IntRepairScanner, IntRepairApplier
from .detector import OverflowFault

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s — %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Final result of a full INTREPAIR pipeline run."""
    source_file:        str
    faults_found:       int
    repairs_applied:    int
    repaired_file:      Optional[str]
    gcc_valid:          bool
    fault_details:      List[dict] = field(default_factory=list)
    success:            bool = False

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


class IntRepairPipeline:
    """
    Orchestrates the full INTREPAIR pipeline:
      1. Scan source file
      2. Detect overflow faults (Z3 SMT)
      3. Generate repairs (decision tree)
      4. Validate repairs (Z3 negation + GCC)
      5. Write repaired source
      6. Re-run scan to confirm removal
    """

    def __init__(self, source_path: str, output_path: Optional[str] = None,
                 auto_apply: bool = True):
        """
        Args:
            source_path:  Path to the C source file to repair.
            output_path:  Path to write the repaired file (default: <name>_repaired.c).
            auto_apply:   If True, auto-select first repair pattern (paper §7 default).
                          If False, list candidates for user selection (human-in-the-loop).
        """
        self.source_path = source_path
        self.output_path = output_path
        self.auto_apply  = auto_apply

    def run(self) -> PipelineResult:
        """Run the complete INTREPAIR pipeline. Returns PipelineResult."""

        if not os.path.exists(self.source_path):
            raise FileNotFoundError(f"Source file not found: {self.source_path}")

        logger.info("=" * 60)
        logger.info(f" INTREPAIR — Scanning: {self.source_path}")
        logger.info("=" * 60)

        # ── PHASE 1: SCAN & DETECT ──
        scanner = IntRepairScanner()
        faults  = scanner.scan_file(self.source_path)

        if not faults:
            logger.info("✅ No integer overflow faults detected.")
            return PipelineResult(
                source_file=self.source_path,
                faults_found=0,
                repairs_applied=0,
                repaired_file=None,
                gcc_valid=True,
                success=True,
            )

        logger.info(f"⚠️  {len(faults)} fault(s) detected. Generating repairs...")

        # ── PHASE 2: APPLY REPAIRS ──
        applier  = IntRepairApplier(self.source_path)
        repaired = applier.apply_all(faults)

        # ── PHASE 3: WRITE REPAIRED FILE ──
        output_path = applier.write_repaired(repaired, self.output_path)

        # ── PHASE 4: GCC VALIDATION (paper §10) ──
        gcc_ok = applier.validate_with_gcc(output_path)

        # ── PHASE 5: RE-SCAN REPAIRED FILE (paper §10 "re-run symbolic execution") ──
        logger.info("🔄 Re-scanning repaired file to confirm fault removal...")
        re_scanner = IntRepairScanner()
        remaining  = re_scanner.scan_file(output_path)

        if remaining:
            logger.warning(
                f"⚠️  {len(remaining)} fault(s) still detected after repair. "
                f"Manual review required."
            )
            success = False
        else:
            logger.info("✅ Re-scan confirms: all faults removed.")
            success = gcc_ok

        # ── BUILD RESULT ──
        fault_details = []
        for f in faults:
            fault_details.append({
                "fault_id":          f.fault_id,
                "file":              f.file_name,
                "line":              f.line_number,
                "statement":         f.faulty_statement,
                "operator":          f.operator,
                "type":              f.inferred_type,
                "can_overflow":      f.can_overflow,
                "can_underflow":     f.can_underflow,
            })

        result = PipelineResult(
            source_file=self.source_path,
            faults_found=len(faults),
            repairs_applied=len(faults),
            repaired_file=output_path,
            gcc_valid=gcc_ok,
            fault_details=fault_details,
            success=success,
        )

        logger.info("=" * 60)
        logger.info(f" INTREPAIR — Complete")
        logger.info(f"   Faults detected:  {result.faults_found}")
        logger.info(f"   Repaired file:    {result.repaired_file}")
        logger.info(f"   GCC valid:        {result.gcc_valid}")
        logger.info(f"   Success:          {result.success}")
        logger.info("=" * 60)

        return result


# ─────────────────────────────────────────────
# CLI ENTRYPOINT
# ─────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="INTREPAIR — Automatic Integer Overflow Repair for C"
    )
    ap.add_argument("source",        help="Path to C source file")
    ap.add_argument("--output", "-o", help="Path for repaired output file", default=None)
    ap.add_argument("--json",         help="Output results as JSON", action="store_true")
    ap.add_argument("--no-apply",     help="Detect only, do not apply repairs", action="store_true")
    args = ap.parse_args()

    pipeline = IntRepairPipeline(
        source_path=args.source,
        output_path=args.output,
        auto_apply=not args.no_apply,
    )

    result = pipeline.run()

    if args.json:
        print(result.to_json())
    else:
        sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
