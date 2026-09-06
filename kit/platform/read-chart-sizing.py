#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read the delivered chart's own resource figures out of a values.yaml.

kit/platform/chart-sizing.env carries these numbers as a RECORD, because the
platform pack is rendered where the Vexa chart source is not present. This is
the other half: point it at a real values.yaml and it recomputes every line,
so the record can be refreshed — and checked — rather than trusted.

    python3 read-chart-sizing.py <values.yaml>

Prints the same KEY=VALUE lines chart-sizing.env holds, on stdout, so
render.sh can `source` either one. Exit 0, or 1 with the reason.

What it counts, and why each term is there:

  every `resources.limits` / `resources.requests` block anywhere in the values
  tree                       the containers the chart declares. The MAXIMUM of
                             the memory limits is the LimitRange ceiling — the
                             number a project must clear or the delivered set
                             is refused at admission, which is what happened to
                             postgres (4Gi) against a 2560Mi ceiling on
                             2026-09-04.

  runtime.workloadResources  the Pods the runtime SPAWNS at meeting and
                             dispatch time. They are NOT in the chart's own
                             container list, and runtime.v1 carries one value
                             per dimension which is both the request and the
                             limit (Guaranteed QoS). A quota that forgets them
                             refuses the meeting, not the install.
"""

from __future__ import annotations

import math
import re
import sys

try:
    import yaml
except ImportError:                                          # pragma: no cover
    print("read-chart-sizing: needs PyYAML (pip install pyyaml), or drop "
          "--chart-values and use the recorded kit/platform/chart-sizing.env",
          file=sys.stderr)
    raise SystemExit(1)

MEM_UNITS = {"": 1 / 1048576, "Ki": 1 / 1024, "Mi": 1, "Gi": 1024, "Ti": 1048576,
             "K": 1000 / 1048576, "M": 1000000 / 1048576, "G": 1000000000 / 1048576}


def mebibytes(value) -> int:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([KMGT]i?)?", str(value).strip())
    if not m:
        raise ValueError(f"unparseable memory quantity {value!r}")
    return math.ceil(float(m.group(1)) * MEM_UNITS[m.group(2) or ""])


def millicores(value) -> int:
    text = str(value).strip()
    if text.endswith("m"):
        return int(text[:-1])
    return int(float(text) * 1000)


def containers(node, path=()):
    """Every {requests, limits} pair in the tree, with the key that owns it."""
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, dict) and isinstance(value.get("limits"), dict):
                yield ".".join(path + (str(key),)), value.get("requests") or {}, value["limits"]
            yield from containers(value, path + (str(key),))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from containers(value, path + (str(index),))


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    values = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}

    found = list(containers(values))
    if not found:
        print(f"read-chart-sizing: {sys.argv[1]} declares no resources blocks — "
              f"is it a Vexa chart values.yaml?", file=sys.stderr)
        return 1

    biggest = max(found, key=lambda row: mebibytes(row[2]["memory"]))
    spawned = (values.get("runtime") or {}).get("workloadResources") or {}
    bot = spawned.get("meetingBot") or {}
    worker = spawned.get("agentWorker") or {}

    print(f"CHART_MAX_CONTAINER_MEMORY={biggest[2]['memory']}")
    print(f"CHART_MAX_CONTAINER_NAME={biggest[0].split('.')[0]}")
    print(f"CHART_CONTAINERS={len(found)}")
    print(f"CHART_SUM_LIMITS_MEMORY_MI={sum(mebibytes(r[2]['memory']) for r in found)}")
    print(f"CHART_SUM_REQUESTS_MEMORY_MI={sum(mebibytes(r[1].get('memory', 0)) for r in found)}")
    print(f"CHART_SUM_LIMITS_CPU_M={sum(millicores(r[2]['cpu']) for r in found)}")
    print(f"CHART_SUM_REQUESTS_CPU_M={sum(millicores(r[1].get('cpu', 0)) for r in found)}")
    # PVCs are declared in templates, not in values — there is nothing here to
    # count, so the recorded figure stands and says so.
    print(f"CHART_SPAWNED_BOT_MEMORY_MI={int(bot.get('memoryMb') or 0)}")
    print(f"CHART_SPAWNED_BOT_CPU_M={millicores(bot.get('cpu') or 0)}")
    print(f"CHART_SPAWNED_WORKER_MEMORY_MI={int(worker.get('memoryMb') or 0)}")
    print(f"CHART_SPAWNED_WORKER_CPU_M={millicores(worker.get('cpu') or 0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
