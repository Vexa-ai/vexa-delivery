<!-- SPDX-License-Identifier: Apache-2.0 -->
# `empty/` — the cluster that answers nothing

Deliberately holds no fixture files. The fake `kubectl` exits non-zero for
every resource it has no fixture for, so this directory is a cluster where
every read is refused — the RBAC-too-narrow case.

The tool must still exit 0, still write an archive, and record each missing
source as **absent with a reason**. Absent over zero: a report that renders an
unreadable cluster as "no workloads" is worse than one that says it could not
look, because only one of the two is distinguishable from an empty namespace.
