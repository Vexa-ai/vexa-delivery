<!-- SPDX-License-Identifier: Apache-2.0 -->
# `openshift-locked-down/` — OpenShift, and almost nothing granted

Holds one fixture file: the cluster version, which answers as OpenShift. Every
other read is refused, `routes.route.openshift.io` among them.

It exists for one sentence in the report. On plain Kubernetes an unreadable
Route list means the kind is not there; on OpenShift it means a grant is
missing and the estate is almost certainly exposed by a Route we cannot see.
The two are indistinguishable from the read alone, so the tool uses the one
other fact it has — whether the cluster answered as OpenShift — and says which
of the two it is looking at. Getting this wrong in the OpenShift direction is
the expensive one: it reports, positively, that nothing is exposed.
