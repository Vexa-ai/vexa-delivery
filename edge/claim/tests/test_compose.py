# SPDX-License-Identifier: Apache-2.0
"""The two compose files: the base publishes on the HOST's loopback, and the
override for a containerised Caddy adds a network alias and nothing else.

Read as data, not run — there is no Docker in CI. What can go wrong in these
files is structural and this is where it is pinned: an override that also set
an image or a mount would silently replace the base's, and an alias that
drifted from the name the Caddyfile proxies to would be the 2026-09-06 502 with
one more step.
"""

import pathlib
import unittest

try:
    import yaml
except ImportError:  # pragma: no cover - the publisher's tests already need it
    yaml = None

HERE = pathlib.Path(__file__).resolve().parent.parent


@unittest.skipUnless(yaml, "PyYAML is not installed")
class Compose(unittest.TestCase):
    def load(self, name):
        return yaml.safe_load((HERE / name).read_text())

    def test_the_base_publishes_on_the_hosts_loopback_only(self):
        svc = self.load("compose.yaml")["services"]["claim-edge"]
        self.assertEqual(svc["ports"], ["127.0.0.1:8088:8088"])
        # The probe's default URL rides the same variable the publisher parks
        # against, so there is one value for "where subscribers post".
        self.assertEqual(svc["environment"]["CLAIM_PUBLIC_URL"],
                         "${CHANNEL_CLAIM_EDGE:-}")

    def test_the_container_caddy_override_joins_the_stack_under_the_alias(self):
        doc = self.load("compose.caddy-container.yaml")
        svc = doc["services"]["claim-edge"]
        (stack,) = [n for n in svc["networks"] if n != "default"]
        # The alias IS the upstream name in the Caddyfile (`claim-edge:8088`).
        self.assertEqual(svc["networks"][stack]["aliases"], ["claim-edge"])
        # It joins the registry stack's network; it never creates one.
        self.assertIs(doc["networks"][stack]["external"], True)
        self.assertIn("CHANNEL_STACK_NETWORK", doc["networks"][stack]["name"])
        # It keeps the base project's own network, so the loopback publish holds.
        self.assertIn("default", svc["networks"])
        # A network and NOTHING else. An override that named an image or a
        # volume would replace the base file's, unnoticed.
        self.assertEqual(set(svc), {"networks"})
        self.assertEqual(set(doc), {"services", "networks"})


if __name__ == "__main__":
    unittest.main()
