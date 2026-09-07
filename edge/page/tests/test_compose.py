# SPDX-License-Identifier: Apache-2.0
"""The two compose files, read as data: the base publishes on the HOST's
loopback, and the override for a containerised Caddy adds a network alias and
nothing else. See edge/claim/tests/test_compose.py for why this is pinned."""

import pathlib
import unittest

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

HERE = pathlib.Path(__file__).resolve().parent.parent


@unittest.skipUnless(yaml, "PyYAML is not installed")
class Compose(unittest.TestCase):
    def load(self, name):
        return yaml.safe_load((HERE / name).read_text())

    def test_the_base_publishes_on_the_hosts_loopback_only(self):
        svc = self.load("compose.yaml")["services"]["page-edge"]
        self.assertEqual(svc["ports"], ["127.0.0.1:8089:8089"])

    def test_the_container_caddy_override_joins_the_stack_under_the_alias(self):
        doc = self.load("compose.caddy-container.yaml")
        svc = doc["services"]["page-edge"]
        (stack,) = [n for n in svc["networks"] if n != "default"]
        self.assertEqual(svc["networks"][stack]["aliases"], ["page-edge"])
        self.assertIs(doc["networks"][stack]["external"], True)
        self.assertIn("CHANNEL_STACK_NETWORK", doc["networks"][stack]["name"])
        self.assertIn("default", svc["networks"])
        self.assertEqual(set(svc), {"networks"})
        self.assertEqual(set(doc), {"services", "networks"})


if __name__ == "__main__":
    unittest.main()
