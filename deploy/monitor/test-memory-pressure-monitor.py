#!/usr/bin/env python3
import importlib.util
import os
import tempfile
import unittest


HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location(
    "memory_pressure_monitor", os.path.join(HERE, "memory-pressure-monitor.py")
)
MONITOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MONITOR)


class MemoryPressureMonitorTests(unittest.TestCase):
    def test_fine_first_breach_sustained_breach_and_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            old_state = MONITOR.STATE_FILE
            old_send = MONITOR.send_alert
            MONITOR.STATE_FILE = os.path.join(temp, "state.json")
            alerts = []
            MONITOR.send_alert = lambda subject, text: alerts.append((subject, text)) or (True, "stub")
            try:
                fine = {"available_mb": 2013, "swap_free_mb": 1134, "consumers": [], "build_running": False}
                danger = {"available_mb": 851, "swap_free_mb": 776, "consumers": ["rustc[7] 1200 MiB"], "build_running": True}
                self.assertEqual(MONITOR.main(lambda: fine), 0)
                self.assertEqual(MONITOR.main(lambda: danger), 0)
                self.assertEqual(MONITOR.main(lambda: danger), 1)
                self.assertEqual(MONITOR.main(lambda: fine), 0)
                self.assertEqual([subject for subject, _ in alerts], [
                    "[filament] sustained memory pressure",
                    "[filament] memory pressure RECOVERED",
                ])
                self.assertIn("cargo/rustc detected", alerts[0][1])
                self.assertIn("rustc[7] 1200 MiB", alerts[0][1])
            finally:
                MONITOR.STATE_FILE = old_state
                MONITOR.send_alert = old_send


if __name__ == "__main__":
    unittest.main()
