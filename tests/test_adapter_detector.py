"""Unit tests for automatic network adapter detection and multi-adapter support."""
import unittest
from unittest.mock import MagicMock, patch

from backend.network.adapter_detector import (
    NetworkAdapter,
    AdapterSelectionResult,
    _classify_adapter,
    _is_virtual_adapter,
    enumerate_windows_adapters,
    get_default_ipv4_routes,
    register_scapy_npcap_interface,
    select_network_adapter,
)
from backend.network.capture import PacketCapture, is_npcap_available


def make_dummy_adapter(
    name: str = "Wi-Fi",
    description: str = "Intel Wireless",
    guid: str = "{11111111-2222-3333-4444-555555555555}",
    adapter_type: str = "Wi-Fi",
    ips: list = None,
    index: int = 1,
    is_connected: bool = True,
    is_virtual: bool = False,
    is_loopback: bool = False,
    metric: int = 25,
) -> NetworkAdapter:
    ipv4s = ips or ["192.168.1.100"]
    return NetworkAdapter(
        name=name,
        description=description,
        guid=guid,
        npcap_name=f"\\Device\\NPF_{guid}",
        adapter_type=adapter_type,
        ipv4_addresses=ipv4s,
        mac_address="00:11:22:33:44:55",
        interface_index=index,
        is_connected=is_connected,
        is_virtual=is_virtual,
        is_loopback=is_loopback,
        ipv4_metric=metric,
    )


class AdapterDetectorTests(unittest.TestCase):

    def setUp(self):
        self.wifi_adapter = make_dummy_adapter(
            name="Wi-Fi",
            description="Intel(R) Dual Band Wireless-AC 8265",
            guid="{17AED3A9-905E-440B-8E34-9A930904ABE0}",
            adapter_type="Wi-Fi",
            ips=["192.168.1.3"],
            index=3,
            is_connected=True,
            metric=40,
        )
        self.eth_adapter = make_dummy_adapter(
            name="Ethernet",
            description="Intel(R) Ethernet Connection I219-LM",
            guid="{CF5384B7-C38C-4BBF-BC21-3B773E101B78}",
            adapter_type="Ethernet",
            ips=["192.168.1.150"],
            index=14,
            is_connected=True,
            metric=15,
        )
        self.loopback_adapter = make_dummy_adapter(
            name="Loopback Pseudo-Interface 1",
            description="Software Loopback Interface 1",
            guid="{1C225568-FAA8-11EF-841B-806E6F6E6963}",
            adapter_type="Loopback",
            ips=["127.0.0.1"],
            index=1,
            is_connected=False,
            is_loopback=True,
            metric=75,
        )
        self.virtual_adapter = make_dummy_adapter(
            name="Local Area Connection* 1",
            description="Microsoft Wi-Fi Direct Virtual Adapter",
            guid="{F66678BB-C0C4-44E1-99D7-09B81E41F667}",
            adapter_type="Virtual",
            ips=["169.254.11.104"],
            index=18,
            is_connected=False,
            is_virtual=True,
            metric=25,
        )

    def test_wifi_adapter_selection(self):
        """Wi-Fi only is connected with active default route."""
        adapters = [self.wifi_adapter, self.loopback_adapter, self.virtual_adapter]
        routes = [{"index": 3, "gateway": "192.168.1.1", "metric": 40}]

        res = select_network_adapter(adapters=adapters, default_routes=routes)
        self.assertEqual(res.selection_mode, "automatic_default_route")
        self.assertEqual(res.adapter_name, "Wi-Fi")
        self.assertEqual(res.adapter_type, "Wi-Fi")
        self.assertEqual(res.local_ip, "192.168.1.3")
        self.assertEqual(res.interface_id, r"\Device\NPF_{17AED3A9-905E-440B-8E34-9A930904ABE0}")
        self.assertTrue(res.is_automatic)
        self.assertIn("Wi-Fi", res.selection_reason)

    def test_ethernet_adapter_selection(self):
        """Ethernet only is connected with active default route."""
        adapters = [self.eth_adapter, self.loopback_adapter]
        routes = [{"index": 14, "gateway": "192.168.1.1", "metric": 15}]

        res = select_network_adapter(adapters=adapters, default_routes=routes)
        self.assertEqual(res.selection_mode, "automatic_default_route")
        self.assertEqual(res.adapter_name, "Ethernet")
        self.assertEqual(res.adapter_type, "Ethernet")
        self.assertEqual(res.local_ip, "192.168.1.150")
        self.assertEqual(res.interface_id, r"\Device\NPF_{CF5384B7-C38C-4BBF-BC21-3B773E101B78}")
        self.assertTrue(res.is_automatic)

    def test_explicit_network_interface_override(self):
        """Explicit NETWORK_INTERFACE takes precedence over automatic route detection."""
        adapters = [self.wifi_adapter, self.eth_adapter]
        routes = [{"index": 3, "gateway": "192.168.1.1", "metric": 10}]  # Wi-Fi has default route

        # Explicitly configure Ethernet
        res = select_network_adapter(
            explicit_network_interface="Ethernet",
            adapters=adapters,
            default_routes=routes,
        )
        self.assertEqual(res.selection_mode, "explicit_network_interface")
        self.assertEqual(res.adapter_name, "Ethernet")
        self.assertEqual(res.interface_id, r"\Device\NPF_{CF5384B7-C38C-4BBF-BC21-3B773E101B78}")
        self.assertFalse(res.is_automatic)

    def test_explicit_capture_interface_override(self):
        """Explicit CAPTURE_INTERFACE takes precedence when NETWORK_INTERFACE is unset."""
        adapters = [self.wifi_adapter, self.eth_adapter]
        routes = [{"index": 3, "gateway": "192.168.1.1", "metric": 10}]

        res = select_network_adapter(
            explicit_capture_interface=r"\Device\NPF_{CF5384B7-C38C-4BBF-BC21-3B773E101B78}",
            adapters=adapters,
            default_routes=routes,
        )
        self.assertEqual(res.selection_mode, "explicit_capture_interface")
        self.assertEqual(res.adapter_name, "Ethernet")
        self.assertFalse(res.is_automatic)

    def test_multiple_active_adapters_lowest_metric(self):
        """Both Wi-Fi and Ethernet are connected; selects adapter with lowest route metric."""
        adapters = [self.wifi_adapter, self.eth_adapter]
        routes = [
            {"index": 3, "gateway": "192.168.1.1", "metric": 45},   # Wi-Fi
            {"index": 14, "gateway": "192.168.1.1", "metric": 10},  # Ethernet (lower metric)
        ]

        res = select_network_adapter(adapters=adapters, default_routes=routes)
        self.assertEqual(res.selection_mode, "automatic_default_route")
        self.assertEqual(res.adapter_name, "Ethernet")
        self.assertEqual(res.local_ip, "192.168.1.150")

    def test_multiple_active_adapters_equal_metric(self):
        """Both Wi-Fi and Ethernet have equal route metric; Ethernet is preferred."""
        adapters = [self.wifi_adapter, self.eth_adapter]
        routes = [
            {"index": 3, "gateway": "192.168.1.1", "metric": 25},
            {"index": 14, "gateway": "192.168.1.1", "metric": 25},
        ]

        res = select_network_adapter(adapters=adapters, default_routes=routes)
        self.assertEqual(res.selection_mode, "automatic_default_route")
        self.assertEqual(res.adapter_name, "Ethernet")

    def test_no_active_adapter(self):
        """No connected adapter exists (all disconnected or virtual/loopback)."""
        disconnected_eth = make_dummy_adapter(
            name="Ethernet",
            ips=["169.254.10.10"],
            is_connected=False,
        )
        adapters = [disconnected_eth, self.loopback_adapter, self.virtual_adapter]
        routes = []

        res = select_network_adapter(adapters=adapters, default_routes=routes)
        self.assertEqual(res.selection_mode, "none")
        self.assertIsNone(res.interface_id)
        self.assertIsNotNone(res.error)
        self.assertIn("No active physical", res.error)

    def test_adapter_disconnection_fallback_to_other(self):
        """Default route is missing, but a physical connected adapter is available on local subnet."""
        adapters = [self.wifi_adapter, self.loopback_adapter]
        routes = []  # No default route (offline router or ad-hoc)

        res = select_network_adapter(adapters=adapters, default_routes=routes)
        self.assertEqual(res.selection_mode, "fallback")
        self.assertEqual(res.adapter_name, "Wi-Fi")
        self.assertEqual(res.local_ip, "192.168.1.3")
        self.assertIn("Fallback", res.selection_reason)

    def test_correct_npcap_guid_mapping(self):
        """Correctly maps adapter GUID into \\Device\\NPF_{GUID} format."""
        guid = "{ABCD1234-5678-90EF-1234-567890ABCDEF}"
        adapter = make_dummy_adapter(name="Special LAN", guid=guid, index=99)
        routes = [{"index": 99, "gateway": "10.0.0.1", "metric": 5}]

        res = select_network_adapter(adapters=[adapter], default_routes=routes)
        self.assertEqual(res.interface_id, f"\\Device\\NPF_{guid}")

    def test_virtual_and_loopback_adapters_excluded_from_default_route(self):
        """Virtual adapters and loopback are never selected as automatic default-route interfaces."""
        adapters = [self.loopback_adapter, self.virtual_adapter]
        routes = [
            {"index": 1, "gateway": "127.0.0.1", "metric": 1},   # Loopback
            {"index": 18, "gateway": "169.254.1.1", "metric": 5}, # Virtual Wi-Fi Direct
        ]

        res = select_network_adapter(adapters=adapters, default_routes=routes)
        self.assertEqual(res.selection_mode, "none")
        self.assertIsNone(res.interface_id)

    def test_virtual_adapter_classification(self):
        """Detects virtual adapters, Hyper-V, VMware, VirtualBox, WSL, and filters."""
        self.assertTrue(_is_virtual_adapter("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet"))
        self.assertTrue(_is_virtual_adapter("Ethernet 2", "VirtualBox Host-Only Ethernet Adapter"))
        self.assertTrue(_is_virtual_adapter("VMware Network Adapter VMnet1", "VMware Virtual Ethernet"))
        self.assertTrue(_is_virtual_adapter("OpenVPN TAP", "TAP-Windows Adapter V9"))
        self.assertTrue(_is_virtual_adapter("Local Area Connection* 1", "Microsoft Wi-Fi Direct Virtual Adapter"))
        self.assertFalse(_is_virtual_adapter("Wi-Fi", "Intel(R) Dual Band Wireless-AC 8265"))
        self.assertFalse(_is_virtual_adapter("Ethernet", "Intel(R) Ethernet Connection (4) I219-LM"))

    def test_actual_host_detection(self):
        """Tests actual adapter detection on the host machine running this test."""
        adapters = enumerate_windows_adapters()
        self.assertIsInstance(adapters, list)
        self.assertGreater(len(adapters), 0, "Host should have at least one network adapter.")

        routes = get_default_ipv4_routes()
        self.assertIsInstance(routes, list)

        res = select_network_adapter(adapters=adapters, default_routes=routes)
        self.assertIsInstance(res, AdapterSelectionResult)
        # On this machine, Wi-Fi is active and should be selected
        if routes:
            self.assertEqual(res.selection_mode, "automatic_default_route")
            self.assertIsNotNone(res.interface_id)
            self.assertTrue(res.interface_id.startswith(r"\Device\NPF_"))
            self.assertIsNotNone(res.local_ip)

    def test_packet_capture_missing_npcap_handling(self):
        """PacketCapture gracefully handles missing Npcap without crashing."""
        with patch("backend.network.capture.is_npcap_available", return_value=False):
            handler = MagicMock()
            cap = PacketCapture(handler=handler)
            cap.start()
            self.assertEqual(cap.status, "unavailable")
            self.assertIn("Npcap packet capture driver is not installed", cap.error)
            self.assertIsNone(cap._thread)

    def test_packet_capture_no_duplicate_threads(self):
        """Calling start() multiple times does not leak duplicate capture worker threads."""
        handler = MagicMock()
        cap = PacketCapture(handler=handler)
        # Mock thread to simulate running state
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        cap._thread = mock_thread

        with patch.object(cap, "stop") as mock_stop:
            with patch("backend.network.capture.is_npcap_available", return_value=False):
                cap.start()
                mock_stop.assert_called_once()

    def test_stop_retains_thread_reference_on_hung_worker_timeout(self):
        """PacketCapture.stop() retains thread reference and flags error if worker fails to terminate."""
        handler = MagicMock()
        cap = PacketCapture(handler=handler)

        mock_hung_thread = MagicMock()
        mock_hung_thread.name = "scapy-capture-hung"
        mock_hung_thread.is_alive.return_value = True  # Worker refuses to die
        cap._thread = mock_hung_thread

        stopped = cap.stop(timeout=0.05)
        self.assertFalse(stopped, "stop() must return False when worker fails to terminate within timeout.")
        self.assertIs(cap._thread, mock_hung_thread, "Must NOT discard reference to still-running worker thread.")
        self.assertEqual(cap.status, "unavailable")
        self.assertIn("failed to terminate within 0.05s timeout", cap.error)

    def test_start_refuses_restart_when_worker_is_hung(self):
        """PacketCapture.start() refuses to spawn a second worker if previous thread remains alive."""
        handler = MagicMock()
        cap = PacketCapture(handler=handler)

        mock_hung_thread = MagicMock()
        mock_hung_thread.name = "scapy-capture-hung"
        mock_hung_thread.is_alive.return_value = True
        cap._thread = mock_hung_thread

        with patch.object(cap, "stop", return_value=False):
            started = cap.start()
            self.assertFalse(started, "start() must return False when previous worker is still active.")
            self.assertIs(cap._thread, mock_hung_thread, "Original hung thread reference must be preserved.")
            self.assertIn("previous capture worker thread is still active", cap.error)
            self.assertEqual(cap.status, "unavailable")

    def test_reconfigure_refuses_when_worker_is_hung(self):
        """reconfigure() respects the same lifecycle guarantee and refuses if worker remains alive."""
        handler = MagicMock()
        cap = PacketCapture(handler=handler)

        mock_hung_thread = MagicMock()
        mock_hung_thread.is_alive.return_value = True
        cap._thread = mock_hung_thread

        with patch.object(cap, "stop", return_value=False):
            reconfigured = cap.reconfigure("Ethernet")
            self.assertFalse(reconfigured, "reconfigure() must fail if previous worker cannot be stopped.")
            self.assertIs(cap._thread, mock_hung_thread)
            self.assertIn("previous capture worker thread failed to terminate", cap.error)

    def test_repeated_stop_and_start_safe(self):
        """Repeated stop() calls are safe on idle capture instances."""
        handler = MagicMock()
        cap = PacketCapture(handler=handler)
        self.assertIsNone(cap._thread)
        self.assertTrue(cap.stop())
        self.assertTrue(cap.stop())  # Second call safe
        self.assertIsNone(cap._thread)

    def test_concurrent_start_calls_create_only_one_worker(self):
        """Invoking start() concurrently from multiple threads spawns exactly one worker thread."""
        import threading, time
        handler = MagicMock()
        cap = PacketCapture(handler=handler)
        cap.interface = r"\Device\NPF_{TEST-INTERFACE-GUID}"

        thread_spawn_count = 0
        original_thread_cls = threading.Thread

        def counting_thread(*args, **kwargs):
            nonlocal thread_spawn_count
            thread_spawn_count += 1
            def dummy_worker():
                cap.status = "running"
                while not cap._stop.is_set():
                    time.sleep(0.01)
            kwargs["target"] = dummy_worker
            return original_thread_cls(*args, **kwargs)

        with patch("backend.network.capture.is_npcap_available", return_value=True):
            with patch("threading.Thread", side_effect=counting_thread):
                barrier = threading.Barrier(10)
                results = []

                def concurrent_start():
                    barrier.wait()
                    res = cap.start()
                    results.append(res)

                threads = [original_thread_cls(target=concurrent_start) for _ in range(10)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

                self.assertEqual(thread_spawn_count, 1, "Exactly one worker thread should be spawned.")
                self.assertTrue(all(results), "All concurrent start() calls should succeed.")
                self.assertIsNotNone(cap._thread)
                self.assertTrue(cap._thread.is_alive())

                stopped = cap.stop(timeout=1.0)
                self.assertTrue(stopped)
                self.assertIsNone(cap._thread)


if __name__ == "__main__":
    unittest.main()

