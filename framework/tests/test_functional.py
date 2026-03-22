"""Tests for functional test suite.

All tests use mocked ScapyEngine / IPerf3Engine — no real SSH or network.
"""

from __future__ import annotations

import importlib
import sys
import types
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# When paramiko has been replaced by a stub (e.g. by test_scapy_engine.py),
# netmiko cannot import paramiko.ssh_exception.  Restore real paramiko so
# the full import chain (functional → cisco_snmp → netmiko → paramiko) works.
_paramiko_mod = sys.modules.get("paramiko")
if _paramiko_mod is not None and not hasattr(_paramiko_mod, "__file__"):
    del sys.modules["paramiko"]
    for key in [k for k in sys.modules if k.startswith("paramiko.")]:
        del sys.modules[key]

from framework.tests.functional import (
    FunctionalTestConfig,
    FunctionalTestError,
    SwitchSSHConfig,
    acl_enforcement,
    dot1q_tagging,
    jumbo_frames,
    mac_learning,
    stp_convergence,
    vlan_isolation,
)
from framework.traffic.scapy_engine import ScapyEngine


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

_CAPTURE_BASE: dict[str, Any] = {
    "status": "ok",
    "interface": "eth0",
    "timeout_sec": 5.0,
    "filter": None,
    "expected_vlan": None,
    "frames_received": 1,
    "timestamps": ["2026-01-01T00:00:00+00:00"],
    "src_macs": ["00:00:00:00:00:01"],
    "dst_macs": ["00:00:00:00:00:02"],
    "vlan_tags_observed": [],
    "vlan_match_count": 0,
    "vlan_mismatch_count": 0,
    "packets": [
        {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "len_bytes": 128,
            "src_mac": "00:00:00:00:00:01",
            "dst_mac": "00:00:00:00:00:02",
            "src_ip": "172.16.0.1",
            "dst_ip": "172.16.0.2",
            "ip_version": "ipv4",
            "protocol": "udp",
            "sport": 12345,
            "dport": 80,
            "vlan_tags": [],
        }
    ],
    "capture_start_ts": "2026-01-01T00:00:00+00:00",
    "capture_end_ts": "2026-01-01T00:00:01+00:00",
    "timestamp": "2026-01-01T00:00:01+00:00",
}


def _send_and_capture_result(**capture_overrides: Any) -> dict[str, Any]:
    """Build a fake ``send_and_capture`` return dict."""
    capture = {**_CAPTURE_BASE, **capture_overrides}
    return {
        "status": "ok",
        "method": "send_and_capture",
        "timestamp": "2026-01-01T00:00:01+00:00",
        "capture_started_at": "2026-01-01T00:00:00+00:00",
        "send_started_at": "2026-01-01T00:00:00+00:00",
        "rtt_ms": 0.5,
        "generator_host": "10.0.0.11",
        "analyzer_host": "10.0.0.12",
        "send_result": {"status": "ok"},
        "capture_result": capture,
    }


def _make_scapy_engine(**method_results: Any) -> MagicMock:
    """Build a mock ScapyEngine with per-method return values."""
    engine = MagicMock(spec=ScapyEngine)
    for method, retval in method_results.items():
        getattr(engine, method).return_value = retval
    return engine


# ---------------------------------------------------------------------------
# Test 1 — VLAN Isolation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("vlan_match_count", "expected_pass"),
    [(0, True), (1, False), (5, False)],
    ids=["isolated", "leak-1", "leak-5"],
)
def test_vlan_isolation(vlan_match_count: int, expected_pass: bool) -> None:
    engine = MagicMock(spec=ScapyEngine)
    engine.check_vlan_isolation.return_value = {
        "status": "pass" if vlan_match_count == 0 else "fail",
        "method": "check_vlan_isolation",
        "timestamp": "2026-01-01T00:00:01+00:00",
        "sent_vlan": 10,
        "expected_vlan": 20,
        "frames_received": vlan_match_count,
        "vlan_match_count": vlan_match_count,
        "vlan_mismatch_count": 0,
        "evidence": _send_and_capture_result(),
    }

    result = vlan_isolation(engine)

    assert result["test"] == "vlan_isolation"
    assert result["passed"] is expected_pass
    assert result["details"]["sent_vlan"] == 10
    assert result["details"]["expected_vlan"] == 20
    engine.check_vlan_isolation.assert_called_once()


# ---------------------------------------------------------------------------
# Test 2 — MAC Learning
# ---------------------------------------------------------------------------


def _mac_table_result(entries: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "host": "10.0.0.2",
        "command": "show mac address-table",
        "raw": "",
        "entries": entries,
    }


def test_mac_learning_pass() -> None:
    burst = _send_and_capture_result()
    verify = _send_and_capture_result(frames_received=1)
    engine = _make_scapy_engine(send_burst=burst, send_and_capture=verify)
    switch_ssh = SwitchSSHConfig(host="10.0.0.2", username="u", password="p")

    mac_table = _mac_table_result(
        [
            {
                "vlan": "10",
                "mac": "0000.0000.0001",
                "type": "DYNAMIC",
                "ports": "Gi1/0/5",
            },
        ]
    )

    with patch(
        "framework.tests.functional.get_mac_address_table_ssh",
        return_value=mac_table,
    ):
        result = mac_learning(engine, switch_ssh)

    assert result["test"] == "mac_learning"
    assert result["passed"] is True
    assert result["details"]["mac_found_in_table"] is True
    assert result["details"]["mac_on_correct_port"] is True


def test_mac_learning_wrong_port() -> None:
    burst = _send_and_capture_result()
    verify = _send_and_capture_result(frames_received=1)
    engine = _make_scapy_engine(send_burst=burst, send_and_capture=verify)
    switch_ssh = SwitchSSHConfig(host="10.0.0.2", username="u", password="p")

    mac_table = _mac_table_result(
        [
            {
                "vlan": "10",
                "mac": "0000.0000.0001",
                "type": "DYNAMIC",
                "ports": "Gi1/0/9",
            },
        ]
    )

    with patch(
        "framework.tests.functional.get_mac_address_table_ssh",
        return_value=mac_table,
    ):
        result = mac_learning(engine, switch_ssh)

    assert result["passed"] is False
    assert result["details"]["mac_on_correct_port"] is False


def test_mac_learning_mac_not_found() -> None:
    burst = _send_and_capture_result()
    verify = _send_and_capture_result(frames_received=1)
    engine = _make_scapy_engine(send_burst=burst, send_and_capture=verify)
    switch_ssh = SwitchSSHConfig(host="10.0.0.2", username="u", password="p")

    mac_table = _mac_table_result([])

    with patch(
        "framework.tests.functional.get_mac_address_table_ssh",
        return_value=mac_table,
    ):
        result = mac_learning(engine, switch_ssh)

    assert result["passed"] is False
    assert result["details"]["mac_found_in_table"] is False


# ---------------------------------------------------------------------------
# Test 3 — Jumbo Frames
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pkt_len", "expected_pass"),
    [(9000, True), (8500, True), (1518, False)],
    ids=["9000B", "8500B", "1518B-fail"],
)
def test_jumbo_frames(pkt_len: int, expected_pass: bool) -> None:
    packets = [{**_CAPTURE_BASE["packets"][0], "len_bytes": pkt_len}]
    capture = _send_and_capture_result(frames_received=1, packets=packets)
    engine = _make_scapy_engine(send_and_capture=capture)

    result = jumbo_frames(engine)

    assert result["test"] == "jumbo_frames"
    assert result["passed"] is expected_pass
    assert result["details"]["max_len_bytes"] == pkt_len


def test_jumbo_frames_no_packets() -> None:
    capture = _send_and_capture_result(frames_received=0, packets=[])
    engine = _make_scapy_engine(send_and_capture=capture)

    result = jumbo_frames(engine)

    assert result["passed"] is False
    assert result["details"]["jumbo_received"] is False


# ---------------------------------------------------------------------------
# Test 4 — 802.1Q Tagging
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("observed_vlans", "expect_on_wire", "expected_pass"),
    [
        ([10], True, True),
        ([], True, False),
        ([10], False, False),
        ([], False, True),
    ],
    ids=["trunk-present", "trunk-missing", "access-present", "access-stripped"],
)
def test_dot1q_tagging(
    observed_vlans: list[int],
    expect_on_wire: bool,
    expected_pass: bool,
) -> None:
    packets = [{**_CAPTURE_BASE["packets"][0], "vlan_tags": observed_vlans}]
    capture = _send_and_capture_result(
        frames_received=1,
        vlan_tags_observed=observed_vlans,
        packets=packets,
    )
    engine = _make_scapy_engine(send_and_capture=capture)
    cfg = FunctionalTestConfig(dot1q_vlan=10, expect_tag_on_wire=expect_on_wire)

    result = dot1q_tagging(engine, config=cfg)

    assert result["test"] == "dot1q_tagging"
    assert result["passed"] is expected_pass
    assert result["details"]["sent_vlan"] == 10


# ---------------------------------------------------------------------------
# Test 5 — STP Convergence
# ---------------------------------------------------------------------------


def test_stp_convergence_fast() -> None:
    """Converges quickly — should pass."""
    iperf_engine = MagicMock()
    iperf_engine.run_udp.return_value = {
        "bitrate_bps": 100_000_000,
        "lost_percent": 0.0,
        "lost_packets": 0,
        "jitter_ms": 0.01,
        "duration_sec": 2.0,
        "protocol": "udp",
        "requested_bitrate": "100M",
        "retransmits": 0,
        "timestamp": "2026-01-01T00:00:00+00:00",
    }

    call_count = 0

    def fake_poll(
        switch_ip: str, community: str, interface: str, **kw: Any
    ) -> dict[str, Any]:
        nonlocal call_count
        call_count += 1
        # First call (before): low TX; subsequent calls: TX jumps
        return {
            "switch_ip": switch_ip,
            "interface": interface,
            "if_index": 5,
            "rx_packets": 1000,
            "tx_packets": 1000 if call_count <= 2 else 1500,
            "rx_errors": 0,
            "tx_errors": 0,
            "rx_discards": 0,
            "tx_discards": 0,
            "rx_octets": 0,
            "tx_octets": 0,
        }

    from framework.tests.rfc2544 import TelemetryConfig

    telem = TelemetryConfig(switch_ip="10.0.0.2", community="test", interface="Gi1/0/5")
    cfg = FunctionalTestConfig(stp_threshold_sec=5.0, stp_poll_interval_sec=0.01)

    with (
        patch(
            "framework.tests.functional.poll_interface_counters", side_effect=fake_poll
        ),
        patch("framework.tests.rfc2544.poll_interface_counters", side_effect=fake_poll),
    ):
        result = stp_convergence(
            iperf_engine,
            "172.16.0.2",
            on_link_failure=lambda: None,
            config=cfg,
            telemetry=telem,
        )

    assert result["test"] == "stp_convergence"
    assert result["passed"] is True
    assert result["details"]["converged"] is True


def test_stp_convergence_requires_telemetry() -> None:
    iperf_engine = MagicMock()
    iperf_engine.run_udp.return_value = {
        "bitrate_bps": 100_000_000,
        "lost_percent": 0.0,
        "lost_packets": 0,
        "jitter_ms": 0.01,
        "duration_sec": 2.0,
        "protocol": "udp",
        "requested_bitrate": "100M",
        "retransmits": 0,
        "timestamp": "2026-01-01T00:00:00+00:00",
    }

    with pytest.raises(FunctionalTestError, match="TelemetryConfig"):
        stp_convergence(
            iperf_engine,
            "172.16.0.2",
            on_link_failure=lambda: None,
            telemetry=None,
        )


# ---------------------------------------------------------------------------
# Test 6 — ACL Enforcement
# ---------------------------------------------------------------------------


def test_acl_permit_and_deny() -> None:
    """Permit traffic arrives, deny traffic blocked."""
    permit_capture = _send_and_capture_result(frames_received=1)
    deny_capture = _send_and_capture_result(frames_received=0, packets=[])

    engine = MagicMock(spec=ScapyEngine)
    engine.send_and_capture.side_effect = [permit_capture, deny_capture]

    result = acl_enforcement(engine)

    assert result["test"] == "acl_enforcement"
    assert result["passed"] is True
    assert result["details"]["permit_received"] is True
    assert result["details"]["deny_blocked"] is True
    assert result["details"]["ansible_configured"] is False


def test_acl_permit_blocked_fails() -> None:
    """If permit traffic is blocked, test should fail."""
    permit_capture = _send_and_capture_result(frames_received=0, packets=[])
    deny_capture = _send_and_capture_result(frames_received=0, packets=[])

    engine = MagicMock(spec=ScapyEngine)
    engine.send_and_capture.side_effect = [permit_capture, deny_capture]

    result = acl_enforcement(engine)

    assert result["passed"] is False
    assert result["details"]["permit_received"] is False


def test_acl_deny_not_blocked_fails() -> None:
    """If denied traffic leaks through, test should fail."""
    permit_capture = _send_and_capture_result(frames_received=1)
    deny_capture = _send_and_capture_result(frames_received=1)

    engine = MagicMock(spec=ScapyEngine)
    engine.send_and_capture.side_effect = [permit_capture, deny_capture]

    result = acl_enforcement(engine)

    assert result["passed"] is False
    assert result["details"]["deny_blocked"] is False


# ---------------------------------------------------------------------------
# Unified result shape
# ---------------------------------------------------------------------------

_REQUIRED_KEYS = {
    "test",
    "passed",
    "timestamp",
    "duration_sec",
    "switch_counter_delta",
    "details",
    "evidence",
}


@pytest.mark.parametrize(
    "run_test",
    [
        lambda: vlan_isolation(
            _make_scapy_engine(
                check_vlan_isolation={
                    "status": "pass",
                    "method": "check_vlan_isolation",
                    "timestamp": "T",
                    "sent_vlan": 10,
                    "expected_vlan": 20,
                    "frames_received": 0,
                    "vlan_match_count": 0,
                    "vlan_mismatch_count": 0,
                    "evidence": _send_and_capture_result(),
                }
            ),
        ),
        lambda: jumbo_frames(
            _make_scapy_engine(
                send_and_capture=_send_and_capture_result(
                    frames_received=1,
                    packets=[{**_CAPTURE_BASE["packets"][0], "len_bytes": 9000}],
                )
            ),
        ),
        lambda: dot1q_tagging(
            _make_scapy_engine(
                send_and_capture=_send_and_capture_result(
                    frames_received=1,
                    vlan_tags_observed=[10],
                )
            ),
        ),
    ],
    ids=["vlan_isolation", "jumbo_frames", "dot1q_tagging"],
)
def test_unified_result_shape(run_test: Any) -> None:
    result = run_test()
    assert _REQUIRED_KEYS.issubset(result.keys())
    assert isinstance(result["passed"], bool)
    assert isinstance(result["duration_sec"], float)
