import copy
import json
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler

from framework.lab_secrets import load_lab_secrets
from framework.tests.rfc2544 import (
    TelemetryConfig,
    back_to_back,
    frame_loss,
    latency,
    RFC2544Config,
    throughput,
)
from framework.traffic.iperf3_engine import IPerf3Engine
from framework.tests.functional import (
    acl_enforcement,
    vlan_isolation,
    mac_learning,
    jumbo_frames,
    dot1q_tagging,
    stp_convergence,
    FunctionalTestConfig,
)
from framework.traffic.scapy_engine import ScapyEngine


def on_link_failure() -> None:
    lab_secrets = load_lab_secrets()

    # Netmiko into device and shutdown interface then no shutdown to restore
    device = {
        "device_type": "cisco_ios",
        "host": "10.0.0.2",
        "username": lab_secrets.username,
        "password": lab_secrets.password,
        "port": 22,
    }
    with ConnectHandler(**device) as conn:
        conn.enable()
        cmds = [
            "interface GigabitEthernet1/0/5",
            "shutdown",
        ]
        conn.send_config_set(cmds)
        cmds = [
            "interface GigabitEthernet1/0/5",
            "no shutdown",
        ]
        conn.send_config_set(cmds)


def save_result(result: dict, path: str):
    clean = copy.deepcopy(result)
    for item in clean.get("evidence", []):
        if "raw_json" in item:
            item.pop("raw_json", None)
    with open(path, "w") as f:
        json.dump(clean, f, indent=2)


def run_rfc2544_tests(engine: IPerf3Engine, config: RFC2544Config) -> None:
    # Get time in format yyyy-mm-dd-hh-mm
    time = datetime.now().strftime("%Y-%m-%d-%H-%M")

    # ----- Throughput test -----
    print("Running throughput test...")
    throughput_result = throughput(engine, "172.16.0.2", config=config)

    throughput_result_file = Path(f"results/{time}_throughput.json")
    save_result(throughput_result, throughput_result_file)

    # ----- Latency test -----
    print("Running latency test...")
    # throughput_result ={"details": {"zero_loss_bitrate_bps": 800_000_000}}
    latency_result = latency(
        engine,
        "172.16.0.2",
        throughput_bps=throughput_result["details"]["zero_loss_bitrate_bps"],
        config=config,
    )
    latency_result_file = Path(f"results/{time}_latency.json")
    save_result(latency_result, latency_result_file)

    # ----- Frame loss test -----
    print("Running frame loss test...")
    frame_loss_result = frame_loss(engine, "172.16.0.2", config=config)
    frame_loss_result_file = Path(f"results/{time}_frame_loss.json")
    save_result(frame_loss_result, frame_loss_result_file)

    # ----- Back-to-back test -----
    print("Running back-to-back test...")
    back_to_back_result = back_to_back(engine, "172.16.0.2", config=config)
    back_to_back_result_file = Path(f"results/{time}_back_to_back.json")
    save_result(back_to_back_result, back_to_back_result_file)


def run_functional_tests(
    engine: ScapyEngine, iperf3_engine: IPerf3Engine, config: FunctionalTestConfig
) -> None:
    # Get time in format yyyy-mm-dd-hh-mm
    time = datetime.now().strftime("%Y-%m-%d-%H-%M")

    # ----- VLAN Isolation test -----
    print("Running VLAN Isolation test...")
    vlan_isolation_result = vlan_isolation(engine, config)
    vlan_isolation_result_file = Path(f"results/{time}_vlan_isolation.json")
    save_result(vlan_isolation_result, vlan_isolation_result_file)

    # ----- MAC Learning test -----
    print("Running MAC Learning test...")
    mac_learning_result = mac_learning(engine, config)
    mac_learning_result_file = Path(f"results/{time}_mac_learning.json")
    save_result(mac_learning_result, mac_learning_result_file)

    # ----- Jumbo Frames test -----
    print("Running Jumbo Frames test...")
    jumbo_frames_result = jumbo_frames(engine, config)
    jumbo_frames_result_file = Path(f"results/{time}_jumbo_frames.json")
    save_result(jumbo_frames_result, jumbo_frames_result_file)

    # ----- 802.1Q Tagging test -----
    print("Running 802.1Q Tagging test...")
    dot1q_tagging_result = dot1q_tagging(engine, config)
    dot1q_tagging_result_file = Path(f"results/{time}_dot1q_tagging.json")
    save_result(dot1q_tagging_result, dot1q_tagging_result_file)

    # ----- STP Convergence test -----
    print("Running STP Convergence test...")
    telemetry = TelemetryConfig(
        switch_ip="10.0.0.2", community="network-test", interface="GigabitEthernet1/0/5"
    )
    stp_convergence_result = stp_convergence(
        iperf3_engine,
        "172.16.0.2",
        on_link_failure=on_link_failure,
        config=config,
        telemetry=telemetry,
    )
    stp_convergence_result_file = Path(f"results/{time}_stp_convergence.json")
    save_result(stp_convergence_result, stp_convergence_result_file)

    # ----- ACL Enforcement test -----
    print("Running ACL Enforcement test...")
    acl_enforcement_result = acl_enforcement(engine, config)
    acl_enforcement_result_file = Path(f"results/{time}_acl_enforcement.json")
    save_result(acl_enforcement_result, acl_enforcement_result_file)


def main() -> None:
    ssh_options = ["-i", "/home/jimmy/.ssh/test-framework"]
    iperf3_engine = IPerf3Engine(ssh_options=ssh_options)
    scapy_engine = ScapyEngine(ssh_key_path="/home/jimmy/.ssh/test-framework")
    rfc2544_config = RFC2544Config(frame_length=1472, duration_sec=5)
    functional_test_config = FunctionalTestConfig(
        lab_secrets=load_lab_secrets(),
        src_ip="172.16.0.1",
        dst_ip="172.16.0.2",
        protocol="udp",
        frame_size=128,
        expect_tag_on_wire=False,
    )

    run_rfc2544_tests(iperf3_engine, rfc2544_config)
    run_functional_tests(scapy_engine, iperf3_engine, functional_test_config)


if __name__ == "__main__":
    main()
