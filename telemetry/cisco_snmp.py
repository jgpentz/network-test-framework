import easysnmp
import netmiko

def get_interface_counters(switch_ip, community, interface):
    """
    Get the counters for a given interface on a Cisco switch.
    """
    session = easysnmp.Session(
        hostname=switch_ip,
        community=community,
        version=2,
        timeout=2,
        retries=2,
    )

    # Find ifIndex for Gi1/0/5
    interfaces = session.walk('IF-MIB::ifDescr')
    ifIndex = None
    for intf in interfaces:
        if intf.value == interface:
            ifIndex = int(intf.oid_index)
            break

    if ifIndex is None:
        raise ValueError(f"Interface {interface} not found")

    # Get in/out octets
    in_octets = session.get(f'IF-MIB::ifHCInOctets.{ifIndex}').value
    out_octets = session.get(f'IF-MIB::ifHCOutOctets.{ifIndex}').value

    return in_octets, out_octets

if __name__ == "__main__":
    in_octets, out_octets = get_interface_counters("10.0.0.2", "network-test", "GigabitEthernet1/0/5")
    print(f"In octets: {in_octets}")
    print(f"Out octets: {out_octets}")