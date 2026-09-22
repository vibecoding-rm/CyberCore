import pytest
from pydantic import ValidationError

from app.tools.nmap import (
    DiscoverHostsArguments,
    InspectServicesArguments,
    NmapDiscoverHostsTool,
    NmapInspectServicesTool,
    find_nmap_executable,
)

SAMPLE_DISCOVER_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.99">
<host><status state="up" reason="localhost-response"/>
<address addr="192.168.10.25" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response"/>
<address addr="192.168.10.26" addrtype="ipv4"/>
</host>
</nmaprun>
"""

SAMPLE_SERVICES_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.99">
<host><status state="up"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22">
  <state state="open"/>
  <service name="ssh" product="OpenSSH" version="9.6p1">
    <cpe>cpe:/a:openbsd:openssh:9.6p1</cpe>
  </service>
</port>
<port protocol="tcp" portid="80">
  <state state="closed"/>
  <service name="http"/>
</port>
<port protocol="tcp" portid="8000">
  <state state="open"/>
  <service name="http" product="Uvicorn" version="0.30.0">
    <cpe>cpe:/a:encode:uvicorn:0.30.0</cpe>
  </service>
</port>
</ports>
</host>
</nmaprun>
"""


def test_discover_hosts_arguments_accepts_valid_ip_and_c24():
    args = DiscoverHostsArguments(target="192.168.10.25")
    assert args.target == "192.168.10.25"

    args_subnet = DiscoverHostsArguments(target="192.168.10.0/24")
    assert args_subnet.target == "192.168.10.0/24"


def test_discover_hosts_arguments_rejects_wider_than_slash_24():
    with pytest.raises(ValidationError, match="más amplio que /24"):
        DiscoverHostsArguments(target="192.168.0.0/16")

    with pytest.raises(ValidationError, match="más amplio que /24"):
        DiscoverHostsArguments(target="10.0.0.0/8")


def test_discover_hosts_arguments_rejects_arbitrary_extra_fields():
    with pytest.raises(ValidationError):
        DiscoverHostsArguments(target="192.168.10.1", raw_flags="--script vuln")


def test_inspect_services_arguments_validation():
    args = InspectServicesArguments(target="192.168.10.25", ports=[22, 443, 8080])
    assert args.target == "192.168.10.25"
    assert args.ports == [22, 443, 8080]

    # Deduplicates and sorts ports
    args_dedup = InspectServicesArguments(target="192.168.10.25", ports=[443, 22, 443])
    assert args_dedup.ports == [22, 443]


def test_inspect_services_rejects_invalid_ports():
    with pytest.raises(ValidationError, match="fuera de rango"):
        InspectServicesArguments(target="192.168.10.25", ports=[0])

    with pytest.raises(ValidationError, match="fuera de rango"):
        InspectServicesArguments(target="192.168.10.25", ports=[70000])

    with pytest.raises(ValidationError, match="no puede estar vacía"):
        InspectServicesArguments(target="192.168.10.25", ports=[])


def test_inspect_services_rejects_network_target():
    with pytest.raises(ValidationError):
        InspectServicesArguments(target="192.168.10.0/24")


@pytest.mark.asyncio
async def test_discover_hosts_mock_mode():
    tool = NmapDiscoverHostsTool(mode="mock")
    validated = tool.validate_arguments({"target": "192.168.10.0/24"})
    result = await tool.execute(validated)

    assert result["total_hosts_up"] == 2
    assert len(result["hosts"]) == 2
    assert result["hosts"][0]["status"] == "up"


@pytest.mark.asyncio
async def test_inspect_services_mock_mode():
    tool = NmapInspectServicesTool(mode="mock")
    validated = tool.validate_arguments({"target": "192.168.10.25", "ports": [22, 443]})
    result = await tool.execute(validated)

    assert len(result["services"]) == 2
    assert result["services"][0]["service_name"] == "ssh"
    assert result["services"][0]["product"] == "OpenSSH"


def test_parse_discover_xml():
    hosts = NmapDiscoverHostsTool._parse_discover_xml(SAMPLE_DISCOVER_XML)
    assert len(hosts) == 1
    assert hosts[0]["address"] == "192.168.10.25"
    assert hosts[0]["status"] == "up"


def test_parse_services_xml():
    services = NmapInspectServicesTool._parse_services_xml(SAMPLE_SERVICES_XML)
    # Closed port 80 must be excluded, only open ports included
    assert len(services) == 2

    ssh = services[0]
    assert ssh["port"] == 22
    assert ssh["protocol"] == "tcp"
    assert ssh["service_name"] == "ssh"
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "9.6p1"
    assert ssh["cpe"] == "cpe:/a:openbsd:openssh:9.6p1"

    uvicorn = services[1]
    assert uvicorn["port"] == 8000
    assert uvicorn["service_name"] == "http"
    assert uvicorn["product"] == "Uvicorn"
    assert uvicorn["version"] == "0.30.0"


@pytest.mark.asyncio
async def test_real_nmap_discover_on_loopback():
    try:
        find_nmap_executable()
    except RuntimeError:
        pytest.skip("Nmap no instalado en el sistema")

    tool = NmapDiscoverHostsTool(mode="local")
    validated = tool.validate_arguments({"target": "127.0.0.1"})
    result = await tool.execute(validated)

    assert result["total_hosts_up"] == 1
    assert result["hosts"][0]["address"] == "127.0.0.1"
    assert result["hosts"][0]["status"] == "up"
