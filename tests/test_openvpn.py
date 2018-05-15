#
# foris-controller-openvpn-module
# Copyright (C) 2018 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
#

import os
import pytest
import shutil

from foris_controller_testtools.fixtures import (
    backend, infrastructure, ubusd_test, only_backends, uci_configs_init,
    init_script_result, lock_backend, file_root_init
)
from foris_controller_testtools.utils import match_subdict, check_service_result, get_uci_module

CERT_PATH = "/tmp/test-cagen/"

@pytest.fixture(scope="function")
def empty_certs():
    try:
        shutil.rmtree(CERT_PATH, ignore_errors=True)
    except Exception:
        pass

    yield CERT_PATH

    try:
        shutil.rmtree(CERT_PATH, ignore_errors=True)
    except Exception:
        pass


@pytest.fixture(scope="function")
def generating_certs():
    try:
        shutil.rmtree(CERT_PATH, ignore_errors=True)
    except Exception:
        pass

    dir_path = os.path.join(CERT_PATH, "openvpn")
    os.makedirs(dir_path)

    with open(os.path.join(dir_path, "ca"), "w") as f:
        f.write("1\n")
        f.flush()

    yield CERT_PATH

    try:
        shutil.rmtree(CERT_PATH, ignore_errors=True)
    except Exception:
        pass


@pytest.fixture(scope="function")
def ready_certs():
    try:
        shutil.rmtree(CERT_PATH, ignore_errors=True)
    except Exception:
        pass

    dir_path = os.path.join(CERT_PATH, "openvpn")
    os.makedirs(dir_path)

    with open(os.path.join(dir_path, "ca"), "w") as f:
        f.write("4\n")
        f.flush()

    with open(os.path.join(dir_path, "01-turris-server"), "w") as f:
        f.write("valid\n")
        f.flush()

    with open(os.path.join(dir_path, "02-client1-client"), "w") as f:
        f.write("revoked\n")
        f.flush()

    with open(os.path.join(dir_path, "03-client2-client"), "w") as f:
        f.write("valid\n")
        f.flush()

    with open(os.path.join(dir_path, "04-client3-client"), "w") as f:
        f.write("generating\n")
        f.flush()

    yield CERT_PATH

    try:
        shutil.rmtree(CERT_PATH, ignore_errors=True)
    except Exception:
        pass



@pytest.mark.only_backends(['mock'])
def test_generate_ca_mock(infrastructure, ubusd_test):
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "generate_ca",
        "kind": "request",
    })
    assert set(res.keys()) == {u"module", u"action", u"kind", u"data"}
    assert "task_id" in res["data"]


@pytest.mark.only_backends(['openwrt'])
def test_generate_ca_openwrt(empty_certs, infrastructure, ubusd_test):

    filters = [("openvpn", "generate_ca")]

    # successful generation
    notifications = infrastructure.get_notifications(filters=filters)

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "generate_ca",
        "kind": "request",
    })
    assert set(res.keys()) == {u"module", u"action", u"kind", u"data"}
    assert "task_id" in res["data"]
    task_id = res["data"]["task_id"]

    new_notifications = infrastructure.get_notifications(notifications, filters=filters)
    while len(new_notifications) - len(notifications) < 5:
        new_notifications = infrastructure.get_notifications(new_notifications, filters=filters)

    assert new_notifications[-5]["action"] == "generate_ca"
    assert new_notifications[-5]["data"]["status"] == "ca_generating"
    assert new_notifications[-5]["data"]["task_id"] == task_id
    assert new_notifications[-4]["action"] == "generate_ca"
    assert new_notifications[-4]["data"]["status"] == "ca_done"
    assert new_notifications[-4]["data"]["task_id"] == task_id
    assert new_notifications[-3]["action"] == "generate_ca"
    assert new_notifications[-3]["data"]["status"] == "server_generating"
    assert new_notifications[-3]["data"]["task_id"] == task_id
    assert new_notifications[-2]["action"] == "generate_ca"
    assert new_notifications[-2]["data"]["status"] == "server_done"
    assert new_notifications[-2]["data"]["task_id"] == task_id
    assert new_notifications[-1]["action"] == "generate_ca"
    assert new_notifications[-1]["data"]["status"] == "succeeded"
    assert new_notifications[-1]["data"]["task_id"] == task_id

    # failed to generate
    notifications = infrastructure.get_notifications(filters=filters)
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "generate_ca",
        "kind": "request",
    })
    assert set(res.keys()) == {u"module", u"action", u"kind", u"data"}
    assert "task_id" in res["data"]
    task_id = res["data"]["task_id"]

    new_notifications = infrastructure.get_notifications(notifications, filters=filters)

    assert new_notifications[-1]["action"] == "generate_ca"
    assert new_notifications[-1]["data"]["status"] == "failed"
    assert new_notifications[-1]["data"]["task_id"] == task_id


@pytest.mark.only_backends(['mock'])
def test_ca_get_status_mock(infrastructure, ubusd_test):
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert set(res.keys()) == {u"module", u"action", u"kind", u"data"}
    assert "status" in res["data"]


@pytest.mark.only_backends(['openwrt'])
def test_get_status_openwrt_ready(ready_certs, infrastructure, ubusd_test):
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert res == {
        u"module": u"openvpn",
        u"action": u"get_status",
        u"kind": u"reply",
        u"data": {
            u"status": u"ready",
            u"clients": [
                {u"id": u"02", u"name": u"client1", u"status": u"revoked"},
                {u"id": u"03", u"name": u"client2", u"status": u"valid"},
                {u"id": u"04", u"name": u"client3", u"status": u"generating"},
            ],
        }
    }


@pytest.mark.only_backends(['openwrt'])
def test_get_status_openwrt_missing(empty_certs, infrastructure, ubusd_test):
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert res == {
        u"module": u"openvpn",
        u"action": u"get_status",
        u"kind": u"reply",
        u"data": {u"status": "missing", u"clients": []}
    }


@pytest.mark.only_backends(['openwrt'])
def test_get_status_openwrt_generating(generating_certs, infrastructure, ubusd_test):
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert res == {
        u"module": u"openvpn",
        u"action": u"get_status",
        u"kind": u"reply",
        u"data": {u"status": u"generating", u"clients": []}
    }


@pytest.mark.only_backends(['mock'])
def test_generate_client_mock(infrastructure, ubusd_test):
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert "data" in res
    assert "clients" in res["data"]
    orig_count = len(res["data"]["clients"])

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "generate_client",
        "kind": "request",
        "data": {"name": "new.client_1"},
    })
    assert set(res.keys()) == {u"module", u"action", u"kind", u"data"}
    assert "task_id" in res["data"]

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert "data" in res
    assert "clients" in res["data"]
    assert len(res["data"]["clients"]) == orig_count + 1
    assert res["data"]["clients"][-1]["name"] == "new.client_1"


@pytest.mark.only_backends(['openwrt'])
def test_generate_client_openwrt_success(ready_certs, infrastructure, ubusd_test):

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert "data" in res
    assert "clients" in res["data"]
    orig_count = len(res["data"]["clients"])

    filters = [("openvpn", "generate_client")]

    notifications = infrastructure.get_notifications(filters=filters)

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "generate_client",
        "kind": "request",
        "data": {"name": "new.client_1"},
    })
    assert set(res.keys()) == {u"module", u"action", u"kind", u"data"}
    assert "task_id" in res["data"]
    task_id = res["data"]["task_id"]

    new_notifications = infrastructure.get_notifications(notifications, filters=filters)
    while len(new_notifications) - len(notifications) < 3:
        new_notifications = infrastructure.get_notifications(new_notifications, filters=filters)

    assert new_notifications[-3]["action"] == "generate_client"
    assert new_notifications[-3]["data"]["name"] == "new.client_1"
    assert new_notifications[-3]["data"]["status"] == "client_generating"
    assert new_notifications[-3]["data"]["task_id"] == task_id
    assert new_notifications[-2]["action"] == "generate_client"
    assert new_notifications[-2]["data"]["name"] == "new.client_1"
    assert new_notifications[-2]["data"]["status"] == "client_done"
    assert new_notifications[-2]["data"]["task_id"] == task_id
    assert new_notifications[-1]["action"] == "generate_client"
    assert new_notifications[-1]["data"]["name"] == "new.client_1"
    assert new_notifications[-1]["data"]["status"] == "succeeded"
    assert new_notifications[-1]["data"]["task_id"] == task_id

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert "data" in res
    assert "clients" in res["data"]
    assert len(res["data"]["clients"]) == orig_count + 1
    assert res["data"]["clients"][-1]["name"] == "new.client_1"


@pytest.mark.only_backends(['openwrt'])
def test_generate_client_openwrt_failed(empty_certs, infrastructure, ubusd_test):

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert "data" in res
    assert "clients" in res["data"]
    assert len(res["data"]["clients"]) == 0

    filters = [("openvpn", "generate_client")]

    notifications = infrastructure.get_notifications(filters=filters)

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "generate_client",
        "kind": "request",
        "data": {"name": "new.client_2"},
    })
    assert set(res.keys()) == {u"module", u"action", u"kind", u"data"}
    assert "task_id" in res["data"]
    task_id = res["data"]["task_id"]

    new_notifications = infrastructure.get_notifications(notifications, filters=filters)
    while len(new_notifications) - len(notifications) < 1:
        new_notifications = infrastructure.get_notifications(new_notifications, filters=filters)

    assert new_notifications[-1]["action"] == "generate_client"
    assert new_notifications[-1]["data"]["name"] == "new.client_2"
    assert new_notifications[-1]["data"]["status"] == "failed"
    assert new_notifications[-1]["data"]["task_id"] == task_id

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert "data" in res
    assert "clients" in res["data"]
    assert len(res["data"]["clients"]) == 0


def test_generate_client_name_failed(empty_certs, infrastructure, ubusd_test):
    def wrong_name(name):
        res = infrastructure.process_message({
            "module": "openvpn",
            "action": "generate_client",
            "kind": "request",
            "data": {"name": name},
        })
        assert "errors" in res["data"]

    wrong_name("aaa%")
    wrong_name("bbb$")
    wrong_name("ccc!")


@pytest.mark.only_backends(['mock'])
def test_revoke_mock(infrastructure, ubusd_test):

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "generate_client",
        "kind": "request",
        "data": {"name": "new.client_to_revoke"},
    })
    assert set(res.keys()) == {u"module", u"action", u"kind", u"data"}
    assert "task_id" in res["data"]

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert "data" in res
    assert "clients" in res["data"]
    assert res["data"]["clients"][-1]["name"] == "new.client_to_revoke"
    id_to_revoke = res["data"]["clients"][-1]["id"]

    filters = [("openvpn", "revoke")]

    # successful generation
    notifications = infrastructure.get_notifications(filters=filters)

    # existing
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "revoke",
        "kind": "request",
        "data": {"id": id_to_revoke},
    })
    assert "result" in res["data"]
    assert res["data"]["result"] is True

    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1] == {
        u"module": u"openvpn",
        u"action": u"revoke",
        u"kind": u"notification",
        u"data": {u"id": id_to_revoke},
    }

    # non-existing
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "revoke",
        "kind": "request",
        "data": {"id": "FF"},
    })
    assert "result" in res["data"]
    assert res["data"]["result"] is False


@pytest.mark.only_backends(['openwrt'])
def test_revoke_openwrt_ready(ready_certs, infrastructure, ubusd_test):
    filters = [("openvpn", "revoke")]

    # successful generation
    notifications = infrastructure.get_notifications(filters=filters)

    # existing
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "revoke",
        "kind": "request",
        "data": {"id": "03"},
    })
    assert "result" in res["data"]
    assert res["data"]["result"] is True

    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1] == {
        u"module": u"openvpn",
        u"action": u"revoke",
        u"kind": u"notification",
        u"data": {u"id": "03"},
    }

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert "data" in res
    assert "clients" in res["data"]
    matched = [e for e in res["data"]["clients"] if e["id"] == "03"][0]
    assert matched["status"] == "revoked"

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "revoke",
        "kind": "request",
        "data": {"id": "FF"},
    })
    assert "result" in res["data"]
    assert res["data"]["result"] is False


@pytest.mark.only_backends(['openwrt'])
def test_revoke_openwrt_missing(empty_certs, infrastructure, ubusd_test):
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "revoke",
        "kind": "request",
        "data": {"id": "03"},
    })
    assert "result" in res["data"]
    assert res["data"]["result"] is False


def test_delete_ca(ready_certs, infrastructure, ubusd_test):
    filters = [("openvpn", "delete_ca")]

    notifications = infrastructure.get_notifications(filters=filters)
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "delete_ca",
        "kind": "request",
    })
    assert "data" in res
    assert "result" in res["data"]
    assert res["data"]["result"] is True

    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1] == {
        u"module": u"openvpn",
        u"action": u"delete_ca",
        u"kind": u"notification",
    }

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert "status" in res["data"]
    assert res["data"]["status"] == "missing"


def test_get_settings(uci_configs_init, infrastructure, ubusd_test):
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_settings",
        "kind": "request",
    })
    assert set(res["data"].keys()) == {
        u"enabled", u"network", u"network_netmask", u"device", u"protocol", u"port", u"routes",
        u"route_all", u"use_dns", u"server_hostname", "ipv6",
    }


def test_update_settings(uci_configs_init, init_script_result, infrastructure, ubusd_test):
    filters = [("openvpn", "update_settings")]

    def update(new_settings):
        notifications = infrastructure.get_notifications(filters=filters)
        res = infrastructure.process_message({
            "module": "openvpn",
            "action": "update_settings",
            "kind": "request",
            "data": new_settings,
        })
        assert "result" in res["data"]
        assert res["data"]["result"] is True

        notifications = infrastructure.get_notifications(notifications, filters=filters)
        assert notifications[-1]["data"] == new_settings

        res = infrastructure.process_message({
            "module": "openvpn",
            "action": "get_settings",
            "kind": "request",
        })
        assert match_subdict(new_settings, res["data"])

    update({u"enabled": False})
    update({
        "enabled": True,
        "ipv6": True,
        "protocol": "udp",
        "network": "10.111.222.0",
        "network_netmask": "255.255.254.0",
        "route_all": False,
        "use_dns": False,
    })
    update({
        "enabled": True,
        "ipv6": False,
        "protocol": "tcp",
        "network": "10.222.222.0",
        "network_netmask": "255.255.252.0",
        "route_all": True,
        "use_dns": True,
    })


@pytest.mark.only_backends(['openwrt'])
def test_update_settings_openwrt(
    uci_configs_init, init_script_result, lock_backend, infrastructure, ubusd_test
):

    uci = get_uci_module(lock_backend)

    def update(data):
        res = infrastructure.process_message({
            "module": "openvpn",
            "action": "update_settings",
            "kind": "request",
            "data": data,
        })
        assert res == {
            u'action': u'update_settings',
            u'data': {u'result': True},
            u'kind': u'reply',
            u'module': u'openvpn'
        }
        check_service_result("openvpn", True, "restart")

    update({
        "enabled": False,
    })
    with uci.UciBackend() as backend:
        data = backend.read()
    assert uci.parse_bool(uci.get_option_named(data, "network", "vpn_turris", "enabled")) is False
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_rule", "enabled")) is False
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris", "enabled")) is False
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_in", "enabled")) is False
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_out", "enabled")) is False
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_forward_wan_out", "enabled")) is False
    assert uci.parse_bool(uci.get_option_named(data, "openvpn", "server_turris", "enabled")) is False

    update({
        "enabled": True,
        "network": "10.111.222.0",
        "network_netmask": "255.255.254.0",
        "route_all": False,
        "use_dns": False,
        "ipv6": False,
        "protocol": "udp",
    })

    with uci.UciBackend() as backend:
        data = backend.read()

    assert uci.get_option_named(data, "network", "vpn_turris", "ifname") == "tun_turris"
    assert uci.get_option_named(data, "network", "vpn_turris", "proto") == "none"
    assert uci.parse_bool(uci.get_option_named(data, "network", "vpn_turris", "auto")) is True
    assert uci.parse_bool(uci.get_option_named(data, "network", "vpn_turris", "enabled")) is True

    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_rule", "enabled")) is True
    assert uci.get_option_named(data, "firewall", "vpn_turris_rule", "name") == "vpn_turris_rule"
    assert uci.get_option_named(data, "firewall", "vpn_turris_rule", "target") == "ACCEPT"
    assert uci.get_option_named(data, "firewall", "vpn_turris_rule", "proto") == "udp"
    assert uci.get_option_named(data, "firewall", "vpn_turris_rule", "src") == "wan"
    assert uci.get_option_named(data, "firewall", "vpn_turris_rule", "dest_port") == "1194"

    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris", "enabled")) is True
    assert uci.get_option_named(data, "firewall", "vpn_turris", "name") == "vpn_turris"
    assert uci.get_option_named(data, "firewall", "vpn_turris", "network") == ["vpn_turris"]
    assert uci.get_option_named(data, "firewall", "vpn_turris", "input") == "ACCEPT"
    assert uci.get_option_named(data, "firewall", "vpn_turris", "forward") == "REJECT"
    assert uci.get_option_named(data, "firewall", "vpn_turris", "output") == "ACCEPT"
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris", "masq")) is True

    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_in", "enabled")) is True
    assert uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_in", "src") == "vpn_turris"
    assert uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_in", "dest") == "lan"

    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_out", "enabled")) is True
    assert uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_out", "src") == "lan"
    assert uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_out", "dest") == "vpn_turris"

    # no default route
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_forward_wan_out", "enabled")) is False
    assert uci.get_option_named(data, "firewall", "vpn_turris_forward_wan_out", "src") == "vpn_turris"
    assert uci.get_option_named(data, "firewall", "vpn_turris_forward_wan_out", "dest") == "wan"

    assert uci.parse_bool(uci.get_option_named(data, "openvpn", "server_turris", "enabled")) is True
    assert uci.get_option_named(data, "openvpn", "server_turris", "server") == "10.111.222.0 255.255.254.0"
    assert uci.get_option_named(data, "openvpn", "server_turris", "port") == "1194"
    assert uci.get_option_named(data, "openvpn", "server_turris", "proto") == "udp"
    assert uci.get_option_named(data, "openvpn", "server_turris", "dev") == "tun_turris"
    assert uci.get_option_named(data, "openvpn", "server_turris", "ca") == "/etc/ssl/ca/openvpn/ca.crt"
    assert uci.get_option_named(data, "openvpn", "server_turris", "crl_verify") == "/etc/ssl/ca/openvpn/ca.crl"
    assert uci.get_option_named(data, "openvpn", "server_turris", "cert") == "/etc/ssl/ca/openvpn/01.crt"
    assert uci.get_option_named(data, "openvpn", "server_turris", "key") == "/etc/ssl/ca/openvpn/01.key"
    assert uci.get_option_named(data, "openvpn", "server_turris", "dh") == "/etc/dhparam/dh-default.pem"
    assert uci.get_option_named(data, "openvpn", "server_turris", "ifconfig_pool_persist") == "/tmp/ipp.txt"
    assert uci.parse_bool(uci.get_option_named(data, "openvpn", "server_turris", "duplicate_cn")) is False
    assert uci.get_option_named(data, "openvpn", "server_turris", "keepalive") == "10 120"
    assert uci.get_option_named(data, "openvpn", "server_turris", "comp_lzo") == "yes"
    assert uci.parse_bool(uci.get_option_named(data, "openvpn", "server_turris", "persist_key")) is True
    assert uci.parse_bool(uci.get_option_named(data, "openvpn", "server_turris", "persist_tun")) is True
    assert uci.get_option_named(data, "openvpn", "server_turris", "status") == "/tmp/openvpn-status.log"
    assert uci.get_option_named(data, "openvpn", "server_turris", "verb") == "3"
    assert uci.get_option_named(data, "openvpn", "server_turris", "mute") == "20"
    push_options = uci.get_option_named(data, "openvpn", "server_turris", "push")
    assert len(push_options) == 1
    assert "route 192.168.1.0 255.255.255.0" in push_options  # Default lan network

    update({
        "enabled": True,
        "network": "10.222.222.0",
        "network_netmask": "255.255.252.0",
        "route_all": True,
        "use_dns": True,
        "ipv6": True,
        "protocol": "tcp",
    })

    with uci.UciBackend() as backend:
        data = backend.read()

    assert uci.get_option_named(data, "network", "vpn_turris", "ifname") == "tun_turris"
    assert uci.get_option_named(data, "network", "vpn_turris", "proto") == "none"
    assert uci.parse_bool(uci.get_option_named(data, "network", "vpn_turris", "auto")) is True
    assert uci.parse_bool(uci.get_option_named(data, "network", "vpn_turris", "enabled")) is True

    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_rule", "enabled")) is True
    assert uci.get_option_named(data, "firewall", "vpn_turris_rule", "name") == "vpn_turris_rule"
    assert uci.get_option_named(data, "firewall", "vpn_turris_rule", "target") == "ACCEPT"
    assert uci.get_option_named(data, "firewall", "vpn_turris_rule", "proto") == "tcp"
    assert uci.get_option_named(data, "firewall", "vpn_turris_rule", "src") == "wan"
    assert uci.get_option_named(data, "firewall", "vpn_turris_rule", "dest_port") == "1194"

    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris", "enabled")) is True
    assert uci.get_option_named(data, "firewall", "vpn_turris", "name") == "vpn_turris"
    assert uci.get_option_named(data, "firewall", "vpn_turris", "network") == ["vpn_turris"]
    assert uci.get_option_named(data, "firewall", "vpn_turris", "input") == "ACCEPT"
    assert uci.get_option_named(data, "firewall", "vpn_turris", "forward") == "REJECT"
    assert uci.get_option_named(data, "firewall", "vpn_turris", "output") == "ACCEPT"
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris", "masq")) is True

    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_in", "enabled")) is True
    assert uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_in", "src") == "vpn_turris"
    assert uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_in", "dest") == "lan"

    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_out", "enabled")) is True
    assert uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_out", "src") == "lan"
    assert uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_out", "dest") == "vpn_turris"

    # redirect to default route
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_forward_wan_out", "enabled")) is True
    assert uci.get_option_named(data, "firewall", "vpn_turris_forward_wan_out", "src") == "vpn_turris"
    assert uci.get_option_named(data, "firewall", "vpn_turris_forward_wan_out", "dest") == "wan"

    assert uci.parse_bool(uci.get_option_named(data, "openvpn", "server_turris", "enabled")) is True
    assert uci.get_option_named(data, "openvpn", "server_turris", "server") == "10.222.222.0 255.255.252.0"
    assert uci.get_option_named(data, "openvpn", "server_turris", "port") == "1194"
    assert uci.get_option_named(data, "openvpn", "server_turris", "proto") == "tcp6-server"
    assert uci.get_option_named(data, "openvpn", "server_turris", "dev") == "tun_turris"
    assert uci.get_option_named(data, "openvpn", "server_turris", "ca") == "/etc/ssl/ca/openvpn/ca.crt"
    assert uci.get_option_named(data, "openvpn", "server_turris", "crl_verify") == "/etc/ssl/ca/openvpn/ca.crl"
    assert uci.get_option_named(data, "openvpn", "server_turris", "cert") == "/etc/ssl/ca/openvpn/01.crt"
    assert uci.get_option_named(data, "openvpn", "server_turris", "key") == "/etc/ssl/ca/openvpn/01.key"
    assert uci.get_option_named(data, "openvpn", "server_turris", "dh") == "/etc/dhparam/dh-default.pem"
    assert uci.get_option_named(data, "openvpn", "server_turris", "ifconfig_pool_persist") == "/tmp/ipp.txt"
    assert uci.parse_bool(uci.get_option_named(data, "openvpn", "server_turris", "duplicate_cn")) is False
    assert uci.get_option_named(data, "openvpn", "server_turris", "keepalive") == "10 120"
    assert uci.get_option_named(data, "openvpn", "server_turris", "comp_lzo") == "yes"
    assert uci.parse_bool(uci.get_option_named(data, "openvpn", "server_turris", "persist_key")) is True
    assert uci.parse_bool(uci.get_option_named(data, "openvpn", "server_turris", "persist_tun")) is True
    assert uci.get_option_named(data, "openvpn", "server_turris", "status") == "/tmp/openvpn-status.log"
    assert uci.get_option_named(data, "openvpn", "server_turris", "verb") == "3"
    assert uci.get_option_named(data, "openvpn", "server_turris", "mute") == "20"
    push_options = uci.get_option_named(data, "openvpn", "server_turris", "push")
    assert len(push_options) == 3
    assert "route 192.168.1.0 255.255.255.0" in push_options  # Default lan network
    assert "dhcp-option DNS 10.222.222.1" in push_options  # Default router ip in lan
    assert "redirect-gateway def1" in push_options  # Default router ip in lan

    update({
        "enabled": False,
    })
    with uci.UciBackend() as backend:
        data = backend.read()
    assert uci.parse_bool(uci.get_option_named(data, "network", "vpn_turris", "enabled")) is False
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_rule", "enabled")) is False
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris", "enabled")) is False
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_in", "enabled")) is False
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_forward_lan_out", "enabled")) is False
    assert uci.parse_bool(uci.get_option_named(data, "firewall", "vpn_turris_forward_wan_out", "enabled")) is False
    assert uci.parse_bool(uci.get_option_named(data, "openvpn", "server_turris", "enabled")) is False


@pytest.mark.only_backends(['mock'])
@pytest.mark.parametrize("hostname", ["", "10.20.30.40"])
def test_get_client_config_mock(infrastructure, hostname, ubusd_test):
    def check_hostname(server_hostname):
        if server_hostname:
            res = infrastructure.process_message({
                "module": "openvpn",
                "action": "get_settings",
                "kind": "request",
            })
            assert res["data"]["server_hostname"] == server_hostname

    query_data = {"hostname": hostname} if hostname else {}
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "generate_ca",
        "kind": "request",
    })
    assert "errors" not in res["data"]

    query_data["id"] = "FF"
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_client_config",
        "kind": "request",
        "data": query_data,
    })
    assert {"status"} == set(res["data"].keys())
    assert res["data"]["status"] == "not_found"
    check_hostname(hostname)

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "generate_client",
        "kind": "request",
        "data": {"name": "get_client_config"},
    })
    assert "errors" not in res["data"]
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_status",
        "kind": "request",
    })
    assert "errors" not in res["data"]
    assert res["data"]["clients"][-1]["name"] == "get_client_config"
    client = res["data"]["clients"][-1]

    query_data["id"] = client["id"]
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_client_config",
        "kind": "request",
        "data": query_data,
    })
    assert {"status", "config"} == set(res["data"].keys())
    assert res["data"]["status"] == "valid"
    check_hostname(hostname)
    if hostname:
        assert hostname in res["data"]["config"]

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "revoke",
        "kind": "request",
        "data": {"id": client["id"]},
    })
    assert "result" in res["data"]
    assert res["data"]["result"] is True

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_client_config",
        "kind": "request",
        "data": query_data,
    })
    assert {"status"} == set(res["data"].keys())
    assert res["data"]["status"] == "revoked"
    check_hostname(hostname)


AVAILABLE_PROTOCOLS = [
    "tcp", "udp", "tcp-server", "tcp4", "udp4", "tcp4-server", "tcp6", "udp6", "tcp6-server"
]


@pytest.mark.only_backends(['openwrt'])
@pytest.mark.parametrize("hostname", ["", "10.30.50.70"])
@pytest.mark.parametrize("proto", AVAILABLE_PROTOCOLS)
def test_get_client_config_openwrt(
    ready_certs, uci_configs_init, init_script_result, lock_backend, infrastructure, ubusd_test,
    hostname, file_root_init, proto
):

    uci = get_uci_module(lock_backend)
    with uci.UciBackend() as backend:
        backend.add_section("openvpn", "openvpn", "server_turris")
        backend.set_option("openvpn", "server_turris", "proto", proto)

    def check_hostname(server_hostname):
        if server_hostname:
            res = infrastructure.process_message({
                "module": "openvpn",
                "action": "get_settings",
                "kind": "request",
            })
            assert res["data"]["server_hostname"] == server_hostname

    query_data = {"hostname": hostname} if hostname else {}

    query_data["id"] = "FF"
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_client_config",
        "kind": "request",
        "data": query_data,
    })
    assert {"status"} == set(res["data"].keys())
    assert res["data"]["status"] == "not_found"
    check_hostname(hostname)

    query_data["id"] = "02"
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_client_config",
        "kind": "request",
        "data": query_data,
    })
    assert {"status"} == set(res["data"].keys())
    assert res["data"]["status"] == "revoked"
    check_hostname(hostname)

    query_data["id"] = "03"
    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_client_config",
        "kind": "request",
        "data": query_data,
    })
    assert {"status", "config"} == set(res["data"].keys())
    assert res["data"]["status"] == "valid"
    check_hostname(hostname)
    if hostname:
        assert hostname in res["data"]["config"]
    assert "dev tun_turris" in res["data"]["config"]
    if proto in ["tcp-server", "tcp4-server", "tcp6-server"]:
        assert "proto %s" % proto.replace("server", "client") in res["data"]["config"]
    else:
        assert "proto %s" % proto in res["data"]["config"]
    assert "<ca>" in res["data"]["config"]
    assert "</ca>" in res["data"]["config"]
    assert "<cert>" in res["data"]["config"]
    assert "</cert>" in res["data"]["config"]
    assert "<key>" in res["data"]["config"]
    assert "</key>" in res["data"]["config"]

    # Following lines regards other options which might be set in the future
    ## tls-auth
    # if tls_auth_used:
    #    assert "key-direction 1" in res["config"]
    #    assert "<tls-auth>" in res["data"]["config"]
    #    assert "</tls-auth>" in res["data"]["config"]
    # if custom_cipher:
    #    assert "cipher %s" % custom_cipher in res["data"]["config"]
    # if comp_lzo_used:
    #    assert "comp-lzo" in res["data"]["config"]


@pytest.mark.only_backends(['openwrt'])
@pytest.mark.parametrize("proto", AVAILABLE_PROTOCOLS)
def test_available_protocols(
    uci_configs_init, init_script_result, lock_backend, infrastructure, ubusd_test, proto
):
    uci = get_uci_module(lock_backend)
    with uci.UciBackend() as backend:
        backend.add_section("openvpn", "openvpn", "server_turris")
        backend.set_option("openvpn", "server_turris", "proto", proto)

    res = infrastructure.process_message({
        "module": "openvpn",
        "action": "get_settings",
        "kind": "request",
    })
    assert res["data"]["protocol"] == proto[:3]
    assert res["data"]["ipv6"] == ("6" in proto)
