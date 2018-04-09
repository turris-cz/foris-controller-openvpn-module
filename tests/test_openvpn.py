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
    backend, infrastructure, ubusd_test, only_backends
)

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
    assert new_notifications[-3]["data"]["status"] == "client_generating"
    assert new_notifications[-3]["data"]["task_id"] == task_id
    assert new_notifications[-2]["action"] == "generate_client"
    assert new_notifications[-2]["data"]["status"] == "client_done"
    assert new_notifications[-2]["data"]["task_id"] == task_id
    assert new_notifications[-1]["action"] == "generate_client"
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
        "data": {"name": "new.client_1"},
    })
    assert set(res.keys()) == {u"module", u"action", u"kind", u"data"}
    assert "task_id" in res["data"]
    task_id = res["data"]["task_id"]

    new_notifications = infrastructure.get_notifications(notifications, filters=filters)
    while len(new_notifications) - len(notifications) < 1:
        new_notifications = infrastructure.get_notifications(new_notifications, filters=filters)

    assert new_notifications[-1]["action"] == "generate_client"
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
