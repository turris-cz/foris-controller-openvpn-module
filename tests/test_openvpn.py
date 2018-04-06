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


@pytest.mark.only_backends(['mock'])
def test_generate_ca(infrastructure, ubusd_test):
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
