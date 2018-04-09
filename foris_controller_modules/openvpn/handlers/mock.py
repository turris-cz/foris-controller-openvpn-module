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

import logging
import random

from foris_controller.handler_base import BaseMockHandler
from foris_controller.utils import logger_wrapper

from .. import Handler

logger = logging.getLogger(__name__)


class MockOpenvpnHandler(Handler, BaseMockHandler):
    ca_generated = False
    clients = []

    @logger_wrapper(logger)
    def generate_ca(self, notify, exit_notify, reset_notify):
        MockOpenvpnHandler.ca_generated = True
        return "%032X" % random.randrange(2**32)

    @logger_wrapper(logger)
    def get_status(self):
        return {
            "status": "ready" if MockOpenvpnHandler.ca_generated else "missing",
            "clients": MockOpenvpnHandler.clients,
        }
