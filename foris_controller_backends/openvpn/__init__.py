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

import re
import logging

from foris_controller_backends.cmdline import AsyncCommand, BaseCmdLine
from foris_controller_backends.uci import (
    UciBackend, get_option_named, parse_bool, UciRecordNotFound, UciException, store_bool
)
from foris_controller_backends.services import OpenwrtServices
from foris_controller.utils import IPv4

logger = logging.getLogger(__name__)


class CaGenAsync(AsyncCommand):

    def generate_ca(self, notify_function, exit_notify_function, reset_notify_function):

        def handler_exit(process_data):
            exit_notify_function({
                "task_id": process_data.id,
                "status": "succeeded" if process_data.get_retval() == 0 else "failed"
            })

        def gen_handler(status):
            def handler(matched, process_data):
                notify_function({"task_id": process_data.id, "status": status})
            return handler

        task_id = self.start_process(
            ["/usr/bin/turris-cagen", "new_ca", "openvpn", "gen_ca", "gen_server", "turris"],
            [
                (r"^gen_ca: started", gen_handler("ca_generating")),
                (r"^gen_ca: finished", gen_handler("ca_done")),
                (r"^gen_server: started", gen_handler("server_generating")),
                (r"^gen_server: finished", gen_handler("server_done")),
            ],
            handler_exit,
            reset_notify_function,
        )

        return task_id

    def generate_client(self, name, notify_function, exit_notify_function, reset_notify_function):

        def handler_exit(process_data):
            exit_notify_function({
                "task_id": process_data.id,
                "status": "succeeded" if process_data.get_retval() == 0 else "failed"
            })

        def gen_handler(status):
            def handler(matched, process_data):
                notify_function({"task_id": process_data.id, "status": status})
            return handler

        task_id = self.start_process(
            ["/usr/bin/turris-cagen", "switch", "openvpn", "gen_client", name],
            [
                (r"^gen_client: started", gen_handler("client_generating")),
                (r"^gen_client: finished", gen_handler("client_done")),
            ],
            handler_exit,
            reset_notify_function,
        )

        return task_id


class CaGenCmds(BaseCmdLine):

    def get_status(self):
        output, _ = self._run_command_and_check_retval(
            ["/usr/bin/turris-cagen-status", "openvpn"], 0)
        ca_status = re.search(r"^status: (\w+)$", output, re.MULTILINE).group(1)
        clients = []
        in_cert_section = False
        server_cert_found = False
        for line in output.split("\n"):
            if in_cert_section:
                try:
                    cert_id, cert_type, name, status = line.split(" ")
                    if cert_type == "client":
                        clients.append({
                            "id": cert_id,
                            "name": name,
                            "status": status,
                        })
                    elif cert_type == "server":
                        server_cert_found = True
                except ValueError:
                    continue
            if line == "## Certs:":
                in_cert_section = True

        # if server cert is missing this means that openvpn CA hasn't been generated yet
        ca_status = "generating" if ca_status == "ready" and not server_cert_found else ca_status

        return {
            "status": ca_status,
            "clients": clients,
        }

    def revoke(self, cert_id):
        retval, _, _ = self._run_command(
            "/usr/bin/turris-cagen", "switch", "openvpn", "revoke", cert_id
        )
        return retval == 0

    def delete_ca(self):
        retval, _, _ = self._run_command("/usr/bin/turris-cagen", "drop_ca", "openvpn")
        return retval == 0


class OpenvpnUci(object):
    DEFAULTS = {
        "enabled": False,
        "network": "10.111.111.0",
        "network_netmask": "255.255.255.0",
        "routes": [
        ],
        "device": "",
        "protocol": "",
        "port": 1194,
        "route_all": False,
        "use_dns": False,
    }

    def get_settings(self):
        with UciBackend() as backend:
            data = backend.read("openvpn")

        try:
            enabled = parse_bool(get_option_named(data, "openvpn", "server_turris", "enabled", "0"))
            network, network_netmask = get_option_named(
                data, "openvpn", "server_turris", "server", "10.111.111.0 255.255.255.0").split()
            push_options = get_option_named(data, "openvpn", "server_turris", "push", [])
            routes = [
                dict(zip(("network", "netmask"), e.split()[1:]))  # `route <network> <netmask>`
                for e in push_options if e.startswith("route ")
            ]
            device = get_option_named(data, "openvpn", "server_turris", "device", "")
            protocol = get_option_named(data, "openvpn", "server_turris", "proto", "")
            port = int(get_option_named(data, "openvpn", "server_turris", "port", "0"))
            use_dns = True if [e for e in push_options if e.startswith("dhcp-option DNS")] \
                else False
            route_all = True if [e for e in push_options if e == "redirect-gateway def1"] \
                else False

        except UciException:
            return OpenvpnUci.DEFAULTS

        return {
            "enabled": enabled,
            "network": network,
            "network_netmask": network_netmask,
            "routes": routes,
            "device": device,
            "protocol": protocol,
            "port": port,
            "route_all": route_all,
            "use_dns": use_dns,
        }

    def update_settings(
        self, enabled, network=None, network_netmask=None, route_all=None, use_dns=None
    ):
        with UciBackend() as backend:
            if enabled:
                network_data = backend.read("network")
                lan_ip = get_option_named(network_data, "network", "lan", "ipaddr")
                lan_netmask = get_option_named(network_data, "network", "lan", "netmask")

                backend.add_section("network", "interface", "vpn_turris")
                backend.set_option("network", "vpn_turris", "enabled", store_bool(True))
                backend.set_option("network", "vpn_turris", "ifname", "tun_turris")
                backend.set_option("network", "vpn_turris", "proto", "none")
                backend.set_option("network", "vpn_turris", "auto", store_bool(True))

                backend.add_section("firewall", "zone", "vpn_turris")
                backend.set_option("firewall", "vpn_turris", "enabled", store_bool(True))
                backend.set_option("firewall", "vpn_turris", "name", "vpn_turris")
                backend.set_option("firewall", "vpn_turris", "input", "ACCEPT")
                backend.set_option("firewall", "vpn_turris", "forward", "REJECT")
                backend.set_option("firewall", "vpn_turris", "output", "ACCEPT")
                backend.set_option("firewall", "vpn_turris", "masq", store_bool(True))
                backend.replace_list("firewall", "vpn_turris", "network", ["vpn_turris"])
                backend.add_section("firewall", "rule", "vpn_turris_rule")
                backend.set_option("firewall", "vpn_turris_rule", "enabled", store_bool(True))
                backend.set_option("firewall", "vpn_turris_rule", "name", "vpn_turris_rule")
                backend.set_option("firewall", "vpn_turris_rule", "target", "ACCEPT")
                backend.set_option("firewall", "vpn_turris_rule", "proto", "udp")
                backend.set_option("firewall", "vpn_turris_rule", "src", "wan")
                backend.set_option("firewall", "vpn_turris_rule", "dest_port", "1194")
                backend.add_section("firewall", "forwarding", "vpn_turris_forward_lan_in")
                backend.set_option(
                    "firewall", "vpn_turris_forward_lan_in", "enabled", store_bool(True))
                backend.set_option("firewall", "vpn_turris_forward_lan_in", "src", "vpn_turris")
                backend.set_option("firewall", "vpn_turris_forward_lan_in", "dest", "lan")
                backend.set_option(
                    "firewall", "vpn_turris_forward_lan_out", "enabled", store_bool(True))
                backend.set_option("firewall", "vpn_turris_forward_lan_out", "src", "lan")
                backend.set_option("firewall", "vpn_turris_forward_lan_out", "dest", "vpn_turris")
                backend.set_option(
                    "firewall", "vpn_turris_forward_wan_out", "enabled",
                    store_bool(True if route_all else False)
                )
                backend.set_option("firewall", "vpn_turris_forward_wan_out", "src", "vpn_turris")
                backend.set_option("firewall", "vpn_turris_forward_wan_out", "dest", "wan")

                backend.add_section("openvpn", "openvpn", "server_turris")
                backend.set_option("openvpn", "server_turris", "enabled", store_bool(True))
                backend.set_option("openvpn", "server_turris", "port", "1194")
                backend.set_option("openvpn", "server_turris", "proto", "udp")
                backend.set_option("openvpn", "server_turris", "dev", "tun_turris")
                backend.set_option("openvpn", "server_turris", "ca", "/etc/ssl/ca/openvpn/ca.crt")
                backend.set_option(
                    "openvpn", "server_turris", "crl_verify", "/etc/ssl/ca/openvpn/ca.crl")
                backend.set_option("openvpn", "server_turris", "cert", "/etc/ssl/ca/openvpn/01.crt")
                backend.set_option("openvpn", "server_turris", "key", "/etc/ssl/ca/openvpn/01.key")
                backend.set_option("openvpn", "server_turris", "dh", "/etc/dhparam/dh-default.pem")
                backend.set_option(
                    "openvpn", "server_turris", "server", "%s %s" % (network, network_netmask))
                backend.set_option(
                    "openvpn", "server_turris", "ifconfig_pool_persist", "/tmp/ipp.txt")
                backend.set_option("openvpn", "server_turris", "duplicate_cn", store_bool(False))
                backend.set_option("openvpn", "server_turris", "keepalive", "10 120")
                backend.set_option("openvpn", "server_turris", "comp_lzo", "yes")
                backend.set_option("openvpn", "server_turris", "persist_key", store_bool(True))
                backend.set_option("openvpn", "server_turris", "persist_tun", store_bool(True))
                backend.set_option("openvpn", "server_turris", "status", "/tmp/openvpn-status.log")
                backend.set_option("openvpn", "server_turris", "verb", "3")
                backend.set_option("openvpn", "server_turris", "mute", "20")
                push = [
                    "route %s %s" % (IPv4.normalize_subnet(lan_ip, lan_netmask), lan_netmask)
                ]
                if route_all:
                    push.append("redirect-gateway def1")
                if use_dns:
                    # 10.111.111.0 -> 10.111.111.1
                    push.append(
                        "dhcp-option DNS %s" % IPv4.num_to_str(IPv4.str_to_num(network) + 1))
                backend.replace_list("openvpn", "server_turris", "push", push)

            else:
                backend.add_section("network", "interface", "vpn_turris")
                backend.set_option("network", "vpn_turris", "enabled", store_bool(False))
                backend.add_section("firewall", "zone", "vpn_turris")
                backend.set_option("firewall", "vpn_turris", "enabled", store_bool(False))
                backend.add_section("firewall", "rule", "vpn_turris_rule")
                backend.set_option("firewall", "vpn_turris_rule", "enabled", store_bool(False))
                backend.add_section("firewall", "forwarding", "vpn_turris_forward_lan_in")
                backend.set_option(
                    "firewall", "vpn_turris_forward_lan_in", "enabled", store_bool(False))
                backend.add_section("firewall", "forwarding", "vpn_turris_forward_lan_out")
                backend.set_option(
                    "firewall", "vpn_turris_forward_lan_out", "enabled", store_bool(False))
                backend.add_section("firewall", "forwarding", "vpn_turris_forward_wan_out")
                backend.set_option(
                    "firewall", "vpn_turris_forward_wan_out", "enabled", store_bool(False))
                backend.add_section("openvpn", "openvpn", "server_turris")
                backend.set_option("openvpn", "server_turris", "enabled", store_bool(False))

        with OpenwrtServices() as services:
            services.restart("openvpn")

        return True
