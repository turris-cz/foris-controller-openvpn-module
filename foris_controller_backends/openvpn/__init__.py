#
# foris-controller-openvpn-module
# Copyright (C) 2018-2025 CZ.NIC, z.s.p.o. (https://www.nic.cz/)
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

import ipaddress
import logging
import os
import re
import typing
from collections import defaultdict
from datetime import datetime

from foris_controller import utils
from foris_controller.exceptions import UciRecordNotFound
from foris_controller_backends.cmdline import AsyncCommand, BaseCmdLine
from foris_controller_backends.files import BaseFile, inject_file_root
from foris_controller_backends.lan import LanUci
from foris_controller_backends.maintain import MaintainCommands
from foris_controller_backends.services import OpenwrtServices
from foris_controller_backends.uci import (
    UciBackend,
    UciException,
    get_option_named,
    parse_bool,
    store_bool,
)
from foris_controller_backends.networks import NetworksCmd

logger = logging.getLogger(__name__)


class CaGenAsync(AsyncCommand):
    def generate_ca(self, notify_function, exit_notify_function, reset_notify_function):
        def handler_exit(process_data):
            exit_notify_function(
                {
                    "task_id": process_data.id,
                    "status": "succeeded" if process_data.get_retval() == 0 else "failed",
                }
            )

        def gen_handler(status):
            def handler(matched, process_data):
                notify_function({"task_id": process_data.id, "status": status})

            return handler

        task_id = self.start_process(
            ["/usr/bin/turris-cagen", "new_ca", "openvpn", "gen_ca", "link_dh", "gen_server", "turris"],
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
            exit_notify_function(
                {
                    "task_id": process_data.id,
                    "name": name,
                    "status": "succeeded" if process_data.get_retval() == 0 else "failed",
                }
            )

        def gen_handler(status):
            def handler(matched, process_data):
                notify_function({"task_id": process_data.id, "status": status, "name": name})

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


class StatusFileReader:
    OPENVPN_STATUS_FILE = "/tmp/openvpn-status.log"
    HEADER = "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since"

    @classmethod
    def get_connections(cls) -> typing.Dict[str, dict]:
        """ Reads info regarding current connections """
        res = defaultdict(list)
        try:
            with open(inject_file_root(cls.OPENVPN_STATUS_FILE)) as file:
                in_section = False
                for line in file:
                    line = line.strip()
                    if line == "ROUTING TABLE":
                        break
                    if not in_section:
                        if line == cls.HEADER:
                            in_section = True
                    else:
                        (
                            name, ip_and_port, in_bytes, out_bytes, since
                        ) = line.rsplit(",", 4)
                        ip, port = ip_and_port.rsplit(":", 1)
                        ip = str(ipaddress.ip_address(ip.strip("[]")))
                        since = datetime.fromisoformat(since).isoformat()
                        res[name].append({
                            "address": ip,
                            "port": int(port),
                            "in_bytes": int(in_bytes),
                            "out_bytes": int(out_bytes),
                            "connected_since": since
                        })
        except Exception as e:
            logger.warning("Failed to read connection from openvpn status file", exc_info=e)
            # Don't crash when an error occurs
            # this should provide additional info only
            return {}

        return res


class CaGenCmds(BaseCmdLine):
    def get_status(self):
        output, _ = self._run_command_and_check_retval(
            ["/usr/bin/turris-cagen-status", "openvpn"], 0
        )
        connections = StatusFileReader.get_connections()
        output = output.decode("utf-8")
        ca_status = re.search(r"^status: (\w+)$", output, re.MULTILINE).group(1)
        clients = []
        in_cert_section = False
        server_cert_found = False
        for line in output.split("\n"):
            if in_cert_section:
                try:
                    cert_id, cert_type, name, status = line.split(" ")
                    if cert_type == "client":
                        clients.append(
                            {
                                "id": cert_id,
                                "name": name,
                                "status": status,
                                "connections": connections.get(name, []),
                            }
                        )
                    elif cert_type == "server" and status == "valid":
                        server_cert_found = True
                except ValueError:
                    continue
            if line == "## Certs:":
                in_cert_section = True

        # if server cert is missing this means that openvpn CA hasn't been generated yet
        ca_status = "generating" if ca_status == "ready" and not server_cert_found else ca_status

        return {"status": ca_status, "clients": clients}

    def revoke(self, cert_id):
        retval, _, _ = self._run_command(
            "/usr/bin/turris-cagen", "switch", "openvpn", "revoke", cert_id
        )
        return retval == 0

    def delete_ca(self):
        retval, _, _ = self._run_command("/usr/bin/turris-cagen", "drop_ca", "openvpn")
        return retval == 0


class OpenvpnUci:
    DEFAULTS = {
        "enabled": False,
        "network": "10.111.111.0",
        "network_netmask": "255.255.255.0",
        "routes": [],
        "device": "",
        "protocol": "",
        "port": 1194,
        "route_all": False,
        "use_dns": False,
    }

    @staticmethod
    def get_settings():
        with UciBackend() as backend:
            data = backend.read("openvpn")
            foris_data = backend.read("foris")

        try:
            enabled = parse_bool(get_option_named(data, "openvpn", "server_turris", "enabled", "0"))
            network, network_netmask = get_option_named(
                data, "openvpn", "server_turris", "server", "10.111.111.0 255.255.255.0"
            ).split()
            push_options = get_option_named(data, "openvpn", "server_turris", "push", [])
            routes = [
                dict(zip(("network", "netmask"), e.split()[1:]))  # `route <network> <netmask>`
                for e in push_options
                if e.startswith("route ")
            ]
            device = get_option_named(data, "openvpn", "server_turris", "dev", "")
            protocol = get_option_named(data, "openvpn", "server_turris", "proto", "udp")
            ipv6 = "6" in protocol  # tcp6-server, udp6
            protocol = "tcp" if protocol.startswith("tcp") else "udp"
            port = int(get_option_named(data, "openvpn", "server_turris", "port", "0"))
            use_dns = (
                True if [e for e in push_options if e.startswith("dhcp-option DNS")] else False
            )
            route_all = True if [e for e in push_options if e == "redirect-gateway def1"] else False
            server_hostname = get_option_named(
                foris_data, "foris", "openvpn_plugin", "server_address", ""
            )

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
            "server_hostname": server_hostname,
            "ipv6": ipv6,
        }

    @staticmethod
    def update_settings(
        enabled,
        network=None,
        network_netmask=None,
        route_all=None,
        use_dns=None,
        protocol=None,
        ipv6=None,
    ):
        with UciBackend() as backend:
            network_data = backend.read("network")
            OpenvpnUci._migrate_old_config_syntax(backend, network_data)

            if enabled:
                lan_ip, lan_netmask, _ = LanUci.get_network_combo(network_data)
                lan_network_addr = utils.ip_network_address(lan_ip, lan_netmask)

                backend.add_section("network", "interface", "vpn_turris")
                backend.set_option("network", "vpn_turris", "enabled", store_bool(True))
                backend.set_option("network", "vpn_turris", "device", "tun_turris")
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
                backend.set_option("firewall", "vpn_turris_rule", "proto", protocol)
                backend.set_option("firewall", "vpn_turris_rule", "src", "wan")
                backend.set_option("firewall", "vpn_turris_rule", "dest_port", "1194")
                backend.add_section("firewall", "forwarding", "vpn_turris_forward_lan_in")
                backend.set_option(
                    "firewall", "vpn_turris_forward_lan_in", "enabled", store_bool(True)
                )
                backend.set_option("firewall", "vpn_turris_forward_lan_in", "src", "vpn_turris")
                backend.set_option("firewall", "vpn_turris_forward_lan_in", "dest", "lan")
                backend.add_section("firewall", "forwarding", "vpn_turris_forward_lan_out")
                backend.set_option(
                    "firewall", "vpn_turris_forward_lan_out", "enabled", store_bool(True)
                )
                backend.set_option("firewall", "vpn_turris_forward_lan_out", "src", "lan")
                backend.set_option("firewall", "vpn_turris_forward_lan_out", "dest", "vpn_turris")
                backend.add_section("firewall", "forwarding", "vpn_turris_forward_wan_out")
                backend.set_option(
                    "firewall",
                    "vpn_turris_forward_wan_out",
                    "enabled",
                    store_bool(True if route_all else False),
                )
                backend.set_option("firewall", "vpn_turris_forward_wan_out", "src", "vpn_turris")
                backend.set_option("firewall", "vpn_turris_forward_wan_out", "dest", "wan")

                backend.add_section("openvpn", "openvpn", "server_turris")
                backend.set_option("openvpn", "server_turris", "enabled", store_bool(True))
                backend.set_option("openvpn", "server_turris", "port", "1194")
                if ipv6:
                    proto = "tcp6-server" if protocol == "tcp" else "udp6"
                else:
                    proto = "tcp-server" if protocol == "tcp" else "udp"
                backend.set_option("openvpn", "server_turris", "proto", proto)
                backend.set_option("openvpn", "server_turris", "dev", "tun_turris")
                backend.set_option("openvpn", "server_turris", "ca", "/etc/ssl/ca/openvpn/ca.crt")
                backend.set_option(
                    "openvpn", "server_turris", "crl_verify", "/etc/ssl/ca/openvpn/ca.crl"
                )
                backend.set_option("openvpn", "server_turris", "cert", "/etc/ssl/ca/openvpn/01.crt")
                backend.set_option("openvpn", "server_turris", "key", "/etc/ssl/ca/openvpn/01.key")
                backend.set_option("openvpn", "server_turris", "dh", "/etc/ssl/ca/openvpn/dhparam.pem")
                backend.set_option(
                    "openvpn", "server_turris", "server", "%s %s" % (network, network_netmask)
                )
                backend.set_option(
                    "openvpn", "server_turris", "ifconfig_pool_persist", "/tmp/ipp.txt"
                )
                backend.set_option("openvpn", "server_turris", "duplicate_cn", store_bool(False))
                backend.set_option("openvpn", "server_turris", "keepalive", "10 120")
                backend.set_option("openvpn", "server_turris", "persist_key", store_bool(True))
                backend.set_option("openvpn", "server_turris", "persist_tun", store_bool(True))
                backend.set_option("openvpn", "server_turris", "status", "/tmp/openvpn-status.log")
                backend.set_option("openvpn", "server_turris", "verb", "3")
                backend.set_option("openvpn", "server_turris", "mute", "20")
                backend.set_option("openvpn", "server_turris", "topology", "subnet")
                push = [f"route {lan_network_addr} {lan_netmask}"]
                if route_all:
                    push.append("redirect-gateway def1")
                if use_dns:
                    # 10.111.111.0 -> 10.111.111.1
                    # TODO this won't work when router ip is set to a different address
                    push.append(
                        f"dhcp-option DNS {ipaddress.ip_network(network, False).network_address + 1}"
                    )
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
                    "firewall", "vpn_turris_forward_lan_in", "enabled", store_bool(False)
                )
                backend.add_section("firewall", "forwarding", "vpn_turris_forward_lan_out")
                backend.set_option(
                    "firewall", "vpn_turris_forward_lan_out", "enabled", store_bool(False)
                )
                backend.add_section("firewall", "forwarding", "vpn_turris_forward_wan_out")
                backend.set_option(
                    "firewall", "vpn_turris_forward_wan_out", "enabled", store_bool(False)
                )
                backend.add_section("openvpn", "openvpn", "server_turris")
                backend.set_option("openvpn", "server_turris", "enabled", store_bool(False))

        with OpenwrtServices() as services:
            MaintainCommands().restart_network()
            services.restart("openvpn", delay=3)

        return True

    @staticmethod
    def reload_settings() -> None:
        """ Trigger reload of openvpn server settings

        Some config values are derived from network uci config, but only during update_settings()
        Therefore we need a way to trigger re-read of such settings, when changes in network configuration occur
        """
        requested_args = [
            "enabled", "network", "network_netmask", "route_all", "use_dns", "protocol", "ipv6"
        ]
        current_settings = OpenvpnUci.get_settings()
        new_settings = {
            key: val for key, val in current_settings.items()
            if key in requested_args
        }

        OpenvpnUci.update_settings(**new_settings)

    @staticmethod
    def _migrate_old_config_syntax(backend: UciBackend, data: dict) -> None:
        """Migrate old style (OpenWrt <=19.07) config syntax to new style (OpenWrt 21.02) syntax"""
        try:
            if get_option_named(data, "network", "vpn_turris", "ifname", ""):
                # change "ifname" -> "device"
                backend.del_option("network", "vpn_turris", "ifname", fail_on_error=False)
                backend.set_option("network", "vpn_turris", "device", "tun_turris")
        except UciRecordNotFound:
            return

    def update_server_hostname(self, server_hostname):
        with UciBackend() as backend:
            try:
                if server_hostname:
                    backend.add_section("foris", "config", "openvpn_plugin")
                    backend.set_option("foris", "openvpn_plugin", "server_address", server_hostname)
                else:
                    backend.del_option("foris", "openvpn_plugin", "server_address")
            except UciException:
                pass  # best effort (foris doesn't need to be installed...)

    def get_options_for_client(self):
        with UciBackend() as backend:
            data = backend.read("openvpn")

        dev = get_option_named(data, "openvpn", "server_turris", "dev", "tun_turris")
        proto = get_option_named(data, "openvpn", "server_turris", "proto", "udp")
        port = get_option_named(data, "openvpn", "server_turris", "port", "1194")
        ca_path = get_option_named(
            data, "openvpn", "server_turris", "ca", "/etc/ssl/ca/openvpn/ca.crt"
        )
        compress = get_option_named(data, "openvpn", "server_turris", "compress", "")

        # handle server in old configuration (can be removed once we migrate to openvpn 2.5)
        if not compress:
            old_lzo_present = parse_bool(
                get_option_named(data, "openvpn", "server_turris", "comp_lzo", "0")
            )
            compress = "lzo" if old_lzo_present else ""

        cipher = get_option_named(data, "openvpn", "server_turris", "cipher", "")
        tls_auth_path = get_option_named(data, "openvpn", "server_turris", "tls_auth", "")
        return {
            "dev": dev,
            "proto": proto,
            "port": port,
            "ca_path": ca_path,
            "compress": compress,
            "cipher": cipher,
            "tls_auth_path": tls_auth_path,
        }


class OpenvpnFiles(BaseFile):
    CONFIG_TEMPLATE = """
##############################################
# Openvpn client configuration generated by  #
# router Turris based on Sample client-side  #
# OpenVPN 2.0 config file                    #
#                                            #
# This configuration can be used only on     #
# a single client.                           #
#                                            #
#                                            #
# On Windows, you might want to rename this  #
# file so it has a .ovpn extension           #
##############################################

client

# Use the same setting as you are using on
# the server.
# On most systems, the VPN will not function
# unless you partially or fully disable
# the firewall for the TUN/TAP interface.
dev %(dev)s

# Windows needs the TAP-Win32 adapter name
# from the Network Connections panel
# if you have more than one.  On XP SP2,
# you may need to disable the firewall
# for the TAP adapter.
;dev-node MyTap

proto %(proto)s

# The hostname/IP and port of the server.
# You can have multiple remote entries
# to load balance between the servers.
;remote my-server-1 1194
;remote my-server-2 1194
remote %(hostname)s %(port)s %(proto_remote)s

# Choose a random host from the remote
# list for load-balancing.  Otherwise
# try hosts in the order specified.
;remote-random

# Keep trying indefinitely to resolve the
# host name of the OpenVPN server.  Very useful
# on machines which are not permanently connected
# to the internet such as laptops.
resolv-retry infinite

# Most clients don't need to bind to
# a specific local port number.
nobind

# Downgrade privileges after initialization (non-Windows only)
;user nobody
;group nobody

# Try to preserve some state across restarts.
persist-key
persist-tun

# If you are connecting through an
# HTTP proxy to reach the actual OpenVPN
# server, put the proxy server/IP and
# port number here.  See the man page
# if your proxy server requires
# authentication.
;http-proxy-retry # retry on connection failures
;http-proxy [proxy server] [proxy port #]

# Wireless networks often produce a lot
# of duplicate packets.  Set this flag
# to silence duplicate packet warnings.
mute-replay-warnings

<ca>
%(ca)s
</ca>
<cert>
%(cert)s
</cert>
<key>
%(key)s
</key>

remote-cert-tls server

%(tls_auth_section)s

%(cipher_section)s

%(compress)s

# Set log file verbosity.
verb 3

# Silence repeating messages
;mute 20

# To enable to process DNS push request from the server on linux machines (non systemd-resolved)
# note that you might need to have resolvconf program installed
;script-security 2
;up /etc/openvpn/update-resolv-conf
;down /etc/openvpn/update-resolv-conf

# To enable to process DNS push request from the server on linux machines (systemd-resolved)
# see https://github.com/jonathanio/update-systemd-resolved
;script-security 2
;setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
;up /etc/openvpn/update-systemd-resolved
;down /etc/openvpn/update-systemd-resolved
;down-pre
"""

    BASE_CERT_PATH = "/etc/ssl/ca/openvpn"

    # pairs of server_proto <-> client_proto
    # used for generating proper client config
    #
    # for instance: TCP needs different proto on server and client
    # tcp-server (server) and tcp-client (client)
    # For more details see OpenVPN manual.
    PROTOCOLS_MAP = {
        "tcp": "tcp",
        "udp": "udp",  # server IPv4 -> client IPv4/6
        "tcp-server": "tcp-client",
        "tcp4": "tcp",
        "udp4": "udp",  # server IPv4 -> client IPv4/6
        "tcp4-server": "tcp-client",
        "tcp6": "tcp",
        "udp6": "udp",  # server IPv4/6 -> client IPv4/6
        "tcp6-server": "tcp-client",
    }

    def get_config(self, id, hostname, dev, proto, port, compress, cipher, tls_auth_path, ca_path):
        ca = self._file_content(ca_path)
        cert = self._file_content(os.path.join(self.BASE_CERT_PATH, "%s.crt" % id))
        key = self._file_content(os.path.join(self.BASE_CERT_PATH, "%s.key" % id))

        if not hostname:
            # try to figure out wan ip
            try:
                if "6" in proto:
                    # Extract ipv6 address into config
                    addresses = NetworksCmd().get_network_info("wan6")["ipv6"]
                    # only global
                    addresses = [
                        e for e in addresses if ipaddress.ip_address(e).is_global
                    ]
                else:
                    # Extract ipv4 address into config
                    addresses = NetworksCmd().get_network_info("wan")["ipv4"]
                hostname = addresses[0]
            except Exception as e:
                logger.warning("%r", e)
                hostname = "<server_address>"

        cipher_section = "cipher %s" % cipher if cipher else ""
        if tls_auth_path:
            tls_auth = self._file_content(tls_auth_path)
            tls_auth_section = "key-direction 1\n<tls-auth>\n%s\n</tls-auth>" % tls_auth
        else:
            tls_auth_section = ""
        compress = "compress %s" % compress if compress else ""

        # Derive correct 'proto' for client from server 'proto'
        # If unsure, fallback to udp - aka UDP on IPv4/6
        proto = self.PROTOCOLS_MAP.get(proto, "udp")

        return self.CONFIG_TEMPLATE % dict(
            dev=dev,
            proto=proto.replace("server", "client"),
            proto_remote=proto.split("-", 1)[0],  # udp{4,6} / tcp{4,6}
            port=port,
            hostname=hostname,
            ca=ca,
            cert=cert,
            key=key,
            tls_auth_section=tls_auth_section,
            cipher_section=cipher_section,
            compress=compress,
        )
