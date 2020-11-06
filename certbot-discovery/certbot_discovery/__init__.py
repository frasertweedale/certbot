"""
ACME Service Discovery for Certbot
"""
import argparse
import logging

import acme.client
import dns.rdatatype
import dns.resolver
import requests
import zope.interface

from certbot import interfaces
from certbot.plugins import common

logger = logging.getLogger(__name__)


@zope.interface.provider(interfaces.IPluginFactory)
class ACMEServiceDiscovery(common.Plugin):

    description = "ACME Service Discovery"

    @classmethod
    def inject_parser_options(cls, parser, name):
        """Inject parser options.

        Override superclass ``inject_parser_options`` definition to make
        ``--discovery`` the main option.

        """
        parser.add_argument(
            "--{0}".format(name),
            help="Enable service discovery",
            action=ServiceDiscoveryAction,
            dest='server',
            choices=['try', 'force', 'off'],
            default='try',
            nargs='?',
        )


class ServiceDiscoveryAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        if values is None:
            values = self.default

        if values == 'off':
            return

        parent_domains = choose_parent_domains()
        server = discover_server(parent_domains)

        if server is not None:
            setattr(namespace, self.dest, server)
        elif values == 'force':
            parser.error("service discovery failed")


def choose_parent_domains():
    """Choose (and sort) candidate parent domains."""

    parent_domains = []

    # search domains from resolv.conf(5)
    parent_domains.extend(dns.resolver.Resolver().search)

    # ensure subdomains are considered first
    parent_domains.sort(key=lambda n: len(n.labels), reverse=True)

    return parent_domains


def discover_server(parent_domains):
    """Given parent domains, perform service discovery."""

    for parent_domain in parent_domains:
        instances = dns_sd_enumerate_service_instances(
            'acme-server', 'tcp', parent_domain)

        servers = []
        for instance in instances:
            servers.extend(dns_sd_resolve_service_instance(instance))

        # filter out servers that do not support 'dns' identifier
        eligible_servers = [
            s for s in servers
            if server_supports_identifier_type(b'dns', s)
                and txt_get_path(s[1]) is not None
        ]

        # now sort by priority
        eligible_servers.sort(key=lambda x: x[0].priority)

        # try each server in order
        for srv, txt in eligible_servers:
            pat = "https://{domain}{path}" if srv.port == 443 \
                    else "https://{domain}:{port}{path}"
            uri = pat.format(
                domain=srv.target.relativize(dns.name.root),
                port=srv.port,
                path=txt_get_path(txt),
            )
            if check_uri(uri):
                return uri

    return None


def txt_get_path(txtstrings):
    """
    Return 'path' attribute as ``str``, or ``None`` if it is absent,
    cannot be decoded or doesn't start with '/'.

    """
    try:
        path = txt_get_attribute(b'path', txtstrings)
    except KeyError:
        return None  # path attribute is required

    if path is None:
        return None

    try:
        path_str = path.decode('ascii')
    except UnicodeDecodeError:
        return None

    if not path_str.startswith('/'):
        return None

    return path_str


def server_supports_identifier_type(itype, server):
    try:
        return txt_check_list_value(b'i', itype, server[1])
    except KeyError:
        return False  # 'i' attribute is required


def txt_check_list_value(key, value, txtstrings):
    """
    Check if the attribute, interpreted as a comma-separated list,
    contains the given value.  Return ``False`` if key is present
    with no value.  Raise ``KeyError`` if key is not present.

    """
    v = txt_get_attribute(key, txtstrings)
    return v is not None and value in v.split(b',')


def txt_get_attribute(key, txtstrings):
    """
    Get the attribute from the set of TXT strings.

    Return the value (which may be empty) or None if there is no
    value (distinct from empty value).  If the attribute is not
    present raise KeyError.

    """
    for s in txtstrings:
        kv = s.split(b'=', 1)
        if kv[0] == key:
            return kv[1] if len(kv) > 1 else None
    else:
        raise KeyError("Attribute not in TXT strings: {0}".format(key))


def dns_sd_enumerate_service_instances(service, proto, domain):
    """
    Enumerate service instances for the given service, protocol
    and parent domain.  Return a list of DNS naems.

    """
    parent = '_{0}._{1}.{2}'.format(service, proto, domain)
    try:
        answer = dns.resolver.query(parent, dns.rdatatype.PTR)
        return [x.target for x in answer if x.rdtype == dns.rdatatype.PTR]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []


def dns_sd_resolve_service_instance(name):
    """
    Resolve a DNS-SD service instance to its SRV and TXT records.
    The return list is NOT sorted by priority.

    Although DNS-SD requires TXT record for every service instances,
    per RFC 6763 §6.1 we treat missing TXT record the same as a
    single, empty TXT record.

    Return the cartesian product of SRV and TXT records.  (Per RFC
    6763 §6.8, where multiple TXT records exist, each describes a
    different variant of the same logical service).

    """
    try:
        answer = dns.resolver.query(name, dns.rdatatype.SRV)
        srvs = [x for x in answer if x.rdtype == dns.rdatatype.SRV]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        srvs = []

    try:
        answer = dns.resolver.query(name, dns.rdatatype.TXT)
        txts = [x.strings for x in answer if x.rdtype == dns.rdatatype.TXT]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        # treat missing TXT as single TXT with empty list of strings
        txts = [[]]

    return [(srv, txt) for srv in srvs for txt in txts]


def check_uri(uri):
    """Check that URI hosts an ACME directory resource."""

    logger.info('ACME-SD: check URI {0}'.format(uri))

    # We don't need a key to retrieve the directory object
    key = None
    net = acme.client.ClientNetwork(key)

    try:
        # constructor fetches, parses and inspects a directory object
        client = acme.client.BackwardsCompatibleClientV2(net, key, uri)

    except (
            ValueError,  # connection refused
            requests.exceptions.ConnectionError,  # name or service not known
            acme.errors.ClientError, # non-2xx response, unexpected response type
    ) as e:
        # These are expected failure modes
        logger.info('ACME-SD: failed to reach server: {0}'.format(e))
        return False

    except Exception as e:
        # This was an unexpected error
        logger.warn(
            'ACME-SD: unexpected error while attempting to reach server: {0}'
            .format(e)
        )
        return False

    # check for newNonce or new-reg fields to have confidence that the
    # target is actually an ACME server
    if (
        hasattr(client.directory, 'newNonce')
        or hasattr(client.directory, 'new-reg')
    ):
        logger.info('ACME-SD: success')
        return True
    else:
        logger.info('ACME-SD: response is not an ACME directory object')
        return False
