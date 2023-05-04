#
# Copyright (C) 2023  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import ldap
import logging
from io import StringIO
from ldap.cidict import cidict
from ldap.ldapobject import ReconnectLDAPObject
from ldap.syncrepl import SyncreplConsumer
from ldif import LDIFParser

from ipalib import constants, errors
from ipaplatform.paths import paths
from ipapython import ipaldap
from ipapython.dn import DN


logger = logging.getLogger(__name__)

OBJCLASS_ATTR = 'objectClass'
DNS_COOKIE = "/var/lib/ipa/dns_cookie"


class ReconnectLDAPClient(ipaldap.LDAPClient):
    """LDAPClient able to reconnect in case of server failure.

    In case of server failure (ldap.SERVER_DOWN) the implementations
    of all synchronous operation methods (search_s() etc.) are doing
    an automatic reconnect and rebind and will retry the very same
    operation.
    """
    def __init__(self, ldap_uri, start_tls=False, force_schema_updates=False,
                 no_schema=False, decode_attrs=True, cacert=None,
                 sasl_nocanon=True, retry_max=1, retry_delay=60):
        self.retry_max = retry_max
        self.retry_delay = retry_delay
        ipaldap.LDAPClient.__init__(
            self,
            ldap_uri=ldap_uri, start_tls=start_tls,
            force_schema_updates=force_schema_updates,
            no_schema=no_schema, decode_attrs=decode_attrs, cacert=cacert,
            sasl_nocanon=sasl_nocanon)

    def _connect(self):
        with self.error_handler():
            conn = ldap.ldapobject.ReconnectLDAPObject(
                self.ldap_uri,
                retry_max=self.retry_max, retry_delay=self.retry_delay)
            # SASL_NOCANON is set to ON in Fedora's default ldap.conf and
            # in the ldap_initialize() function.
            if not self._sasl_nocanon:
                conn.set_option(ldap.OPT_X_SASL_NOCANON, ldap.OPT_OFF)

            if self._start_tls and self.protocol == 'ldap':
                # STARTTLS applies only to ldap:// connections
                conn.start_tls_s()

        return conn


class AddLDIF(LDIFParser):
    def __init__(self, input, conn):
        LDIFParser.__init__(self, StringIO(input))
        self._conn = conn

    def handle(self, dn, entry):
        try:
            newentry = self._conn.make_entry(DN(dn), entry)
            self._conn.add_entry(newentry)
        except errors.DuplicateEntry:
            logger.error("Entry %s already exists", dn)


class DNSSyncer(ReconnectLDAPObject, SyncreplConsumer):
    def __init__(self, *args, **kwargs):
        self.api = kwargs['ipa_api']
        del kwargs['ipa_api']

        # Initialise the LDAP Connection first
        ldap.ldapobject.ReconnectLDAPObject.__init__(self, *args, **kwargs)
        # Now prepare the data store
        self.__data = dict()

        self.idnszone_dn = DN(self.api.env.container_dns, self.api.env.basedn)
        self.idnsrecord_dn = DN(self.api.env.container_dns, self.api.env.basedn)

        ldapuri_ds = ipaldap.get_ldap_uri(realm=self.api.env.realm,
                                          protocol='ldapi')
        self.ds_conn = ipaldap.LDAPClient(ldapuri_ds)
        self.ds_conn.external_bind()

        self.dns_conn = ReconnectLDAPClient(ldapuri_ds)
        self.dns_conn.external_bind()
        self.init_done = False

        self._init_data()

        self.application_add = {b'idnsrecord': self.idnsrecord_add,
                                b'idnszone': self.idnszone_add}
        self.application_mod = {b'idnsrecord': self.idnsrecord_mod,
                                b'idnszone': self.idnszone_mod}
        self.application_del = {b'idnsrecord': self.idnsrecord_del,
                                b'idnszone': self.idnszone_del}

    def _init_data(self):
        """Initialize the internal data from the content of DNS.

        Read the DNS idnsrecord and idnszone entries in LDAP in order to build
        the initial __data structure.
        They are needed to properly process the syncrepl callbacks.
        """
        # Read DNS entries from LDAP
        dns_objects = {
            'idnsrecord': {
                'filter': "(objectclass=idnsrecord)",
                'objclass': b'idnsrecord',
                'orig_dn_format': "idnsname={},idnsname={}",
                'orig_dn_container': self.idnsrecord_dn,
                'orig_dn_attr': 'idnsname',
            },
            'idnszone': {
                'filter': "(objectclass=idnszone)",
                'objclass': b'idnsrecord',
                'orig_dn_format': 'idnsname={}',
                'orig_dn_container': self.idnszone_dn,
                'orig_dn_attr': 'idnsname',
            }
        }
        for object in dns_objects.values():
            logger.info("DNS object %s", object)
            try:
                entries, _truncated = self.dns_conn.find_entries(
                    filter=object['filter'],
                    attrs_list=['idnsName', 'cn'],
                    base_dn=DN("cn=dns", self.api.env.basedn),
                    scope=ldap.SCOPE_SUBTREE, time_limit=None, size_limit=None)

                for entry in entries:
                    logger.info("DNS Entry %s", entry)
                    entry_dict = dict()
                    entry_dict['objectclass'] = object['objclass']
                    # Set the originating DN on DS side
                    entry_dict['dn'] = object['orig_dn_format'].format(
                        entry[object['orig_dn_attr']][0],
                        object['orig_dn_container'])

            except errors.EmptyResult:
                # this is not supposed to happen
                pass

        # Read the last cookie that was processed before shutdown
        cookie = self._get_saved_cookie()
        self.syncrepl_set_cookie(cookie)

    def shutdown(self):
        """Properly stop the syncer.

        Save the last known cookie to a persistent file.
        """
        logger.debug("save cookie")
        cookie = self.syncrepl_get_cookie()
        if cookie:
            # TODO DNS_KEYTAB = "/etc/dirsrv/dns.keytab"
            with open(DNS_COOKIE, 'w') as f:
                f.write(cookie)

    def _get_saved_cookie(self):
        """Get the last known cookie from a persistent file.

        Returns None if the file does not exist or is empty.
        """
        logger.debug("get_saved_cookie")
        cookie = None
        try:
            with open(DNS_COOKIE) as f:
                content = f.read()
            # if the content is an empty string, simply return None
            if content:
                cookie = content.strip()
                logger.debug("Read cookie %s", cookie)
        except FileNotFoundError:
            # It's ok if no cookie was saved, it may be the first run
            pass
        return cookie

    def _get_objclass(self, attrs):
        """Get object class.

        Given the set of attributes, find the main object class.
        idnszone, idnsrecord, iforwardingzone, idnsconfig...
        """
        #present_objclasses = set(
        #    o.lower() for o in attrs[OBJCLASS_ATTR]
        #)
        #oc = None
        #if b'idnsTemplateObject' in present_objclasses:
        #    oc = b'idnsrecord'
        #elif b'idnsConfigObject' in present_objclasses:
        #    oc = b'idnsConfigObject'
        #elif b'idnszone' in present_objclasses:
            # For dnszones 
            # there are idnszone and idnsrecord
        #    oc = b'idnszone'
        return b'idnsrecord'

    # ----------------
    # syncrepl methods
    # ----------------
    def syncrepl_get_cookie(self):
        if 'cookie' in self.__data:
            cookie = self.__data['cookie']
            logger.debug('Current cookie is: %s', cookie)
            return cookie
        else:
            logger.debug('Current cookie is: None (not received yet)')
            return None

    def syncrepl_set_cookie(self, cookie):
        logger.debug('New cookie is: %s', cookie)
        if cookie and cookie.endswith('#4294967295'):
            # Workaround for syncrepl issue 51190
            # https://pagure.io/389-ds-base/issue/51190
            # Just ignore this cookie and keep the previous one
            logger.debug("Ignoring cookie value")
            return
        self.__data['cookie'] = cookie

    def syncrepl_entry(self, dn, attributes, uuid):
        attributes = cidict(attributes)
        # First we filter entries that are not interesting for us
        logger.info("syncrepl_entry for %s", dn)
        return

    def syncrepl_delete(self, uuids):
        logger.debug('Detected deletion of entry: %s', uuid)

    def syncrepl_present(self, uuids, refreshDeletes=False):
        logger.debug('syncrepl present')

    def syncrepl_refreshdone(self):
        """Callback triggered when the initial dump of DS content is done."""
        logger.info('Initial LDAP dump is done, now synchronizing with DNS')
        self.init_done = True

    # ---------------------
    # idnsrecord operations
    # ---------------------
    def idnsrecord_add(self, uuid, entry_dn, newattrs):
        """Add a new idnsrecord in the DNS."""
        logger.debug("idnsrecord_add %s", entry_dn)
        dn = DN(entry_dn)

        # TODO Create a new dnsrecord entry from the attributes read in DS,
        # and add the entry to the dnszone
        logger.debug("Adding idnsrecord to the zone")

    def idnsrecord_del(self, uuid, entry_dn, oldattrs):
        """Remove an existing dnsrecord from the dnszone"""
        logger.debug("idnsrecord_del %s", entry_dn)

        # The corresponding DNS entry must also be deleted but its DNS-side DN
        # must be evaluated first by using the cn value.
        old_cn = oldattrs['cn']
        dns_dn = get_dn_from_cn(self.api, old_cn)

        logger.debug("Deleting idnsrecord from the idnszone %s", dns_dn)
        try:
            self.dns_conn.delete_entry(dns_dn)
        except errors.NotFound:
            logger.warning("Entry already deleted %s", dns_dn)

    def idnsrecord_mod(self, uuid, entry_dn, newattrs, oldattrs):
        """Modify an existing idnsrecord"""
        logger.debug("user_sync %s", entry_dn)

        logger.debug("Syncing idnsrecord (del+add)")
        self.idnsrecord_del(uuid, oldattrs['dn'], oldattrs)
        self.idnsrecord_add(uuid, entry_dn, newattrs)

        # Warning: if the updated attribute is cn, we need to also update
        # all the dnszones that contain this user as the DN of this entry
        # has changed on DNS side, but not on DS side
        if oldattrs['cn'] != newattrs['cn'][0].decode('utf-8'):
            logger.debug("Need to update member: attribute in dnszones")
            old_member = get_dn_from_cn(self.api, oldattrs['cn'])
            new_member = get_dn_from_cn(self.api,
                                        newattrs['cn'][0].decode('utf-8'))
            for dnszone in newattrs.get('memberof', []):
                dns_idnszone_dn = rename_idnszone_dn(self.api,
                                              DN(dnszone.decode('utf-8')))
                mods = [(ldap.MOD_DELETE, 'member', old_member),
                        (ldap.MOD_ADD, 'member', new_member)]
                self.dns_conn.modify_s(dns_idnszone_dn, mods)

    # ------------------
    # dnszone operations
    # ------------------
    def idnszone_add(self, uuid, entry_dn, newattrs):
        """Add a new dnszone in the DNS"""
        logger.debug("idnszone_add %s", entry_dn)
        dn = DN(entry_dn)

        # Create a new dnszone entry from the attributes read in DS,
        logger.debug("Adding dnszone")

    def idnszone_del(self, uuid, entry_dn, oldattrs):
        """Remove an existing dnszone"""
        logger.debug("idnszone_del %s", entry_dn)

    def idnszone_mod(self, uuid, entry_dn, newattrs, oldattrs):
        """Modify an existing dnszone"""
        logger.debug("dnszone_sync %s", entry_dn)

        logger.debug("Syncing dnszone (del+add)")
        self.idnszone_del(uuid, oldattrs['dn'], oldattrs)
        self.idnszone_add(uuid, entry_dn, newattrs)
