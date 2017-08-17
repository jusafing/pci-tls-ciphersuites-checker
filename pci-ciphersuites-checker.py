#!/usr/bin/env python
##############################################################################
# Description : Parser for TLS packets (PCI-PTS [Open Protocols] requirements)
#               It checks PCI-PTS v4.1b TLS/SSL Compliant Ciphersuites
# Author      : Javier S.A. (August 2017) [jusafing@jusanet.org]
#
##############################################################################

import sys
import logging
from scapy.all import *
from scapy.layers.ssl_tls import *
from scapy.layers import ssl_tls_registry

bind_layers(TCP, TLS, dport=4433)
bind_layers(TCP, TLS, sport=4433)

file_cap = sys.argv[1]
file_log = '/tmp/ciphersuites.log'
ciphers_must = {}
ciphers_may = {}

ciphers_must[0x000A] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
ciphers_must[0x002F] = "TLS_RSA_WITH_AES_128_CBC_SHA"
ciphers_must[0x009C] = "TLS_RSA_WITH_AES_128_GCM_SHA256"
ciphers_must[0x0035] = "TLS_RSA_WITH_AES_256_CBC_SHA"
ciphers_must[0x009D] = "TLS_RSA_WITH_AES_256_GCM_SHA384"
ciphers_must[0xC012] = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
ciphers_must[0xC013] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
ciphers_must[0xC027] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
ciphers_must[0xC02F] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
ciphers_must[0xC008] = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
ciphers_must[0xC009] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
ciphers_must[0xC023] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
ciphers_must[0xC02B] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
ciphers_must[0xC02C] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
ciphers_may[0xC014] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
ciphers_may[0x003C] = "TLS_RSA_WITH_AES_128_CBC_SHA256"
ciphers_may[0x003D] = "TLS_RSA_WITH_AES_256_CBC_SHA256"
ciphers_may[0xC09C] = "TLS_RSA_WITH_AES_128_CCM"
ciphers_may[0xC09D] = "TLS_RSA_WITH_AES_256_CCM"
ciphers_may[0xC00A] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
ciphers_may[0x0013] = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
ciphers_may[0x0032] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
ciphers_may[0x0038] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
ciphers_may[0x0040] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
ciphers_may[0x006A] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
ciphers_may[0x00A2] = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
ciphers_may[0x00A3] = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
ciphers_may[0x000D] = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"
ciphers_may[0x0030] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA"
ciphers_may[0x0036] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA"
ciphers_may[0x003E] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"
ciphers_may[0x0068] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"
ciphers_may[0x00A4] = "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"
ciphers_may[0x00A5] = "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"
ciphers_may[0xC003] = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"
ciphers_may[0xC004] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
ciphers_may[0xC005] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
ciphers_may[0xC025] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
ciphers_may[0xC026] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
ciphers_may[0xC02D] = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
ciphers_may[0xC02E] = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"


################################################################################
logger = logging.getLogger("brs-pci-fuzzing-usb-umap")
logging.basicConfig(filename=file_log,level=logging.DEBUG)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


################################################################################
def parsePcap(file_cap):
    """Open up a test pcap file and print out the packets"""
    cs_must_notfound = ciphers_must
    cs_fail = {}
    fails = 0
    dict_ssl = ssl_tls_registry.TLS_CIPHER_SUITE_REGISTRY

    logger.info("Opening file : %s", file_cap)
    pkt_cnt = 1
    for packet in rdpcap(file_cap):
        if packet.haslayer(TCP):
            logger.info("(Packet (%d): Read TCP packet ", pkt_cnt)
        if packet.haslayer(TLS):
            logger.info(" |-- Found TLS data (Packet number %d)", pkt_cnt)
            tcp = packet[TCP]
            logger.debug(" |-- (TLS data hexdump) : %s ", str(tcp.payload).encode("HEX"))
            if packet.haslayer(TLSClientHello):
                logger.info(" |-- ClientHello Packet found")
                for cs in packet[TCP][SSL][TLSHandshake][TLSClientHello].cipher_suites:
                    # logger.info("cheking :", cs, type(cs), hex(cs), type (hex(cs))
                    if cs in dict_ssl:
                        cipher_name = dict_ssl[cs]
                    else:
                        cipher_name = "(unknown name) ", str(cs)
                    logger.debug(" |-- Checking found Ciphersuite : %s (%s)", hex(cs), cipher_name)
                    # for csm in ciphers_must:
                    if cs in ciphers_must:
                        logger.info("   |-- Found REQUIRED     ciphersuite: %s (%s) (%s)" , cs, hex(cs), cipher_name )
                        cs_must_notfound.pop(cs, None)
                    elif cs in ciphers_may:
                        logger.info("   |-- Found ALLOWED      ciphersuite: %s (%s) (%s)", cs, hex(cs), cipher_name)
                    else:
                        logger.info("   |-- Found NOT ALLOWED  ciphersuite: %s (%s) (%s)", cs, hex(cs), cipher_name)
                        cs_fail[cs] = 1
            elif packet.haslayer(TLSServerHello):
                logger.info(" |-- ServerHello Packet found")
        pkt_cnt += 1

    logger.info("**************************")
    logger.info("**    S U M M A R Y     **")
    logger.info("**************************")
    if not len(cs_fail) == 0:
        logger.info("FAIL: The following NOT ALLOWED ciphersuites were found")
        for cs in cs_fail:
            if cs in dict_ssl:
                logger.info(" |--(Item:%d) NOT_ALLOWED : %s", fails,dict_ssl[cs])
            else:
                logger.info(" |--(Item:%d) NOT_ALLOWED : (Unknown name) %s", fails, hex(cs))
            fails += 1
    if not len(cs_must_notfound) == 0:
        logger.debug("FAIL: The following REQUIRED ciphersuites were not found")
        for cs in cs_must_notfound:
            logger.info(" |--(Item:%d) MUST cipher : %s", fails, dict_ssl[cs])
            fails += 1
    logger.info("")
    if fails > 0:
        logger.info("*******************************************")
        logger.info(" FINAL ASSESSMENT:  FAILED, NOT COMPLIANT")
        logger.info("                    (%d) items failed", fails)
        logger.info("*******************************************")
    else:
        logger.info("FINAL ASSESSMENT: ** PASSED, COMPLIANT **")


if __name__ == '__main__':
    parsePcap(file_cap)
