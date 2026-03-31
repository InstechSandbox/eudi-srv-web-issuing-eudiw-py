# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""
The PID Issuer Web service is a component of the PID Provider backend.
Its main goal is to issue the PID in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.

This config_countries.py contains configuration data related to the countries supported by the PID Issuer.

NOTE: You should only change it if you understand what you're doing.
"""

import os
from .config_service import ConfService as cfgserv

EIDAS_LOA_HIGH = "http://eidas.europa.eu/LoA/high"

eidas_node_connector_url = os.getenv(
    "EIDAS_NODE_CONNECTOR_URL",
    "test",
)

eidas_node_client_id = os.getenv(
    "EIDAS_NODE_CLIENT_ID",
    "test",
)

eidas_node_client_secret = os.getenv(
    "EIDAS_NODE_CLIENT_SECRET",
    "test",
)

pt_client_id = os.getenv(
    "PT_CLIENT_ID",
    "test",
)

pt_client_secret = os.getenv(
    "PT_CLIENT_SECRET",
    "test",
)

ee_client_id = os.getenv(
    "EE_CLIENT_ID",
    "test",
)

ee_auth_header = os.getenv(
    "EE_BASIC_AUTHORIZATION_HEADER",
    "test",
)

ee_redirect_uri = os.getenv(
    "EE_REDIRECT_URI",
    "test",
)


def _resolve_first_existing(candidates):
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[0]


def _resolve_utopia_privkey_and_password():
    candidates = [
        (cfgserv.privKey_path + "PID-DS-0001_UT.pem", None),
        (cfgserv.privKey_path + "PID-DS-0002-decrypted.key.pem", None),
        (cfgserv.privKey_path + "PID-DS-0002.pid-ds-0002.key.pem", b"pid-ds-0002"),
    ]

    primary_candidate = candidates[0]
    if os.path.exists(primary_candidate[0]):
        return primary_candidate

    if not cfgserv.allow_local_utopia_signer_fallback:
        return primary_candidate

    for path, password in candidates:
        if os.path.exists(path):
            return path, password

    return primary_candidate


UTOPIA_PID_MDOC_PRIVKEY, UTOPIA_PID_MDOC_PRIVKEY_PASSWORD = (
    _resolve_utopia_privkey_and_password()
)
UTOPIA_PID_MDOC_CERT = _resolve_first_existing(
    [cfgserv.trusted_CAs_path + "PID-DS-0001_UT_cert.der"]
    if not cfgserv.allow_local_utopia_signer_fallback
    else [
        cfgserv.trusted_CAs_path + "PID-DS-0001_UT_cert.der",
        cfgserv.trusted_CAs_path + "PID-DS-0002.cert.der",
    ]
)


def _resolve_age_verification_signer():
    default_privkey = cfgserv.privKey_path + "AgeVerificationDS-001.pem"
    fallback_privkeys = [
        default_privkey,
        cfgserv.privKey_path + "PID-DS-0002-decrypted.key.pem",
    ]
    default_cert = cfgserv.trusted_CAs_path + "AgeVerificationDS-001_cert.der"
    fallback_certs = [
        default_cert,
        cfgserv.trusted_CAs_path + "PID-DS-0002.cert.der",
    ]

    if not cfgserv.allow_local_utopia_signer_fallback:
        return default_privkey, default_cert

    return (
        _resolve_first_existing(fallback_privkeys),
        _resolve_first_existing(fallback_certs),
    )


AGE_VERIFICATION_MDOC_PRIVKEY, AGE_VERIFICATION_MDOC_CERT = (
    _resolve_age_verification_signer()
)


class ConfCountries:
    urlReturnEE = "https://pprpid.provider.eudiw.projj.eu/tara/redirect"

    formCountry = "FC"
    # supported countries
    supported_countries = {
        "EU": {
            "name": "nodeEU",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=EU",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0001_EU.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0001_EU.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes,
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0001_EU_cert.der",
            "loa": EIDAS_LOA_HIGH,
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
                "eu.europa.ec.eudi.pid_mdoc_deferred",
            ],
            "custom_modifiers": {
                "family_name": "CurrentFamilyName",
                "given_name": "CurrentGivenName",
                "birth_date": "DateOfBirth",
            },
            "connection_type": "oauth",
            "oauth_auth": {
                "base_url": eidas_node_connector_url,
                "redirect_uri": f"{cfgserv.service_url}dynamic/redirect",
                "scope": "profile",
                "state": "hkMVY7vjuN7xyLl5",
                "response_type": "code",
                "client_id": eidas_node_client_id,
                "client_secret": eidas_node_client_secret,
            },
        },
        formCountry: {
            "name": "FormEU",
            "pid_url": cfgserv.service_url + "pid/form",
            "pid_mdoc_privkey": UTOPIA_PID_MDOC_PRIVKEY,
            # "pid_mdoc_privkey": cfgserv.privKey_path + "hackathon-DS-0001_UT.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0001_UT.pem',
            "pid_mdoc_privkey_passwd": UTOPIA_PID_MDOC_PRIVKEY_PASSWORD,  # None or bytes
            "pid_mdoc_cert": UTOPIA_PID_MDOC_CERT,
            # "pid_mdoc_cert": cfgserv.trusted_CAs_path + "hackathon-DS-0001_UT_cert.der",
            "un_distinguishing_sign": "FC",
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
                "eu.europa.ec.eudi.mdl_mdoc",
                "eu.europa.ec.eudi.over18_mdoc",
                "eu.europa.ec.eudi.loyalty_mdoc",
                "eu.europa.ec.eudi.photoid",
                "eu.europa.ec.eudi.por_mdoc",
                "eu.europa.ec.eudi.iban_mdoc",
                "eu.europa.ec.eudi.hiid_mdoc",
                "eu.europa.ec.eudi.tax_mdoc",
                "eu.europa.ec.eudi.msisdn_mdoc",
                "eu.europa.ec.eudi.pda1_mdoc",
                "eu.europa.ec.eudi.tax_sd_jwt_vc",
                "eu.europa.ec.eudi.por_sd_jwt_vc",
                "eu.europa.ec.eudi.msisdn_sd_jwt_vc",
                "eu.europa.ec.eudi.hiid_sd_jwt_vc",
                "eu.europa.ec.eudi.iban_sd_jwt_vc",
                "eu.europa.ec.eudi.ehic_mdoc",
                "eu.europa.ec.eudi.cor_mdoc",
                "eu.europa.ec.eudi.ehic_sd_jwt_vc",
                "eu.europa.ec.eudi.pda1_sd_jwt_vc",
                "org.iso.18013.5.1.reservation_mdoc",
                "eu.europa.ec.eudi.seafarer_mdoc",
                "eu.europa.ec.eudi.diploma_vc_sd_jwt",
                "eu.europa.ec.eudi.tax_residency_vc_sd_jwt",
                "eu.europa.ec.eudi.employee_mdoc",
                "eu.europa.ec.eudi.pid_mdoc_deferred",
            ],
        },
        "PT": {
            "name": "Portugal",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0001_PT.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0001_PT.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0001_PT_cert.der",
            "un_distinguishing_sign": "P",
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
                "eu.europa.ec.eudi.mdl_mdoc",
                "eu.europa.ec.eudi.over18_mdoc",
                "eu.europa.ec.eudi.pid_mdoc_deferred",
            ],
            "connection_type": "oauth",
            "custom_modifiers": {
                "http://interop.gov.pt/MDC/Cidadao/DataNascimento": "birth_date",
                "http://interop.gov.pt/MDC/Cidadao/NomeApelido": "family_name",
                "http://interop.gov.pt/MDC/Cidadao/NomeProprio": "given_name",
            },
            "oauth_auth": {
                "base_url": "https://country-connector.ageverification.dev",
                "redirect_uri": f"{cfgserv.service_url}dynamic/redirect",
                "scope": "profile",
                "state": "hkMVY7vjuN7xyLl5",
                "response_type": "code",
                "client_id": pt_client_id,
                "client_secret": pt_client_secret,
            },
        },
        "EE": {
            "name": "Estonia",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0001_EE.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0001_EE.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0001_EE_cert.der",
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
            ],
            "connection_type": "openid",
            "oidc_auth": {
                "base_url": "https://tara-test.ria.ee",
                "redirect_uri": urlReturnEE,
                "scope": "openid",
                "state": "hkMVY7vjuN7xyLl5",
                "response_type": "code",
                "client_id": ee_client_id,
            },
            "attribute_request": {
                "header": {"Host": "tara-test.ria.ee"},
                "custom_modifiers": {
                    "birth_date": "date_of_birth",
                },
            },
            "oidc_redirect": {
                "headers": {
                    "Host": "tara-test.ria.ee",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": ee_auth_header,
                },
                "grant_type": "authorization_code",
                "redirect_uri": ee_redirect_uri,
            },
        },
        "CZ": {
            "name": "Czechia",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=CZ",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0001_CZ.pem",
            # "pid_mdoc_privkey": 'app\certs\PID-DS-0001_CZ.pem',
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0001_CZ_cert.der",
            "loa": EIDAS_LOA_HIGH,
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
            ],
            "custom_modifiers": {
                "family_name": "CurrentFamilyName",
                "given_name": "CurrentGivenName",
                "birth_date": "DateOfBirth",
            },
            "connection_type": "oauth",
            "oauth_auth": {
                "base_url": eidas_node_connector_url,
                "redirect_uri": f"{cfgserv.service_url}dynamic/redirect",
                "scope": "profile",
                "state": "hkMVY7vjuN7xyLl5",
                "response_type": "code",
                "client_id": eidas_node_client_id,
                "client_secret": eidas_node_client_secret,
            },
        },
        "NL": {
            "name": "Netherland",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=NL",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0001_NL.pem",
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0001_NL_cert.der",
            "loa": EIDAS_LOA_HIGH,
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
            ],
            "custom_modifiers": {
                "family_name": "CurrentFamilyName",
                "given_name": "CurrentGivenName",
                "birth_date": "DateOfBirth",
            },
            "connection_type": "oauth",
            "oauth_auth": {
                "base_url": eidas_node_connector_url,
                "redirect_uri": f"{cfgserv.service_url}dynamic/redirect",
                "scope": "profile",
                "state": "hkMVY7vjuN7xyLl5",
                "response_type": "code",
                "client_id": eidas_node_client_id,
                "client_secret": eidas_node_client_secret,
            },
        },
        "LU": {
            "name": "Luxembourg",
            "pid_url_oidc": cfgserv.service_url + "eidasnode/lightrequest?country=LU",
            "pid_mdoc_privkey": cfgserv.privKey_path + "PID-DS-0001_LU.pem",
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": cfgserv.trusted_CAs_path + "PID-DS-0001_LU_cert.der",
            "loa": EIDAS_LOA_HIGH,
            "supported_credentials": [
                "eu.europa.ec.eudi.pid_mdoc",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
            ],
            "custom_modifiers": {
                "family_name": "CurrentFamilyName",
                "given_name": "CurrentGivenName",
                "birth_date": "DateOfBirth",
            },
            "connection_type": "oauth",
            "oauth_auth": {
                "base_url": eidas_node_connector_url,
                "redirect_uri": f"{cfgserv.service_url}dynamic/redirect",
                "scope": "profile",
                "state": "hkMVY7vjuN7xyLl5",
                "response_type": "code",
                "client_id": eidas_node_client_id,
                "client_secret": eidas_node_client_secret,
            },
        },
        "AV": {
            "name": "Trusted Issuer",
            "pid_mdoc_privkey": AGE_VERIFICATION_MDOC_PRIVKEY,
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": AGE_VERIFICATION_MDOC_CERT,
            "un_distinguishing_sign": "AV",
            "supported_credentials": [
                "eu.europa.ec.eudi.age_verification_mdoc",
                "eu.europa.ec.eudi.age_verification_mdoc_passport"
            ],
            "dynamic_R2": cfgserv.service_url + "dynamic/form_R2",
        },
        "AV2": {
            "name": "Non-Trusted Issuer",
            "pid_mdoc_privkey": AGE_VERIFICATION_MDOC_PRIVKEY,
            "pid_mdoc_privkey_passwd": None,  # None or bytes
            "pid_mdoc_cert": AGE_VERIFICATION_MDOC_CERT,
            "un_distinguishing_sign": "AV",
            "supported_credentials": [
                "eu.europa.ec.eudi.age_verification_mdoc",
                "eu.europa.ec.eudi.pid_mdoc"
            ],
            "dynamic_R2": cfgserv.service_url + "dynamic/form_R2",
        },
    }


class ConfFrontend:
    registered_frontends = {
        cfgserv.default_frontend: {
            "url": os.getenv("DEFAULT_FRONTEND_URL", "https://ec.dev.issuer.eudiw.dev")
        },
        "6d725b3c-6d42-448e-8bfd-1eff1fcf152d": {
            "url": "https://age-verification.issuer.eudiw.dev"
        },
    }
