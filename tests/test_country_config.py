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
import pytest
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from app.app_config import config_countries


class TestConfCountries:
    def test_has_supported_countries(self):
        """Ensure supported_countries exists and contains expected keys."""
        countries = config_countries.ConfCountries.supported_countries
        assert isinstance(countries, dict)
        assert "EU" in countries
        assert config_countries.ConfCountries.formCountry in countries
        assert "EE" in countries

    @pytest.mark.parametrize("country_code", ["EU", "FC", "PT", "EE", "CZ", "NL", "LU"])
    def test_country_structure_and_required_keys(self, country_code):
        """Each country entry should contain mandatory configuration keys."""
        countries = config_countries.ConfCountries.supported_countries
        country_conf = countries[country_code]

        assert isinstance(country_conf, dict)
        assert "supported_credentials" in country_conf
        assert isinstance(country_conf["supported_credentials"], list)
        assert len(country_conf["supported_credentials"]) > 0

        # Every config must define at least a private key and cert path
        assert "pid_mdoc_privkey" in country_conf
        assert "pid_mdoc_cert" in country_conf
        assert country_conf["pid_mdoc_privkey"].startswith(
            config_countries.cfgserv.privKey_path
        )
        assert country_conf["pid_mdoc_cert"].startswith(
            config_countries.cfgserv.trusted_CAs_path
        )

    def test_urlReturnEE_is_defined(self):
        """Check the EE redirect URL constant."""
        assert config_countries.ConfCountries.urlReturnEE.startswith("https://")
        assert "tara/redirect" in config_countries.ConfCountries.urlReturnEE

    def test_eidas_loa_high_constant(self):
        """Ensure the EIDAS LOA constant is correct."""
        assert config_countries.EIDAS_LOA_HIGH == "http://eidas.europa.eu/LoA/high"

    def test_eu_oauth_structure(self):
        """Check that EU entry defines a valid OAuth configuration."""
        eu_conf = config_countries.ConfCountries.supported_countries["EU"]
        oauth = eu_conf["oauth_auth"]

        assert "base_url" in oauth
        assert oauth["redirect_uri"].startswith(config_countries.cfgserv.service_url)
        assert oauth["response_type"] == "code"
        assert "client_id" in oauth
        assert "client_secret" in oauth

    def test_ee_oidc_structure(self):
        """Ensure the EE configuration contains expected OIDC and redirect data."""
        ee_conf = config_countries.ConfCountries.supported_countries["EE"]
        assert ee_conf["connection_type"] == "openid"

        oidc_auth = ee_conf["oidc_auth"]
        assert oidc_auth["redirect_uri"] == config_countries.ConfCountries.urlReturnEE

        oidc_redirect = ee_conf["oidc_redirect"]
        assert "headers" in oidc_redirect
        assert "redirect_uri" in oidc_redirect
        assert oidc_redirect["redirect_uri"] == config_countries.ee_redirect_uri


class TestConfFrontend:
    def test_registered_frontends_exist(self):
        """Ensure registered_frontends dictionary is defined correctly."""
        frontend_conf = config_countries.ConfFrontend.registered_frontends
        assert isinstance(frontend_conf, dict)
        assert len(frontend_conf) > 0

    def test_frontend_entry_contains_url(self):
        """Check that all registered frontend entries have valid URLs."""
        for (
            frontend_id,
            data,
        ) in config_countries.ConfFrontend.registered_frontends.items():
            assert isinstance(frontend_id, str)
            assert "url" in data
            assert data["url"].startswith("https://")


def test_utopia_signer_cert_is_rewritten_for_service_url(tmp_path):
    private_key = ec.generate_private_key(ec.SECP256R1())
    key_path = tmp_path / "PID-DS-0001_UT.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    stale_certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local Utopia DS")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local Utopia DS")]))
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier("https://192.168.0.131:5002")]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    cert_path = tmp_path / "PID-DS-0001_UT_cert.der"
    cert_path.write_bytes(stale_certificate.public_bytes(serialization.Encoding.DER))

    updated_cert_path = config_countries._ensure_utopia_signer_cert_matches_service_url(
        str(cert_path),
        str(key_path),
        None,
        "https://issuer-api.test.instech-eudi-poc.com/",
    )

    updated_certificate = x509.load_der_x509_certificate(
        tmp_path.joinpath("PID-DS-0001_UT_cert.der").read_bytes()
    )
    subject_alt_name = updated_certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value

    assert updated_cert_path == str(cert_path)
    assert subject_alt_name.get_values_for_type(x509.UniformResourceIdentifier) == [
        "https://issuer-api.test.instech-eudi-poc.com"
    ]
    assert subject_alt_name.get_values_for_type(x509.DNSName) == [
        "issuer-api.test.instech-eudi-poc.com"
    ]
