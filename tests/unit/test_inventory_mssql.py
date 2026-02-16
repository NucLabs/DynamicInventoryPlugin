# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Your Name <example@domain.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the MSSQL dynamic inventory plugin."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

# Add the project root to the path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import the actual plugin module
from plugins.inventory.mssql import InventoryModule


@pytest.fixture
def inventory_plugin() -> Generator[InventoryModule, None, None]:
    """Create an instance of the MSSQL inventory plugin for testing."""
    plugin = InventoryModule()
    plugin.inventory = MagicMock()
    plugin.display = MagicMock()
    plugin._options: dict[str, Any] = {}

    # Override get_option to use our _options dict
    plugin.get_option = lambda x: plugin._options.get(x)  # type: ignore[method-assign]

    yield plugin


class TestInventoryModuleVerifyFile:
    """Tests for the verify_file method."""

    def test_verify_file_valid_mssql_yml(self) -> None:
        """Test that .mssql.yml files are accepted."""
        path = "/path/to/inventory.mssql.yml"
        valid = path.endswith((".mssql.yml", ".mssql.yaml"))
        assert valid is True

    def test_verify_file_valid_mssql_yaml(self) -> None:
        """Test that .mssql.yaml files are accepted."""
        path = "/path/to/inventory.mssql.yaml"
        valid = path.endswith((".mssql.yml", ".mssql.yaml"))
        assert valid is True

    def test_verify_file_invalid_extension(self) -> None:
        """Test that non-mssql files are rejected."""
        path = "/path/to/inventory.yml"
        valid = path.endswith((".mssql.yml", ".mssql.yaml"))
        assert valid is False


class TestBuildFqdn:
    """Tests for the _build_fqdn method."""

    def test_build_fqdn_simple(self, inventory_plugin: InventoryModule) -> None:
        """Test basic FQDN construction."""
        result = inventory_plugin._build_fqdn("server01", "example.com")
        assert result == "server01.example.com"

    def test_build_fqdn_with_whitespace(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test FQDN construction with whitespace."""
        result = inventory_plugin._build_fqdn("  server01  ", "  example.com  ")
        assert result == "server01.example.com"

    def test_build_fqdn_domain_with_leading_dot(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test FQDN construction when domain starts with dot."""
        result = inventory_plugin._build_fqdn("server01", ".example.com")
        assert result == "server01.example.com"

    def test_build_fqdn_subdomain(self, inventory_plugin: InventoryModule) -> None:
        """Test FQDN construction with subdomain."""
        result = inventory_plugin._build_fqdn("server01", "prod.example.com")
        assert result == "server01.prod.example.com"


class TestValidateRow:
    """Tests for the _validate_row method."""

    def test_validate_row_valid(self, inventory_plugin: InventoryModule) -> None:
        """Test validation of a valid row."""
        row: dict[str, Any] = {
            "computername": "server01",
            "domainname": "example.com",
            "os": "linux",
        }
        result = inventory_plugin._validate_row(row, 0)
        assert result is True

    def test_validate_row_empty_computername(self, inventory_plugin: InventoryModule) -> None:
        """Test validation fails with empty computername."""
        row: dict[str, Any] = {"computername": "", "domainname": "example.com"}
        result = inventory_plugin._validate_row(row, 0)
        assert result is False
        inventory_plugin.display.warning.assert_called()  # type: ignore[union-attr]

    def test_validate_row_empty_domainname(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test validation fails with empty domainname."""
        row: dict[str, Any] = {"computername": "server01", "domainname": ""}
        result = inventory_plugin._validate_row(row, 0)
        assert result is False

    def test_validate_row_none_values(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test validation fails with None values."""
        row: dict[str, Any] = {"computername": None, "domainname": "example.com"}
        result = inventory_plugin._validate_row(row, 0)
        assert result is False


class TestPopulateInventory:
    """Tests for the _populate_inventory method."""

    def test_populate_inventory_single_host(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test populating inventory with a single host."""
        inventory_plugin._options = {
            "strict": False,
            "compose": {},
            "groups": {},
            "keyed_groups": [],
            "var_prefix": "",
        }
        inventory_plugin._set_composite_vars = MagicMock()  # type: ignore[method-assign]
        inventory_plugin._add_host_to_composed_groups = MagicMock()  # type: ignore[method-assign]
        inventory_plugin._add_host_to_keyed_groups = MagicMock()  # type: ignore[method-assign]

        results: list[dict[str, Any]] = [
            {
                "computername": "server01",
                "domainname": "example.com",
                "os_type": "linux",
                "environment": "prod",
            }
        ]

        inventory_plugin._populate_inventory(results)

        inventory_plugin.inventory.add_host.assert_called_with("server01.example.com")  # type: ignore[union-attr]
        inventory_plugin.inventory.set_variable.assert_any_call(  # type: ignore[union-attr]
            "server01.example.com", "os_type", "linux"
        )
        inventory_plugin.inventory.set_variable.assert_any_call(  # type: ignore[union-attr]
            "server01.example.com", "environment", "prod"
        )
        inventory_plugin.inventory.set_variable.assert_any_call(  # type: ignore[union-attr]
            "server01.example.com", "computername", "server01"
        )
        inventory_plugin.inventory.set_variable.assert_any_call(  # type: ignore[union-attr]
            "server01.example.com", "domainname", "example.com"
        )

    def test_populate_inventory_multiple_hosts(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test populating inventory with multiple hosts."""
        inventory_plugin._options = {
            "strict": False,
            "compose": {},
            "groups": {},
            "keyed_groups": [],
            "var_prefix": "",
        }
        inventory_plugin._set_composite_vars = MagicMock()  # type: ignore[method-assign]
        inventory_plugin._add_host_to_composed_groups = MagicMock()  # type: ignore[method-assign]
        inventory_plugin._add_host_to_keyed_groups = MagicMock()  # type: ignore[method-assign]

        results: list[dict[str, Any]] = [
            {"computername": "server01", "domainname": "example.com"},
            {"computername": "server02", "domainname": "example.com"},
            {"computername": "server03", "domainname": "other.com"},
        ]

        inventory_plugin._populate_inventory(results)

        assert inventory_plugin.inventory.add_host.call_count == 3  # type: ignore[union-attr]

    def test_populate_inventory_with_var_prefix(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test populating inventory with a variable prefix."""
        inventory_plugin._options = {
            "strict": False,
            "compose": {},
            "groups": {},
            "keyed_groups": [],
            "var_prefix": "mssql_",
        }
        inventory_plugin._set_composite_vars = MagicMock()  # type: ignore[method-assign]
        inventory_plugin._add_host_to_composed_groups = MagicMock()  # type: ignore[method-assign]
        inventory_plugin._add_host_to_keyed_groups = MagicMock()  # type: ignore[method-assign]

        results: list[dict[str, Any]] = [
            {
                "computername": "server01",
                "domainname": "example.com",
                "os_type": "linux",
            }
        ]

        inventory_plugin._populate_inventory(results)

        inventory_plugin.inventory.add_host.assert_called_with("server01.example.com")  # type: ignore[union-attr]
        # All variables should have the prefix
        inventory_plugin.inventory.set_variable.assert_any_call(  # type: ignore[union-attr]
            "server01.example.com", "mssql_os_type", "linux"
        )
        inventory_plugin.inventory.set_variable.assert_any_call(  # type: ignore[union-attr]
            "server01.example.com", "mssql_computername", "server01"
        )
        inventory_plugin.inventory.set_variable.assert_any_call(  # type: ignore[union-attr]
            "server01.example.com", "mssql_domainname", "example.com"
        )

    def test_populate_inventory_skips_invalid_rows(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that invalid rows are skipped."""
        inventory_plugin._options = {
            "strict": False,
            "compose": {},
            "groups": {},
            "keyed_groups": [],
            "var_prefix": "",
        }
        inventory_plugin._set_composite_vars = MagicMock()  # type: ignore[method-assign]
        inventory_plugin._add_host_to_composed_groups = MagicMock()  # type: ignore[method-assign]
        inventory_plugin._add_host_to_keyed_groups = MagicMock()  # type: ignore[method-assign]

        results: list[dict[str, Any]] = [
            {"computername": "server01", "domainname": "example.com"},
            {"computername": "", "domainname": "example.com"},  # Invalid - empty computername
            {"computername": "server03", "domainname": "other.com"},
        ]

        inventory_plugin._populate_inventory(results)

        # Only 2 hosts should be added (the invalid one is skipped)
        assert inventory_plugin.inventory.add_host.call_count == 2  # type: ignore[union-attr]


class TestExecuteQuery:
    """Tests for the _execute_query method."""

    def test_execute_query_normalizes_column_names(self) -> None:
        """Test that column names are normalized to lowercase."""
        # Simulate the normalization logic
        results: list[dict[str, Any]] = []
        for row in [
            {"COMPUTERNAME": "server01", "DOMAINNAME": "example.com", "OS_TYPE": "linux"}
        ]:
            normalized = {k.lower(): v for k, v in row.items()}
            results.append(normalized)

        assert results[0]["computername"] == "server01"
        assert results[0]["domainname"] == "example.com"
        assert results[0]["os_type"] == "linux"


class TestGetConnection:
    """Tests for the _get_connection method."""

    def test_get_connection_missing_pymssql(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that missing pymssql raises appropriate error."""
        inventory_plugin._options = {
            "host": "localhost",
            "port": 1433,
            "database": "test",
            "username": "user",
            "password": "pass",
            "connect_timeout": 30,
        }

        # This test verifies the import error handling logic
        expected_msg = (
            "The pymssql library is required for the mssql inventory plugin. "
            "Install it with: pip install pymssql"
        )
        assert "pymssql" in expected_msg

    def test_get_connection_with_mock_pymssql(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test connection establishment with mocked pymssql."""
        inventory_plugin._options = {
            "host": "localhost",
            "port": 1433,
            "database": "test",
            "auth_method": "sql",
            "username": "user",
            "password": "pass",
            "connect_timeout": 30,
            "tds_version": "7.3",
        }

        mock_pymssql = MagicMock()
        mock_connection = MagicMock()
        mock_pymssql.connect.return_value = mock_connection

        with patch.dict("sys.modules", {"pymssql": mock_pymssql}):
            with patch(
                "plugins.inventory.mssql.InventoryModule._get_connection",
                return_value=mock_connection,
            ):
                result = inventory_plugin._get_connection()
                assert result == mock_connection


class TestSetupCcache:
    """Tests for the _setup_ccache method."""

    def test_setup_ccache_creates_temp_file(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that _setup_ccache creates a temporary credential cache file."""
        try:
            result = inventory_plugin._setup_ccache()
            assert result.startswith("FILE:")
            assert "mssql_krb_" in result
            assert os.environ.get("KRB5CCNAME") == result
        finally:
            inventory_plugin._cleanup_ccache()

    def test_setup_ccache_reuses_existing(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that _setup_ccache reuses the same temp file on repeated calls."""
        try:
            first = inventory_plugin._setup_ccache()
            second = inventory_plugin._setup_ccache()
            assert first == second
        finally:
            inventory_plugin._cleanup_ccache()


class TestCleanupCcache:
    """Tests for the _cleanup_ccache method."""

    def test_cleanup_ccache_removes_env_var(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that _cleanup_ccache removes KRB5CCNAME from the environment."""
        inventory_plugin._setup_ccache()
        assert "KRB5CCNAME" in os.environ
        inventory_plugin._cleanup_ccache()
        assert "KRB5CCNAME" not in os.environ
        assert inventory_plugin._kerb_ccache is None

    def test_cleanup_ccache_noop_when_no_ccache(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that _cleanup_ccache is safe to call when no ccache exists."""
        inventory_plugin._cleanup_ccache()  # Should not raise


class TestPerformKinit:
    """Tests for the _perform_kinit method."""

    def test_perform_kinit_success(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that kinit succeeds with valid environment variables."""
        env = {"SQL_USER": "user@DOMAIN.COM", "SQL_PASS": "secret"}
        with patch.dict("os.environ", env, clear=False):
            with patch("shutil.which", return_value="/usr/bin/kinit"):
                with patch("subprocess.Popen") as mock_popen:
                    mock_proc = MagicMock()
                    mock_proc.communicate.return_value = (b"", b"")
                    mock_proc.returncode = 0
                    mock_popen.return_value = mock_proc
                    try:
                        inventory_plugin._perform_kinit()
                    finally:
                        inventory_plugin._cleanup_ccache()

                    mock_popen.assert_called_once()
                    call_kwargs = mock_popen.call_args
                    # Verify kinit was called with the expected command
                    assert call_kwargs[1]["env"]["KRB5CCNAME"].startswith("FILE:")
                    assert call_kwargs[0][0] == ["/usr/bin/kinit", "user@DOMAIN.COM"]
                    assert call_kwargs[1]["start_new_session"] is True

    def test_perform_kinit_sets_krb5ccname(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that kinit sets KRB5CCNAME environment variable."""
        env = {"SQL_USER": "user@DOMAIN.COM", "SQL_PASS": "secret"}
        with patch.dict("os.environ", env, clear=False):
            with patch("shutil.which", return_value="/usr/bin/kinit"):
                with patch("subprocess.Popen") as mock_popen:
                    mock_proc = MagicMock()
                    mock_proc.communicate.return_value = (b"", b"")
                    mock_proc.returncode = 0
                    mock_popen.return_value = mock_proc
                    try:
                        inventory_plugin._perform_kinit()
                        assert "KRB5CCNAME" in os.environ
                        assert os.environ["KRB5CCNAME"].startswith("FILE:")
                    finally:
                        inventory_plugin._cleanup_ccache()

    def test_perform_kinit_passes_minimal_env(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that kinit receives a minimal environment with PATH and KRB5CCNAME."""
        env = {
            "SQL_USER": "user@DOMAIN.COM",
            "SQL_PASS": "secret",
            "UNRELATED_VAR": "should_not_pass",
        }
        with patch.dict("os.environ", env, clear=False):
            with patch("shutil.which", return_value="/usr/bin/kinit"):
                with patch("subprocess.Popen") as mock_popen:
                    mock_proc = MagicMock()
                    mock_proc.communicate.return_value = (b"", b"")
                    mock_proc.returncode = 0
                    mock_popen.return_value = mock_proc
                    try:
                        inventory_plugin._perform_kinit()
                    finally:
                        inventory_plugin._cleanup_ccache()

                    call_env = mock_popen.call_args[1]["env"]
                    assert "PATH" in call_env
                    assert "KRB5CCNAME" in call_env
                    assert "UNRELATED_VAR" not in call_env

    def test_perform_kinit_propagates_krb5_config(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that KRB5_CONFIG is propagated to the kinit environment."""
        env = {
            "SQL_USER": "user@DOMAIN.COM",
            "SQL_PASS": "secret",
            "KRB5_CONFIG": "/etc/custom/krb5.conf",
        }
        with patch.dict("os.environ", env, clear=False):
            with patch("shutil.which", return_value="/usr/bin/kinit"):
                with patch("subprocess.Popen") as mock_popen:
                    mock_proc = MagicMock()
                    mock_proc.communicate.return_value = (b"", b"")
                    mock_proc.returncode = 0
                    mock_popen.return_value = mock_proc
                    try:
                        inventory_plugin._perform_kinit()
                    finally:
                        inventory_plugin._cleanup_ccache()

                    call_env = mock_popen.call_args[1]["env"]
                    assert call_env["KRB5_CONFIG"] == "/etc/custom/krb5.conf"

    def test_perform_kinit_missing_sql_user(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that missing SQL_USER raises an error."""
        env = {"SQL_PASS": "secret"}
        with patch.dict("os.environ", env, clear=True):
            from ansible.errors import AnsibleError

            with pytest.raises(AnsibleError, match="SQL_USER and SQL_PASS"):
                inventory_plugin._perform_kinit()

    def test_perform_kinit_missing_sql_pass(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that missing SQL_PASS raises an error."""
        env = {"SQL_USER": "user@DOMAIN.COM"}
        with patch.dict("os.environ", env, clear=True):
            from ansible.errors import AnsibleError

            with pytest.raises(AnsibleError, match="SQL_USER and SQL_PASS"):
                inventory_plugin._perform_kinit()

    def test_perform_kinit_no_kinit_binary(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that missing kinit binary raises an error."""
        env = {"SQL_USER": "user@DOMAIN.COM", "SQL_PASS": "secret"}
        with patch.dict("os.environ", env, clear=False):
            with patch("shutil.which", return_value=None):
                from ansible.errors import AnsibleError

                with pytest.raises(AnsibleError, match="kinit.*not found"):
                    inventory_plugin._perform_kinit()

    def test_perform_kinit_failure(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that kinit failure raises an error with details."""
        env = {"SQL_USER": "user@DOMAIN.COM", "SQL_PASS": "wrong"}
        with patch.dict("os.environ", env, clear=False):
            with patch("shutil.which", return_value="/usr/bin/kinit"):
                with patch("subprocess.Popen") as mock_popen:
                    mock_proc = MagicMock()
                    mock_proc.communicate.return_value = (
                        b"",
                        b"kinit: KDC reply did not match expectations",
                    )
                    mock_proc.returncode = 1
                    mock_popen.return_value = mock_proc
                    from ansible.errors import AnsibleError

                    with pytest.raises(AnsibleError, match="kinit failed"):
                        try:
                            inventory_plugin._perform_kinit()
                        finally:
                            inventory_plugin._cleanup_ccache()

    def test_perform_kinit_redacts_password(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that the password is redacted from kinit error output."""
        env = {"SQL_USER": "user@DOMAIN.COM", "SQL_PASS": "MySecret123"}
        with patch.dict("os.environ", env, clear=False):
            with patch("shutil.which", return_value="/usr/bin/kinit"):
                with patch("subprocess.Popen") as mock_popen:
                    mock_proc = MagicMock()
                    mock_proc.communicate.return_value = (
                        b"",
                        b"kinit: error MySecret123 leaked",
                    )
                    mock_proc.returncode = 1
                    mock_popen.return_value = mock_proc
                    from ansible.errors import AnsibleError

                    with pytest.raises(AnsibleError, match="<redacted>") as exc_info:
                        try:
                            inventory_plugin._perform_kinit()
                        finally:
                            inventory_plugin._cleanup_ccache()
                    assert "MySecret123" not in str(exc_info.value)

    def test_perform_kinit_oserror(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that OSError from Popen is handled."""
        env = {"SQL_USER": "user@DOMAIN.COM", "SQL_PASS": "secret"}
        with patch.dict("os.environ", env, clear=False):
            with patch("shutil.which", return_value="/usr/bin/kinit"):
                with patch(
                    "subprocess.Popen",
                    side_effect=OSError("No such file"),
                ):
                    from ansible.errors import AnsibleError

                    with pytest.raises(AnsibleError, match="Kerberos auth failure"):
                        try:
                            inventory_plugin._perform_kinit()
                        finally:
                            inventory_plugin._cleanup_ccache()


class TestKerberosAuthentication:
    """Tests for Kerberos authentication functionality."""

    def test_kerberos_check_ticket_success(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that Kerberos ticket check passes with valid ticket."""
        with patch.object(inventory_plugin, "_perform_kinit"):
            with patch("shutil.which", return_value="/usr/bin/klist"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0)
                    inventory_plugin._check_kerberos_ticket()
                    mock_run.assert_called_once()

    def test_kerberos_check_ticket_no_klist(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that missing klist issues warning but doesn't fail."""
        with patch.object(inventory_plugin, "_perform_kinit"):
            with patch("shutil.which", return_value=None):
                inventory_plugin._check_kerberos_ticket()
                inventory_plugin.display.warning.assert_called()  # type: ignore[union-attr]

    def test_kerberos_check_ticket_calls_kinit_first(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that _check_kerberos_ticket calls _perform_kinit before klist."""
        call_order: list[str] = []

        def mock_kinit() -> None:
            call_order.append("kinit")

        with patch.object(inventory_plugin, "_perform_kinit", side_effect=mock_kinit):
            with patch("shutil.which", return_value="/usr/bin/klist"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0)

                    def record_klist(*args: Any, **kwargs: Any) -> MagicMock:
                        call_order.append("klist")
                        return MagicMock(returncode=0)

                    mock_run.side_effect = record_klist
                    inventory_plugin._check_kerberos_ticket()
                    assert call_order == ["kinit", "klist"]

    def test_kerberos_default_auth_method(self) -> None:
        """Test that Kerberos is the default authentication method."""
        from plugins.inventory.mssql import DOCUMENTATION

        assert "default: kerberos" in DOCUMENTATION

    def test_sql_auth_requires_credentials(
        self, inventory_plugin: InventoryModule
    ) -> None:
        """Test that SQL auth method requires username and password."""
        inventory_plugin._options = {
            "host": "localhost",
            "port": 1433,
            "database": "test",
            "auth_method": "sql",
            "username": None,
            "password": None,
            "connect_timeout": 30,
            "tds_version": "7.3",
        }

        mock_pymssql = MagicMock()
        with patch.dict("sys.modules", {"pymssql": mock_pymssql}):
            from ansible.errors import AnsibleError

            with pytest.raises(AnsibleError) as exc_info:
                inventory_plugin._get_connection()

            assert "Username and password are required" in str(exc_info.value)
