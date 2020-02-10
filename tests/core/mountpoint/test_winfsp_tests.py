# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import os
import pytest

if os.name != "nt":
    pytest.skip("Windows only", allow_module_level=True)

from winfspy.tests.winfsp_tests import test_winfsp_tests as winfsp_tests

# Constants

TEST_CASES = winfsp_tests.TEST_CASES

XFAIL_LIST = [
    # Require a case-insensitive file system
    "getfileinfo_name_test",
    # Reparse point are not supported
    "reparse_guid_test",
    "reparse_nfs_test",
    "reparse_symlink_test",
    "reparse_symlink_relative_test",
    # Tests failing on file systems mounted as directories
    "create_test",
    "getfileinfo_test",
    "getfileinfo_name_test",
    "getvolinfo_test",
    # Setting file attributes is not supported at the moment
    "create_fileattr_test",
    "create_readonlydir_test",
    "getfileattr_test",
    "setfileinfo_test",
    # Setting allocation size is not supported at the moment
    "create_allocation_test",
    # Renaming has a special behavior in parsec
    "rename_test",
    "rename_mmap_test",
    "rename_standby_test",
    "exec_rename_test",
    # Setting security is not supported at the moment
    "getsecurity_test",
    "setsecurity_test",
    # TODO: investigate misc tests
    "create_notraverse_test",
    "delete_mmap_test",
    "delete_access_test",
]


# Fixtures

file_system_tempdir = winfsp_tests.file_system_tempdir


@pytest.fixture
def file_system_path(mountpoint_service):
    return mountpoint_service.wpath


# Tests


@pytest.mark.slow
@pytest.mark.mountpoint
@pytest.mark.parametrize("test_case", TEST_CASES)
def test_winfsp_tests(test_case, file_system_tempdir):

    # Many tests are not supported
    if test_case in XFAIL_LIST:
        pytest.xfail()

    # Run winfstest with the parsec mountpoint
    winfsp_tests.test_winfsp_tests(
        test_case, file_system_tempdir, enable_stream_tests=False, memfs_tests=False, as_drive=False
    )
