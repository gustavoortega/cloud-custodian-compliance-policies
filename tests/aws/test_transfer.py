"""Behavioural tests for policies/aws/transfer.yml.

Offline: no AWS credentials, no network.
"""
from c7n_kit.testing import run_policy

POLICIES = 'policies/aws/transfer.yml'


def test_transfer_server_ftp_protocol_enabled():
    resources = [
        {'ServerId': 'matches', 'State': 'ONLINE', 'Protocols': ['FTP', 'SFTP']},
        {'ServerId': 'clean', 'State': 'ONLINE', 'Protocols': ['SFTP']},
        # covered by the second branch. `op: contains` against an absent
        # Protocols raises TypeError inside c7n, which swallows it as "no
        # match", so only a separate filter reaches it. Protocols is required
        # at creation, so an absent list is never "it does not speak FTP".
        {'ServerId': 'key-absent', 'State': 'ONLINE'},
        # an empty list IS a real answer and stays clean: `contains` on []
        # is a well-defined False, not a swallowed TypeError.
        {'ServerId': 'clean-empty', 'State': 'ONLINE', 'Protocols': []},
    ]
    # `or` resolves via set union; sort before asserting.
    matched = sorted(r['ServerId'] for r in run_policy(
        POLICIES, 'transfer-server-ftp-protocol-enabled', resources))
    assert matched == ['key-absent', 'matches']


def test_transfer_connector_logging_disabled():
    resources = [
        # DescribeConnector omits LoggingRole when none is attached: that IS
        # the finding, so absence is what the filter looks for.
        {'ConnectorId': 'matches', 'Url': 'https://example.com'},
        {'ConnectorId': 'clean', 'Url': 'https://example.com',
         'LoggingRole': 'arn:aws:iam::000000000000:role/transfer-logging'},
    ]
    matched = [r['ConnectorId'] for r in run_policy(
        POLICIES, 'transfer-connector-logging-disabled', resources)]
    assert matched == ['matches']
