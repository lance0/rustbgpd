"""Run with `python -m unittest -v test_connect` after generating the stubs."""

import argparse
import unittest
from unittest.mock import DEFAULT, patch

import explain


class ConnectTests(unittest.TestCase):
    def test_invalid_tls_options_fail_before_credentials_or_channels(self):
        for ca, cert, key, token in (
            (None, "client.pem", None, "token"),
            (None, None, "client.key", "token"),
            (None, "client.pem", "client.key", "token"),
            ("ca.pem", "client.pem", None, "token"),
            ("ca.pem", None, "client.key", "token"),
            ("", None, None, None),
            (None, "", None, None),
            (None, None, "", None),
            (None, None, None, ""),
        ):
            with self.subTest(ca=ca, cert=cert, key=key, token=token), patch.multiple(
                explain.Path, read_text=DEFAULT, read_bytes=DEFAULT
            ) as files, patch.multiple(
                explain.grpc,
                insecure_channel=DEFAULT,
                secure_channel=DEFAULT,
                ssl_channel_credentials=DEFAULT,
                local_channel_credentials=DEFAULT,
                metadata_call_credentials=DEFAULT,
                composite_channel_credentials=DEFAULT,
            ) as grpc_calls:
                args = argparse.Namespace(
                    target="localhost:50051", tls_ca=ca, tls_cert=cert,
                    tls_key=key, token_file=token,
                )
                with self.assertRaises(ValueError):
                    explain.connect(args)
                for mocked in (*files.values(), *grpc_calls.values()):
                    mocked.assert_not_called()

    def test_valid_connection_modes(self):
        for ca, cert, key, token, target in (
            (None, None, None, None, "localhost:50051"),
            ("ca.pem", None, None, None, "localhost:50051"),
            ("ca.pem", "client.pem", "client.key", None, "localhost:50051"),
            (None, None, None, "token", "unix:///var/lib/rustbgpd/grpc.sock"),
        ):
            with self.subTest(ca=ca, cert=cert, token=token), patch.object(
                explain.Path, "read_bytes", return_value=b"pem"
            ), patch.object(explain.Path, "read_text", return_value="token\n"), patch.multiple(
                explain.grpc, insecure_channel=DEFAULT, secure_channel=DEFAULT,
                ssl_channel_credentials=DEFAULT, local_channel_credentials=DEFAULT,
                metadata_call_credentials=DEFAULT, composite_channel_credentials=DEFAULT,
            ) as grpc_calls:
                args = argparse.Namespace(
                    target=target, tls_ca=ca, tls_cert=cert, tls_key=key, token_file=token,
                )
                channel = explain.connect(args)
                selected = "secure_channel" if ca or token else "insecure_channel"
                self.assertIs(channel, grpc_calls[selected].return_value)
                grpc_calls[selected].assert_called_once()
                other = "insecure_channel" if ca or token else "secure_channel"
                grpc_calls[other].assert_not_called()
                if ca:
                    grpc_calls["ssl_channel_credentials"].assert_called_once_with(
                        root_certificates=b"pem", private_key=b"pem" if key else None,
                        certificate_chain=b"pem" if cert else None,
                    )
                if token:
                    grpc_calls["local_channel_credentials"].assert_called_once_with(
                        explain.grpc.LocalConnectionType.UDS
                    )
                    grpc_calls["composite_channel_credentials"].assert_called_once()


if __name__ == "__main__":
    unittest.main()
