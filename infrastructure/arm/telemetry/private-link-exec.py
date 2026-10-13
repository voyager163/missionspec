"""One fixed streamed Private Link diagnostic. Credentials and raw frames are never logged."""
import hashlib
import json
import logging
import os
import ssl
import sys
import time
from importlib.metadata import version
from urllib.parse import urlencode, urlparse


def require(value):
    if not value:
        raise ValueError("PRIVATE_EXEC_UNCONFIRMED")


def main():
    logging.disable(logging.CRITICAL)
    require(version("websocket-client") == "1.8.0")
    import websocket

    raw = sys.stdin.buffer.read(65537)
    require(len(raw) <= 65536)
    value = json.loads(raw)
    require(set(value) == {"version", "endpoint", "token", "command", "payload", "payloadSha256", "remainingMs"})
    require(value["version"] == 2 and type(value["remainingMs"]) is int and 0 < value["remainingMs"] <= 30000)
    endpoint = urlparse(value["endpoint"])
    require(endpoint.scheme == "wss" and endpoint.hostname == "australiaeast.azurecontainerapps.dev" and
            not endpoint.username and not endpoint.password and not endpoint.query and not endpoint.fragment and not endpoint.port)
    payload = value["payload"].encode("utf-8")
    require(0 < len(payload) <= 16384 and payload.isascii() and
            hashlib.sha256(payload).hexdigest() == value["payloadSha256"])
    require(value["command"].startswith("/usr/local/bin/node --no-turbofan --no-maglev --disable-sigusr1 --max-old-space-size=64 --eval "))
    require(type(value["token"]) is str and 20 <= len(value["token"]) <= 32768 and
            "\r" not in value["token"] and "\n" not in value["token"])
    for name in list(os.environ):
        if "proxy" in name.lower() or name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
                                              "CURL_CA_BUNDLE", "AZURE_CLI_DISABLE_CONNECTION_VERIFICATION"):
            os.environ.pop(name, None)
    websocket.enableTrace(False)
    ws = websocket.WebSocket(enable_multithread=False, sslopt={"cert_reqs": ssl.CERT_REQUIRED, "check_hostname": True})
    until = time.monotonic() + value["remainingMs"] / 1000
    result = None
    try:
        ws.connect(value["endpoint"] + "?" + urlencode({"command": value["command"]}),
                   header=["Authorization: Bearer " + value["token"]], timeout=min(5, until - time.monotonic()), redirect_limit=0)
        require(ws.handshake_response.status == 101)
        value["token"] = None
        ws.send(b'\x00\x04{"Width":80,"Height":24}', opcode=websocket.ABNF.OPCODE_TEXT)
        startup, output = bytearray(), bytearray()
        sent = False
        payload_frames = 0
        for _ in range(32):
            remaining = until - time.monotonic()
            require(remaining > 0)
            ws.settimeout(remaining)
            frame = ws.recv()
            if not frame:
                break
            require(isinstance(frame, bytes) and len(frame) <= 4096)
            if frame[0] == 1:
                continue
            require(frame[:2] == b"\x00\x01")
            if not sent:
                startup.extend(frame[2:])
                require(len(startup) <= 64)
                marker = b"MSP_PRIVATE_READY\r\n" if b"\r" in startup else b"MSP_PRIVATE_READY\n"
                require(marker.startswith(startup) or startup == marker)
                if startup == marker:
                    for offset in range(0, len(payload), 2048):
                        require(time.monotonic() < until)
                        ws.send(b"\x00\x00" + payload[offset:offset + 2048], opcode=websocket.ABNF.OPCODE_TEXT)
                        payload_frames += 1
                    sent = True
            else:
                output.extend(frame[2:])
                require(len(output) <= 2048)
                if output.endswith(b"\n"):
                    result = json.loads(output.decode("utf-8"))
                    break
        require(sent and result is not None and time.monotonic() < until)
        require(set(result) == {"version", "kind", "nodeVersion", "queueHost", "privateIp", "clientId", "principalId", "mode",
                                "dnsPrivate", "dnsPublic", "tlsVerified", "remotePrivate", "remotePublic", "tokenIdentityMatched",
                                "metadataStatus", "storageErrorCode", "tokenRequests", "metadataRequests", "enqueues", "elapsedMs", "failureCode"})
        # Do not forward unexpected strings even on an unsuccessful remote probe.
        require(result["version"] == 1 and result["kind"] == "same-container-private-queue-metadata" and result["nodeVersion"] == "24.21.0")
        require(result["failureCode"] in (None, "PROBE_DEADLINE", "PROBE_FAILED", "CONTEXT_CHANGED",
                                         "PRIVATE_DNS_UNPROVEN", "IDENTITY_ENDPOINT_INVALID", "IDENTITY_UNAVAILABLE",
                                         "QUEUE_METADATA_UNAVAILABLE"))
        require(result["mode"] in ("private", "public-deny"))
        require(result["storageErrorCode"] in (None, "AuthorizationFailure", "AuthenticationFailed",
                                             "AuthorizationPermissionMismatch", "InvalidAuthenticationInfo", "unclassified"))
        for key in ("queueHost", "privateIp", "clientId", "principalId"):
            require(type(result[key]) is str and len(result[key]) <= 128)
            require(all(char in "abcdefghijklmnopqrstuvwxyz0123456789.-" for char in result[key]))
        for key in ("tokenRequests", "metadataRequests", "enqueues", "elapsedMs"):
            require(type(result[key]) is int and 0 <= result[key] <= 25000)
        for key in ("dnsPrivate", "dnsPublic", "tlsVerified", "remotePrivate", "remotePublic", "tokenIdentityMatched"):
            require(type(result[key]) is bool)
        require(result["metadataStatus"] is None or type(result["metadataStatus"]) is int and 100 <= result["metadataStatus"] <= 599)
    finally:
        ws.close(timeout=1)
    print(json.dumps({"version": 2, "kind": "bounded-private-queue-exec", "sessions": 1,
                      "payloadFrames": payload_frames, "sessionClosed": True, "result": result}, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        print('{"status":"PRIVATE_EXEC_UNCONFIRMED"}')
        sys.exit(1)
