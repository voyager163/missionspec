"""One authenticated, nonmutating ARM what-if request; never an ARM executor."""

import hashlib
import json
import logging
import os
from pathlib import Path
import re
import stat
import sys
import time
from urllib.parse import urlsplit, parse_qsl
import warnings

API = "2025-04-01"
HOST = "https://management.azure.com"
MAX_BYTES = 64 * 1024 * 1024
PHASE_CODES = {"core": "co", "workspace-access": "wa", "data": "da", "upload-role": "ur",
               "assignments": "ra", "disabled-app": "di", "synthetic-admission": "sy",
               "synthetic-disable": "sd", "project-budget": "pb",
               "disabled-image-upgrade": "iu", "disabled-image-rollback": "ir"}
GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


class Stop(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Stop(code)


def private_read(path):
    require(os.name == "posix" and os.getuid() == os.geteuid() and hasattr(os, "O_NOFOLLOW"), "PRIVATE_POSIX_REQUIRED")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= MAX_BYTES, "PRIVATE_INPUT_REQUIRED")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, MAX_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            require(size <= MAX_BYTES, "PRIVATE_INPUT_TOO_LARGE")
        after = os.fstat(fd)
        require(size == before.st_size and all(getattr(before, key) == getattr(after, key)
                for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_uid", "st_nlink")), "PRIVATE_INPUT_CHANGED")
        return json.loads(b"".join(chunks))
    finally:
        os.close(fd)


def static_template(value):
    if isinstance(value, str):
        require(not value.lstrip().startswith("["), "STATIC_TEMPLATE_REQUIRED")
    elif isinstance(value, dict):
        require(not any(key in value for key in ("templateLink", "parametersLink")), "INLINE_TEMPLATE_REQUIRED")
        for child in value.values():
            static_template(child)
    elif isinstance(value, list):
        for child in value:
            static_template(child)


def fixed_deployment_name(request):
    require(request.get("phase") in PHASE_CODES and isinstance(request.get("namePrefix"), str)
            and re.fullmatch(r"missionspec-[a-z0-9]{2,10}", request["namePrefix"])
            and isinstance(request.get("runId"), str) and GUID.fullmatch(request["runId"]), "FIXED_WHATIF_NAME_REQUIRED")
    if request["phase"] in ("synthetic-admission", "synthetic-disable", "disabled-image-upgrade", "disabled-image-rollback"):
        instance = request.get("windowInstanceId")
        require(isinstance(instance, str)
                and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", instance)
                and instance != request["runId"]
                and isinstance(request.get("predecessorSha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", request["predecessorSha256"]), "BOUND_WINDOW_INSTANCE_REQUIRED")
        identity = ("u" if request["phase"].startswith("disabled-image-") else "w") + instance.replace("-", "")
    else:
        require(request.get("windowInstanceId") is None and request.get("predecessorSha256") is None, "WINDOW_INSTANCE_TOGGLE_ONLY")
        identity = request["runId"].replace("-", "")
    name = request["namePrefix"] + "-" + identity + "-" + PHASE_CODES[request["phase"]]
    require(len(name) <= 64, "DEPLOYMENT_NAME_INVALID")
    return name


def poll_url(value, subscription, location):
    require(isinstance(value, str) and not any(c in value for c in ("%", "\\", "#", "\r", "\n")), "WHATIF_LOCATION_INVALID")
    absolute = HOST + value if value.startswith("/subscriptions/") else value
    parsed = urlsplit(absolute)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    require(parsed.scheme == "https" and parsed.netloc == "management.azure.com" and not parsed.fragment
            and not parsed.username and not parsed.password and len(dict(query)) == len(query)
            and dict(query).get("api-version") == API, "WHATIF_LOCATION_INVALID")
    prefix = "/subscriptions/" + subscription
    opaque = re.fullmatch(prefix + "/operationresults/([A-Za-z0-9_-]{16,1024})", parsed.path, re.IGNORECASE)
    if opaque:
        fields = dict(query)
        require(set(fields) == {"api-version", "t", "c", "s", "h"}
                and re.fullmatch(r"\d{10,20}", fields["t"])
                and re.fullmatch(r"[A-Za-z0-9_-]{1,4096}", fields["c"])
                and re.fullmatch(r"[A-Za-z0-9_-]{1,1024}", fields["s"])
                and re.fullmatch(r"[A-Za-z0-9_-]{43}", fields["h"]), "WHATIF_OPERATION_CONTEXT_INVALID")
        return absolute
    require(query == [("api-version", API)], "WHATIF_LOCATION_INVALID")
    # These are status/result resources, not deployment/resource mutation endpoints.
    patterns = [
        prefix + "/locations/" + location + "/operationresults/([a-zA-Z0-9-]{16,128})",
        prefix + "/providers/Microsoft.Resources/locations/" + location + "/operationResults/([a-zA-Z0-9-]{16,128})",
        prefix + "/providers/Microsoft.Resources/locations/" + location + "/whatIfOperationResults/([a-zA-Z0-9-]{16,128})",
    ]
    require(any(re.fullmatch(pattern, parsed.path, re.IGNORECASE) for pattern in patterns), "WHATIF_OPERATION_PATH_INVALID")
    return absolute


def main():
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    os.umask(0o077)
    require(len(sys.argv) == 3, "FIXED_WHATIF_ARGUMENTS_REQUIRED")
    request_path, response_path = [Path(value).absolute() for value in sys.argv[1:]]
    root = Path.cwd() / "infrastructure/arm/telemetry/.operator-private"
    parent = request_path.parent
    require(parent == response_path.parent and (parent == root or
            (parent.parent == root and re.fullmatch(r"revision-\d{8}-[a-z0-9-]{1,32}", parent.name))),
            "CANONICAL_PRIVATE_DIRECTORY_REQUIRED")
    for directory in (root, parent):
        fd = os.open(directory, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
        try:
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o700, "PRIVATE_DIRECTORY_REQUIRED")
        finally:
            os.close(fd)
    require(re.fullmatch(r"whatif-request-[0-9a-f-]+\.json", request_path.name)
            and re.fullmatch(r"whatif-response-[0-9a-f-]+\.json", response_path.name), "PRIVATE_WHATIF_FILENAMES_REQUIRED")
    request = private_read(request_path)
    require(set(request) == {"version", "action", "subscriptionId", "tenantId", "location", "namePrefix", "runId",
                            "phase", "scope", "phaseSha256", "body", "bodySha256", "pollUrl", "initialResponseFile",
                            "contextSha256", "timeoutMs", "deadlineMs", "windowInstanceId", "predecessorSha256"}, "CLOSED_WHATIF_INPUT_REQUIRED")
    require(request["version"] == 2 and request["action"] in ("start", "poll")
            and all(isinstance(request[key], str) and GUID.fullmatch(request[key])
                    for key in ("subscriptionId", "tenantId", "runId"))
            and request["location"] == "australiaeast"
            and re.fullmatch(r"missionspec-[a-z0-9]{2,10}", request["namePrefix"])
            and request["phase"] in PHASE_CODES, "FIXED_WHATIF_SCOPE_REQUIRED")
    expected_scope = "subscription" if request["phase"] in ("upload-role", "project-budget") else "group"
    require(request["scope"] == expected_scope, "FIXED_WHATIF_SCOPE_REQUIRED")
    name = fixed_deployment_name(request)
    require(all(isinstance(request[key], str) and re.fullmatch(r"[0-9a-f]{64}", request[key])
                for key in ("phaseSha256", "bodySha256", "contextSha256")), "WHATIF_CONTEXT_INVALID")
    fingerprint = "\n".join("" if request[key] is None else str(request[key]) for key in
                           ("subscriptionId", "tenantId", "location", "namePrefix", "runId", "phase", "scope", "phaseSha256", "bodySha256",
                            "windowInstanceId", "predecessorSha256"))
    require(hashlib.sha256(fingerprint.encode()).hexdigest() == request["contextSha256"], "WHATIF_CONTEXT_INVALID")
    require(type(request["timeoutMs"]) is int and 0 < request["timeoutMs"] <= 15000
            and type(request["deadlineMs"]) is int, "BOUNDED_WHATIF_DEADLINE_REQUIRED")
    end = min(request["deadlineMs"], int(time.time() * 1000) + request["timeoutMs"])
    subscription = request["subscriptionId"]
    scope = "/subscriptions/" + subscription
    if expected_scope == "group":
        scope += "/resourceGroups/" + request["namePrefix"] + "-telemetry"
    url = HOST + scope + "/providers/Microsoft.Resources/deployments/" + name + "/whatIf?api-version=" + API
    if request["action"] == "start":
        require(request["pollUrl"] is None and request["initialResponseFile"] is None and isinstance(request["body"], str)
                and hashlib.sha256(request["body"].encode()).hexdigest() == request["bodySha256"], "WHATIF_BODY_CHANGED")
        body = json.loads(request["body"])
        require(set(body) == ({"properties", "location"} if expected_scope == "subscription" else {"properties"}), "FIXED_WHATIF_BODY_REQUIRED")
        properties = body["properties"]
        require(set(properties) == {"mode", "parameters", "template", "whatIfSettings"} and properties["mode"] == "Incremental"
                and properties["parameters"] == {} and properties["whatIfSettings"] == {"resultFormat": "FullResourcePayloads"},
                "FULL_STATIC_WHATIF_REQUIRED")
        if expected_scope == "subscription":
            require(body["location"] == request["location"], "WHATIF_REGION_CHANGED")
        static_template(properties["template"])
        method = "POST"
    else:
        require(request["body"] is None and isinstance(request["initialResponseFile"], str)
                and re.fullmatch(r"whatif-response-[0-9a-f-]+\.json", request["initialResponseFile"]), "WHATIF_POLL_BODY_FORBIDDEN")
        initial = private_read(parent / request["initialResponseFile"])
        require(initial.get("contextSha256") == request["contextSha256"] and initial.get("statusCode") == 202
                and initial.get("verifiedRegion") == request["location"]
                and initial.get("headers", {}).get("location") == request["pollUrl"], "WHATIF_OPERATION_CONTEXT_CHANGED")
        url = poll_url(request["pollUrl"], subscription, request["location"])
        method, body = "GET", None

    from azure.cli.core import get_default_cli
    from azure.cli.core._profile import Profile
    from azure.core import PipelineClient
    from azure.core.pipeline.policies import BearerTokenCredentialPolicy, RetryPolicy, RedirectPolicy
    from azure.core.pipeline.transport import RequestsTransport, HttpRequest
    from importlib.metadata import version
    import requests

    require(version("azure-cli-core") == "2.90.0" and version("azure-core") == "1.39.0"
            and version("requests") == "2.33.0", "CLI_BRIDGE_VERSION_REVIEW_REQUIRED")
    cli = get_default_cli()
    require(cli.cloud.name == "AzureCloud" and cli.cloud.endpoints.resource_manager.rstrip("/") == HOST, "EXACT_AZURE_CLOUD_REQUIRED")
    profile = Profile(cli_ctx=cli)
    account = profile.get_subscription(subscription)
    require(account["id"].lower() == subscription and account["tenantId"].lower() == request["tenantId"]
            and account.get("user", {}).get("type") == "user", "EXACT_OPERATOR_CONTEXT_REQUIRED")
    credential, selected, tenant = profile.get_login_credentials(subscription_id=subscription)
    require(selected.lower() == subscription and tenant.lower() == request["tenantId"], "EXACT_OPERATOR_CONTEXT_REQUIRED")
    session = requests.Session()
    session.trust_env = False
    transport = RequestsTransport(session=session, session_owner=False)
    class OneShotBearer(BearerTokenCredentialPolicy):
        def on_challenge(self, request, response):
            return False

    policies = [RedirectPolicy(permit_redirects=False), RetryPolicy(retry_total=0, retry_connect=0, retry_read=0, retry_status=0),
                OneShotBearer(credential, cli.cloud.endpoints.active_directory_resource_id.rstrip("/") + "/.default")]
    try:
        with PipelineClient(base_url=HOST, policies=policies, transport=transport) as client:
            def send(one_method, one_url, one_body, step, verified_region):
                remaining = (end - int(time.time() * 1000)) / 1000
                require(remaining > 0, "WHATIF_REQUEST_DEADLINE")
                wire = HttpRequest(one_method, one_url)
                wire.headers["Accept"] = "application/json"
                if one_body is not None:
                    wire.set_json_body(one_body)
                    wire.headers["Content-Type"] = "application/json"
                response = client.send_request(wire, stream=True, connection_verify=True, connection_timeout=remaining, read_timeout=remaining)
                try:
                    headers = {key.lower(): value for key, value in response.headers.items()
                               if key.lower() in ("location", "azure-asyncoperation", "retry-after")}
                    chunks, length = [], 0
                    for chunk in response.stream_download(client._pipeline):
                        length += len(chunk)
                        require(length <= MAX_BYTES and int(time.time() * 1000) < end, "WHATIF_RESPONSE_BOUND")
                        chunks.append(chunk)
                    raw = b"".join(chunks)
                    parse_error = False
                    try:
                        result = json.loads(raw) if raw.strip() else None
                    except (ValueError, UnicodeError):
                        result, parse_error = None, True
                    return {"version": 1, "statusCode": response.status_code, "headers": headers, "body": result,
                            "bodyParseError": parse_error, "contextSha256": request["contextSha256"],
                            "step": step, "verifiedRegion": verified_region}
                finally:
                    response.internal_response.close()

            output = None
            if request["action"] == "start" and expected_scope == "group":
                region = send("GET", HOST + scope + "?api-version=2024-03-01", None, "what-if.region", None)
                if region["statusCode"] != 200:
                    output = region
                else:
                    value = region["body"]
                    require(not region["bodyParseError"] and isinstance(value, dict)
                            and str(value.get("id", "")).lower() == scope.lower()
                            and value.get("location") in ("australiaeast", "Australia East"), "WHATIF_GROUP_REGION_CHANGED")
            if output is None:
                output = send(method, url, body, "what-if." + request["action"], request["location"])
    finally:
        session.close()
    fd = os.open(response_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(output, stream, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        raise
    print("PRIVATE_WHATIF_RESPONSE_SAVED")


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        label = str(error) if isinstance(error, Stop) and re.fullmatch(r"[A-Z_]+", str(error)) else "AUTHENTICATED_WHATIF_REQUEST_FAILED"
        print(label, file=sys.stderr)
        raise SystemExit(1) from None
