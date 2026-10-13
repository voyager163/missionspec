"""TEST ONLY: exercise the real OS pseudo-terminal protocol, not an authority provider."""
import errno
import json
import os
import pty
import re
import select
import signal
import sys
import time

mode, directory, *command = sys.argv[1:]
pid, fd = pty.fork()
if pid == 0:
    os.chdir(directory)
    os.execv(command[0], command)
output = b""
answered = set()
deadline = time.monotonic() + 30
try:
    while time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], 0.1)
        if not readable:
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError as error:
            if error.errno == errno.EIO:
                break
            raise
        if not chunk:
            break
        output += chunk
        for challenge in re.findall(rb'Type exactly "(confirm [a-f0-9]{32})"', output):
            if challenge not in answered:
                answered.add(challenge)
                os.write(fd, challenge + b"\n" if mode == "confirm" else b"decline\n")
    else:
        os.kill(pid, signal.SIGKILL)
        raise RuntimeError("TEST terminal protocol deadline exceeded")
finally:
    os.close(fd)
_, status = os.waitpid(pid, 0)
print(json.dumps({"code": os.waitstatus_to_exitcode(status), "confirmations": len(answered), "output": output.decode("utf-8", errors="replace")}))
