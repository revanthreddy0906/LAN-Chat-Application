"""The real terminal client (client.py) against a server with all security defaults on."""
import os
import subprocess
import sys

from common import *  # noqa: F401,F403
import server as server_module
from chat_core import connect_secure

home = os.environ["LANCHAT_HOME"]
context, fingerprint = server_module.default_tls_context()
server = ChatServer("127.0.0.1", 0, accounts=AccountStore(f"{tmp}/term.json"), tls_context=context, quiet=True)
server.start()
port = server.bound_port
# trust the certificate once, the way a first sign-in would, so the client does not stop to ask
connect_secure("127.0.0.1", port, "Setup", "river-stone-42", Settings(home), confirm_trust=lambda *a: True,
               confirm_plain=lambda *a: False).connection.close()


def client(username, password, lines, timeout=40):
    """Run client.py, typing one line at a time so the server's answers arrive before it quits."""
    process = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "client.py"), "127.0.0.1", "--port", str(port),
         "--username", username, "--password", password],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env={**os.environ, "LANCHAT_HOME": home}, cwd=ROOT)
    time.sleep(1.5)
    for line in lines:
        try:
            process.stdin.write(line + "\n")
            process.stdin.flush()
        except OSError:
            break
        time.sleep(0.8)
    try:
        output, _ = process.communicate(timeout=timeout)  # closes stdin for us
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate()
    return output


out = client("Term", "river-stone-42", ["hello from the terminal", "/users", "/members", "/search terminal",
                                       "/passwd river-stone-42 mountain-lake-77", "/quit"])
check("signs in over TLS", "(encrypted)" in out)
check("sends a message that is stored", any(m.body == "hello from the terminal" for m in server.store.history_for(2, 10)) or
      any(m.body == "hello from the terminal" for m in server.store.history_for(1, 10)))
check("/users lists me", "Online" in out and "Term" in out)
check("/members shows roles", "Members" in out)
check("/search finds my message", "Search results" in out)
check("/passwd works", "Password changed" in out)
check("the new password is in force", server.accounts.authenticate("Term", "mountain-lake-77")[0] == "ok")
check("no traceback", "Traceback" not in out)
check("the plain-text note is shown", "Plain-text mode" in out)

out = client("Term", "wrong-guess", [])
check("a wrong password is explained", "wrong password" in out)
out = client("Newbie", "abc", [])
check("a weak new password is refused", "stronger password" in out)
check("and no account was made", server.store.get_user("Newbie") is None)
for _ in range(4):
    client("Term", "wrong-guess", [])
out = client("Term", "mountain-lake-77", [])
check("repeated failures lock the account, even for the right password", "try again in" in out or "locked" in out)
check("the lockout is in the audit log", "lockout" in [r["action"] for r in server.store.audit_rows(limit=50)])
server.stop()
import shutil
shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
