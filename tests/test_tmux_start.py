"""A tmux server the deck starts gets tmux's own macOS privacy grants, not python's: started from the deck's python3, every chat in it
lacks Full Disk Access, and a privacy prompt nobody sees can freeze one. Runs a throwaway tmux server (deckfdatest) through the real launchd."""
import os, plistlib, subprocess, sys, tempfile, time, unittest
from pathlib import Path

TMP = tempfile.mkdtemp()
for _k, _v in dict(DECK_SECRETS=TMP, DECK_STORE=f"{TMP}/passkeys.json", DECK_PREFS=f"{TMP}/prefs.json", DECK_RP_ID="localhost", DECK_TS_USER="me@example.com",
                  DECK_TMUX_SOCKET="deckfdatest", DECK_SHOW_TEST="1").items(): os.environ.setdefault(_k, _v)  # never over another test module's settings
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server

SOCK, TCC = "deckfdatest", "/Library/Application Support/com.apple.TCC/TCC.db"
def T(*a, sock=SOCK): return subprocess.run(["tmux", "-L", sock, *a], capture_output=True, text=True).stdout.strip()
def readable(sock=SOCK): return T("run-shell", f"head -c1 '{TCC}' >/dev/null 2>&1 && echo yes || echo no", sock=sock) == "yes"
def jobs(): return [l for l in subprocess.run(["launchctl", "list"], capture_output=True, text=True).stdout.splitlines() if "local.deck-job." in l]

def tmux_has_grant():
    """Whether tmux itself has Full Disk Access on this Mac: a tmux server launchd starts directly is tmux's own."""
    sock, d = "deckfdactltest", tempfile.mkdtemp(); p = f"{d}/j.plist"; label = f"local.deckfdactl.{os.getpid()}"
    with open(p, "wb") as f:
        plistlib.dump({"Label": label, "ProgramArguments": [server.shutil.which("tmux"), "-L", sock, "new-session", "-d", "-s", "t", "cat"],
                       "RunAtLoad": True, "AbandonProcessGroup": True}, f)
    subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", p], capture_output=True)
    try:
        end = time.time() + 5
        while time.time() < end and subprocess.run(["tmux", "-L", sock, "has-session"], capture_output=True).returncode: time.sleep(0.1)
        return readable(sock)
    finally:
        T("kill-server", sock=sock); subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/{label}"], capture_output=True)


@unittest.skipUnless(sys.platform == "darwin", "macOS privacy grants")
class NewServer(unittest.TestCase):
    def setUp(self):
        T("kill-server")
        d = Path(os.path.realpath(tempfile.mkdtemp())); self.cwd = d / "proj"; self.cwd.mkdir()
        old = {k: getattr(server, k, None) for k in ("HOME", "engine_exe", "TMUX_SOCKS", "LAUNCHCTL")}
        self.addCleanup(lambda: [setattr(server, k, v) for k, v in old.items()]); self.addCleanup(T, "kill-server")
        server.HOME, server.engine_exe, server.TMUX_SOCKS = d, lambda e: "/bin/cat", [SOCK]
        os.environ["DECK_DRYRUN"] = "1"; self.addCleanup(os.environ.pop, "DECK_DRYRUN", None)
        os.environ["DECK_TEST_MARK"] = "carried"; self.addCleanup(os.environ.pop, "DECK_TEST_MARK", None)

    def test_new_server_gets_tmux_grant(self):
        if subprocess.run(["head", "-c1", TCC], capture_output=True).returncode == 0:
            self.skipTest("this process has Full Disk Access itself, so a server it starts would too: nothing to tell apart")
        if not tmux_has_grant(): self.skipTest("tmux has no Full Disk Access on this Mac (System Settings > Privacy & Security)")
        pane = server.start(str(self.cwd), "claude", None)
        self.assertTrue(pane and pane.startswith(SOCK + "."), pane)
        self.assertTrue(readable(), "the chat's tmux server can't read a Full Disk Access file: it was started with python's grants, not tmux's")
        self.assertEqual(T("show-environment", "-g", "DECK_TEST_MARK"), "DECK_TEST_MARK=carried")  # the server has the deck's environment, as before
        self.assertEqual(jobs(), [])  # the one-off launchd job is gone; the server lives on
        time.sleep(1); self.assertEqual(subprocess.run(["tmux", "-L", SOCK, "has-session"], capture_output=True).returncode, 0)

    def test_second_chat_joins_running_server(self):
        a = server.start(str(self.cwd), "claude", None); b = server.start(str(self.cwd), "claude", None)
        self.assertTrue(a and b and a != b, (a, b))
        self.assertEqual(len(T("list-windows", "-t", "=work", "-F", "#{window_id}").split()), 2)

    def test_chained_commands_all_run(self):  # an SSH terminal marks its session in the same call: those options must land on a launchd-started server too
        for i in range(5):
            T("kill-server")
            r = server.tmux_new(SOCK, "new-session", "-d", "-P", "-F", "#{pane_id}", "-s", "x", "cat",
                                *[x for n in range(20) for x in (";", "set-option", "-t", "=x:", f"@m{n}", str(n))])
            self.assertTrue(r.startswith("%"), r)
            self.assertEqual(T("show-options", "-v", "-t", "=x:", "@m19"), "19", f"run {i}")
        T("kill-server")  # a slow command in the chain: the job must be left to finish it, not stopped once the pane is printed
        server.tmux_new(SOCK, "new-session", "-d", "-P", "-F", "#{pane_id}", "-s", "x", "cat", ";", "run-shell", "sleep 1", ";", "set-option", "-t", "=x:", "@after", "1")
        self.assertEqual(T("show-options", "-v", "-t", "=x:", "@after"), "1")
        self.assertEqual(jobs(), [])

    def test_without_launchd_still_starts(self):  # a deck that can't reach launchd (a guest with no login session) starts the server itself, as before
        server.LAUNCHCTL = "/usr/bin/false"
        pane = server.start(str(self.cwd), "claude", None)
        self.assertTrue(pane and pane.startswith(SOCK + "."), pane)
        self.assertEqual(len(T("list-windows", "-t", "=work", "-F", "#{window_id}").split()), 1)  # ran once, not twice


if __name__ == "__main__":
    unittest.main()
