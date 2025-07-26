import subprocess
import sys


def start_app():
    return subprocess.Popen(
        [sys.executable, "src/app.py"], creationflags=subprocess.CREATE_NEW_CONSOLE
    )


def start_launcher(app_pid):
    return subprocess.Popen(
        [sys.executable, "launcher.py", str(app_pid)],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


def main():
    app_proc = start_app()
    print(f"App started with PID {app_proc.pid}")

    launcher_proc = start_launcher(app_proc.pid)
    print(f"Launcher started with PID {launcher_proc.pid}")

    app_proc.wait()
    print("App process exited.")

    launcher_proc.wait()
    print("Launcher process exited.")


if __name__ == "__main__":
    main()
