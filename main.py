import subprocess
import sys


def start_app():
    return subprocess.Popen(
        [sys.executable, "src/app.py"], creationflags=subprocess.CREATE_NEW_CONSOLE
    )


def main():
    app_proc = start_app()
    print(f"App started with PID {app_proc.pid}")

    app_proc.wait()
    print("App process exited.")


if __name__ == "__main__":
    main()
