import platform
import subprocess
import sys
import time

import psutil


def watchdog(main_pid):
    print(f"Watchdog started with main_pid={main_pid}")

    # 운영 체제에 따라 실행할 스크립트 파일을 다르게 지정
    system = platform.system()
    if system == "Windows":
        subprocess.run(["set-win-localproxy.bat"])
        unset_command = ["unset-win-localproxy.bat"]

    elif sys.platform == "Darwin":
        subprocess.run(["set-mac-localproxy.bat"])
        unset_command = ["unset-mac-localproxy.bat"]

    elif sys.platform == "Linux":
        subprocess.run(["set-fedora-localproxy.bat"])
        unset_command = ["unset-fedora-localproxy.bat"]

    while True:
        if not psutil.pid_exists(main_pid):
            print(f"PID {main_pid} does not exist. Exiting watchdog.")
            subprocess.run(unset_command)
            break
        time.sleep(1)


if __name__ == "__main__":
    main_pid = int(sys.argv[1])
    watchdog(main_pid)
