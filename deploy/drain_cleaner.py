"""Установщик удерживает соединение до остановки службы, чтобы приём не открылся."""
import math
import socket
import subprocess
import sys
import time


def wait_until_idle(connection, timeout):
    deadline = time.monotonic() + timeout
    pending = None
    with connection.makefile("rb") as status:
        try:
            while (remaining := deadline - time.monotonic()) > 0:
                connection.settimeout(remaining)
                line = status.readline(64)
                if line == b"busy\n":
                    raise RuntimeError("служба уже готовится к другому обновлению")
                if not line.endswith(b"\n") or not line[:-1].isdigit():
                    raise RuntimeError("служба не подтвердила завершение операций")
                pending = int(line)
                if pending == 0:
                    return
        except TimeoutError:
            pass
    count = pending if pending is not None else "не удалось определить"
    raise RuntimeError(f"время ожидания истекло, незавершённых операций: {count}")


def main(socket_path, seconds):
    try:
        timeout = float(seconds)
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError
    except ValueError:
        print("CLEANER_DRAIN_TIMEOUT должен задавать положительное число секунд", file=sys.stderr)
        return 2
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        try:
            connection.settimeout(timeout)
            connection.connect(socket_path)
            wait_until_idle(connection, timeout)
        except (OSError, RuntimeError) as error:
            print(f"Cleaner: {error}", file=sys.stderr)
            return 2
        try:
            subprocess.run(["systemctl", "stop", "cleaner.service"], check=True, timeout=100)
        except (OSError, subprocess.SubprocessError):
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
