import subprocess

ALLOWED = {"status"}


def guarded(value):
    if value not in ALLOWED:
        raise ValueError("unsupported command")
    subprocess.run([value], shell=False, check=False)
