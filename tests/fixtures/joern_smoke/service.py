import subprocess


def execute(value):
    subprocess.run(value, shell=True, check=False)
