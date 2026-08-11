import os

from flask import request


def run_command() -> None:
    command = request.args.get("cmd")
    os.system(command)
