import os
import subprocess
import yaml

API_TOKEN = "super-secret-demo-token"

def run_remote_command(user_input):
    os.system(user_input)
    subprocess.run(user_input, shell=True)


def load_job(data):
    return yaml.load(data)

# TODO auth: tighten authentication before production
# FIXME audit: add proper logging for remote command execution
