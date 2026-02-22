import subprocess
import pickle

def run_command(cmd):
    # This should be caught
    subprocess.call(cmd, shell=True)

def load_data(data):
    return pickle.loads(data)

exec("print('hello')")

api_key = "12345-abcde"
