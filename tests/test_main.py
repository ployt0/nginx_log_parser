import os
import subprocess

from main import main

def test_main():
    # Find we're in tests so .. up a dir, if that's our log's location.
    main(["access.log"])
    subprocess.run("pwd", shell=True, capture_output=True)
    # We could instead capture the output of this using subprocess.run, except there is no output!
    assert os.system("../nginx_digester/main.py access.log") == 0


