# import psutil

# PROCNAME = "python.exe"

# for proc in psutil.process_iter():
#     # check whether the process name matches
#     if proc.name() == PROCNAME:
#         proc.kill()

import os
os.system("taskkill /im chrome.exe")