import os
port = 10000
command = 'socat -d -d tcp-l:' + str(port) + ',reuseaddr,fork EXEC:"python -u server.py" '
os.system(command)