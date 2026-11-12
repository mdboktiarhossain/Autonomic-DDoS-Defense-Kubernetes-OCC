import paramiko

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('192.168.160.129', username='osu', password='osu', timeout=30)

cmd = "python3 -u /home/osu/scenario2_parallel_l7/run_tcon_gil_eval.py"
stdin, stdout, stderr = c.exec_command(cmd)

for line in iter(stdout.readline, ""):
    print(line, end="", flush=True)

err = stderr.read().decode('utf-8', errors='replace').strip()
if err:
    print("\nSTDERR:", err)

c.close()
