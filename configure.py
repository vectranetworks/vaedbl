#! /usr/bin/env python
import os

flask_command = os.popen('which flask')
flask_output = flask_command.read().split('\n')[0]
flask_command.close()

if len(flask_output) == 0:
    print("No flask app found in path.  Please ensure requirements have been met.\n Exiting")
    exit(0)
else:
    print('Flask probably found, continuing')
    #  write to supervisor.conf file
    with open('conf/supervisor.conf', 'r') as file:
        supervisor_data = file.readlines()

    pwd_command = os.popen('pwd')
    pwd_output = pwd_command.read().strip()
    supervisor_data[1] ='environment=FLASK_APP="'+pwd_output+'/vaedbl.py"\n'

    with open('conf/supervisor.conf', 'w') as file:
        file.writelines(supervisor_data)

    #  write to systemd.service file
    with open('conf/systemd.service', 'r') as file:
        systemd_data = file.readlines()

    whoami = os.popen('whoami')
    user = whoami.read().strip()
    whoami.close()
    systemd_data[4] = 'User='+user+'\n'

    systemd_data[5] = 'WorkingDirectory='+pwd_output+'\n'
    systemd_data[6] = 'Environment=FLASK_APP='+pwd_output+'/vaedbl.py\n'

    systemd_data[7] = 'ExecStart='+flask_output+ ' run --host=0.0.0.0 --port=8080\n'

    with open('conf/systemd.service', 'w') as file:
        file.writelines(systemd_data)

    os.system('sudo cp conf/systemd.service /etc/systemd/system/vae.service')
    os.system('sudo touch /var/log/vae.log')
    os.system('sudo chown '+user+':'+user+' /var/log/vae.log')
    os.system('sudo systemctl enable vae.service')
    os.system('sudo systemctl daemon-reload')
    os.system('sudo systemctl start vae.service')
