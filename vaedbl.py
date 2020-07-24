import json
import logging
import requests
import os

try:
    from tinydb import TinyDB
    from flask import Flask, render_template, request, redirect, url_for
    from scripts.utils import retrieve_hosts, retrieve_detections, update_needed, mailer
    from config import bogon, args, intel_args, active_state, det_triaged, mail
except Exception as error:
    print(f'\nMissing import requirements: {str(error)}\n')

requests.packages.urllib3.disable_warnings()

app = Flask(__name__)
app.config['send_file_max_age_default'] = 60
src_database = '.src_db.json'
tinydb_src = TinyDB(src_database)
dest_database = '.dest_db.json'
tinydb_dest = TinyDB(dest_database)
logging.basicConfig(filename='/var/log/vae.log', format='%(asctime)s: %(message)s', level=logging.INFO)

detection_types = ['External Remote Access', 'Hidden DNS Tunnel', 'Hidden HTTP Tunnel', 'Hidden HTTPS Tunnel', 'Malware Update', 'Peer-To-Peer', 'Stealth HTTP Post', 'Suspect Domain Activity', 'Suspicious HTTP', 'TOR Activity', 'Suspicious Relay', 'Multi-home Fronted Tunnel']

@app.route('/')
def hello_world():
    return 'VAE is running'

@app.route('/config')
def config():
    config = {}
    with open('config.json') as json_config:
        config = json.load(json_config)
    return render_template('config.html', CONFIG=config)

@app.route('/submit', methods=['POST'])
def submit():
    config = {}
    with open('config.json') as json_config:
        config = json.load(json_config)
    
    form_data = request.form

    config['brain'] = form_data.get('appliance')
    config['token'] = form_data.get('token')
    config['det_active'] = form_data.get('')
    config['det_triaged'] = form_data.get('')
    config['bogon'] = form_data.get('bogon')

    config['tags'] = form_data.get('tags').replace(old=', ', new=',').split(separator=',')
    config['certainty_gte'] = form_data.get('cs')
    config['threat_gte'] = form_data.get('ts')
    config['detection_types'] = []
    for detection_type in detection_types:
        if form_data.get(detection_type):
            config['detection_types'].append(detection_type)

    config_mail = config['mail']
    config_mail['smtp_server'] = form_data.get('smtp_server')
    config_mail['port'] = form_data.get('port')
    config_mail['username'] = form_data.get('user')
    config_mail['password'] = form_data.get('password')
    config_mail['sender'] = form_data.get('mail_from')
    config_mail['recipient'] = form_data.get('mail_to')

    vectra_appliance = request.form.get('appliance')
    return redirect(url_for('hello_world'))

@app.route('/dbl/src')
def get_dbl_source():
    if update_needed(os.path.abspath(src_database), 5):
        #  If DB last updated longer than 5 minutes

        srcdb = tinydb_src.table('src')
        tinydb_src.purge_table('src')

        """Retrieve src hosts"""

        if args:
            retrieve_hosts(args, srcdb)

            ip_addrs = []
            ip_addrs += ['{ip}\n'.format(ip=host['ip']) for host in srcdb]
            ip_addrs = set(ip_addrs)

            fh = open('static/src.txt', 'w')

            if ip_addrs:
                fh.writelines(ip_addrs)
                fh.close()
                if mail:
                    mailer(mail, os.path.abspath('static/src.txt'), 'source')
            else:
                fh.writelines(bogon)
                fh.close()
        else:
            fh = open('static/src.txt', 'w')
            fh.writelines(bogon)
            fh.close()

    return app.send_static_file('src.txt')


@app.route('/dbl/dest')
def get_dbl_dst():

    if update_needed(os.path.abspath(dest_database), 5):
        #  If DB last updated longer than 5 minutes
        destdb = tinydb_dest.table('dest')
        tinydb_dest.purge_table('dest')

        '''
        Retrieve detections
        '''

        if intel_args:
            for intel in intel_args:
                retrieve_detections(intel, destdb)

            ip_addrs = []
            for detection in destdb:
                ip_addrs += ['{ip}\n'.format(ip=ip) for ip in detection['dst_ips']]
            ip_addrs = set(ip_addrs)

            fh = open('static/dest.txt', 'w')

            if ip_addrs:
                fh.writelines(ip_addrs)
                fh.close()
                if mail:
                    mailer(mail, os.path.abspath('static/dest.txt'), 'destination')
            else:

                fh.writelines(bogon)
                fh.close()
        else:
            fh = open('static/dest.txt', 'w')
            fh.writelines(bogon)
            fh.close()

    return app.send_static_file('dest.txt')


if __name__ == '__main__':
    app.run()
