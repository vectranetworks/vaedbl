import json
import logging
import requests
import os

try:
    from tinydb import TinyDB
    from flask import Flask, render_template, request, redirect, url_for
    from scripts.utils import retrieve_hosts, retrieve_detections, update_needed, mailer
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


detection_types = [('external_remote_access', 'External Remote Access'),
                   ('hidden_dns_tunnel', 'Hidden DNS Tunnel'),
                   ('hidden_http_tunnel', 'Hidden HTTP Tunnel'),
                   ('hidden_https_tunnel', 'Hidden HTTPS Tunnel'),
                   ('malware_update', 'Malware Update'),
                   ('peer_to_peer', 'Peer-To-Peer'),
                   ('stealth_http_post', 'Stealth HTTP Post'),
                   ('suspect_domain_activity', 'Suspect Domain Activity'),
                   ('suspicious_http', 'Suspicious HTTP'),
                   ('tor_activity', 'TOR Activity'),
                   ('suspicious_relay', 'Suspicious Relay'),
                   ('multi_home_fronted_tunnel', 'Multi-home Fronted Tunnel')]


@app.route('/')
def hello_world():
    return 'VAE is running'


@app.route('/config')
def config():
    config = {}
    with open('config.json') as json_config:
        config = json.load(json_config)
    return render_template('config.html', CONFIG=config, DET_TYPES=detection_types)


@app.route('/submit', methods=['POST'])
def submit():
    config = {}
    with open('config.json') as json_config:
        config = json.load(json_config)

    form_data = request.form

    config['brain'] = form_data.get('appliance')
    config['token'] = form_data.get('token')
    config['bogon'] = form_data.get('bogon')
    config['active_only'] = True if form_data.get('active', default=False) else False
    config['untriaged_only'] = True if form_data.get('triaged', default=False) else False
    tags = form_data.get('tags')
    config['tags'] = tags.replace(', ', ',').split(',') if tags else None
    config['certainty_gte'] = int(form_data.get('cs'))
    config['threat_gte'] = int(form_data.get('ts'))
    config['detection_types'] = []

    for det_type in detection_types:
        if form_data.get(det_type[0]):
            config['detection_types'].append(det_type[1])

    config_mail = config['mail']
    config_mail['smtp_server'] = form_data.get('smtp_server')
    config_mail['port'] = form_data.get('port')
    config_mail['username'] = form_data.get('user')
    config_mail['password'] = form_data.get('password')
    config_mail['sender'] = form_data.get('mail_from')
    config_mail['recipient'] = form_data.get('mail_to')

    with open('config.json', mode='w') as json_config:
        json.dump(config, json_config, indent=4)

    return redirect(url_for('hello_world'))


@app.route('/dbl/src')
def get_dbl_source():
    if update_needed(os.path.abspath(src_database), 5):
        #  If DB last updated longer than 5 minutes

        srcdb = tinydb_src.table('src')
        tinydb_src.drop_table('src')

        """Retrieve src hosts"""

        with open('config.json') as json_config:
            config_data = json.load(json_config)
            tags = config_data['tags']
            certainty_gte = config_data['certainty_gte']
            threat_gte = config_data['threat_gte']
            brain = config_data['brain']
            token = config_data['token']
            active_only = config_data['active_only']
            bogon = config_data['bogon']
            mail = config_data['mail']

        if tags or certainty_gte or threat_gte:
            args = {
                'url': brain,
                'token': token,
            }
            if active_only:
                args.update({'state': 'active'})

            if tags:
                args.update({'tags': tags})
            
            if certainty_gte or threat_gte:
                args.update({
                    'certainty_gte': certainty_gte,
                    'threat_gte': threat_gte})

            retrieve_hosts(args, srcdb)

            ip_addrs = []
            ip_addrs += ['{ip}\n'.format(ip=host['ip']) for host in srcdb]
            ip_addrs = set(ip_addrs)

            fh = open('static/src.txt', 'w')

            if ip_addrs:
                fh.writelines(ip_addrs)
                fh.close()
                if mail['smtp_server']:
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
        tinydb_dest.drop_table('dest')

        """Retrieve detections"""

        with open('config.json') as json_config:
            config_data = json.load(json_config)
            detection_types = config_data['detection_types']
            brain = config_data['brain']
            token = config_data['token']
            active_only = config_data['active_only']
            untriaged_only = config_data['untriaged_only']
            bogon = config_data['bogon']
            mail = config_data['mail']

        if detection_types:
            for detection_type in detection_types:
                intel = {
                    'url': brain,
                    'token': token,
                    'detection_type': detection_type
                }
                if active_only:
                    intel.update({'state': 'active'})
                if untriaged_only:
                    intel.update({'triaged': 'false'})

                retrieve_detections(intel, destdb)

            ip_addrs = []
            for detection in destdb:
                ip_addrs += ['{ip}\n'.format(ip=ip) for ip in detection['dst_ips']]
            ip_addrs = set(ip_addrs)

            fh = open('static/dest.txt', 'w')

            if ip_addrs:
                fh.writelines(ip_addrs)
                fh.close()
                if mail['smtp_server']:
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
