import json
import logging
import requests
import os

try:
    from tinydb import TinyDB
    from flask import Flask, render_template, request, redirect, url_for
    from scripts.utils import init_db, retrieve_hosts, retrieve_detections, update_needed, mailer, retrieve_c2hosts
except Exception as error:
    print(f'\nMissing import requirements: {str(error)}\n')

requests.packages.urllib3.disable_warnings()

app = Flask(__name__)
app.config['send_file_max_age_default'] = 60

src_database = '.src_db.json'
tinydb_src = TinyDB(src_database)

dest_database = '.dest_db.json'
tinydb_dest = TinyDB(dest_database)

tc_dest_database = '.tcdest_db.json'
tinydb_tc_dest = TinyDB(tc_dest_database)

src_det_database = '.srcdet_db.json'
tinydb_src_det = TinyDB(src_det_database)

logging.basicConfig(filename='/var/log/vae.log', format='%(asctime)s: %(message)s', level=logging.INFO)

src_detection_types = [
    ('ransomware_file_activity', 'Ransomware File Activity')
]

dest_detection_types = [
    ('external_remote_access', 'External Remote Access'),
    ('hidden_http_tunnel', 'Hidden HTTP Tunnel'),
    ('hidden_https_tunnel', 'Hidden HTTPS Tunnel'),
    ('malware_update', 'Malware Update'),
    ('peer_to_peer', 'Peer-To-Peer'),
    ('stealth_http_post', 'Stealth HTTP Post'),
    ('suspect_domain_activity', 'Suspect Domain Activity'),
    ('suspicious_http', 'Suspicious HTTP'),
    ('tor_activity', 'TOR Activity'),
    ('suspicious_relay', 'Suspicious Relay')
]


@app.route('/')
def hello_world():
    return 'VAE is running'


@app.route('/config')
def config():
    config = {}
    with open('config.json') as json_config:
        config = json.load(json_config)
    
    return render_template('config.html', CONFIG=config, SRC_DET_TYPES=src_detection_types,
                           DEST_DET_TYPES=dest_detection_types)


@app.route('/submit', methods=['POST'])
def submit():
    config = {}
    with open('config.json') as json_config:
        config = json.load(json_config)

    form_data = request.form

    config['brain'] = form_data.get('appliance')
    config['token'] = form_data.get('token') if len(form_data.get('token')) > 0 else config['token']
    config['bogon'] = form_data.get('bogon')
    config['active_only'] = True if form_data.get('active', default=False) else False
    config['untriaged_only'] = True if form_data.get('triaged', default=False) else False
    tags = form_data.get('tags')
    config['tags'] = tags.replace(', ', ',').split(',') if tags else None
    src_wl = form_data.get('src_wl')
    config['src_wl'] = src_wl.replace(', ', ',').split(',') if src_wl else None
    dst_wl = form_data.get('dst_wl')
    config['dst_wl'] = dst_wl.replace(', ', ',').split(',') if dst_wl else None

    if form_data.get('cs'):
        config['certainty_gte'] = int(form_data.get('cs'))
    
    if form_data.get('ts'):
        config['threat_gte'] = int(form_data.get('ts'))
   
    if form_data.get('c2cs'):
        config['c2_certainty_gte'] = int(form_data.get('c2cs')) if form_data.get('c2cs', default=50) else 50

    if form_data.get('c2ts'):
        config['c2_threat_gte'] = int(form_data.get('c2ts')) if form_data.get('c2ts', default=50) else 50

    config['dest_detection_types'] = []
    config['src_detection_types'] = []

    for dest_det_type in dest_detection_types:
        if form_data.get(dest_det_type[0]):
            config['dest_detection_types'].append(dest_det_type[1])

    for src_det_type in src_detection_types:
        if form_data.get(src_det_type[0]):
            config['src_detection_types'].append(src_det_type[1])

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
    """
    Returns source host IPs based on tags, and host threat and certainty
    :return: src.txt
    """
    if update_needed(os.path.abspath(src_database), 5):
        #  If DB last updated longer than 5 minutes

        srcdb = tinydb_src.table('src')
        tinydb_src.drop_table('src')

        """Retrieve src hosts"""

        with open('config.json') as json_config:
            config_data = json.load(json_config)
            tags = config_data['tags']
            src_wl = config_data['src_wl']
            certainty_gte = config_data['certainty_gte']
            threat_gte = config_data['threat_gte']
            brain = config_data['brain']
            token = config_data['token']
            active_only = config_data['active_only']
            bogon = config_data['bogon']
            mail = config_data['mail']

        if tags or src_wl or certainty_gte or threat_gte:
            args = {
                'url': brain,
                'token': token,
            }
            if active_only:
                args.update({'state': 'active'})

            if tags:
                args.update({'tags': tags})

            if src_wl:
                args.update({'src_wl':src_wl})
            
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


@app.route('/dbl/src_det')
def get_dbl_source_det():
    """
    Returns source host IPs based detection type
    :return: src_det.txt
    """
    if update_needed(os.path.abspath(src_det_database), 5):
        #  If DB last updated longer than 5 minutes

        srcdetdb = tinydb_src.table('src_det')
        tinydb_src_det.drop_table('src_det')

        """Retrieve src hosts with specific detection(s)"""

        with open('config.json') as json_config:
            config_data = json.load(json_config)
            src_wl = config_data['src_wl']
            brain = config_data['brain']
            token = config_data['token']
            active_only = config_data['active_only']
            bogon = config_data['bogon']
            mail = config_data['mail']
            src_detection_types = config_data['src_detection_types']

        if src_detection_types:
            args = {
                'url': brain,
                'token': token,
            }
            if active_only:
                args.update({'state': 'active'})

            if src_wl:
                args.update({'src_wl': src_wl})

            if src_detection_types:
                args.update({'src_detection_types': src_detection_types})

            retrieve_hosts(args, srcdetdb)

            ip_addrs = []
            ip_addrs += ['{ip}\n'.format(ip=host['ip']) for host in srcdetdb]
            ip_addrs = set(ip_addrs)

            fh = open('static/src_det.txt', 'w')

            if ip_addrs:
                fh.writelines(ip_addrs)
                fh.close()
                if mail['smtp_server']:
                    mailer(mail, os.path.abspath('static/src_det.txt'), 'source')
            else:
                fh.writelines(bogon)
                fh.close()
        else:
            fh = open('static/src_det.txt', 'w')
            fh.writelines(bogon)
            fh.close()

    return app.send_static_file('src_det.txt')


@app.route('/dbl/dest')
def get_dbl_dst():
    """
    Returns destination IPs from specified detections types.
    :return: static/dest.txt
    """
    if update_needed(os.path.abspath(dest_database), 5):
        #  If DB last updated longer than 5 minutes
        destdb = tinydb_dest.table('dest')
        tinydb_dest.drop_table('dest')

        """Retrieve detections"""

        with open('config.json') as json_config:
            config_data = json.load(json_config)
            dest_detection_types = config_data['dest_detection_types']
            brain = config_data['brain']
            token = config_data['token']
            active_only = config_data['active_only']
            untriaged_only = config_data['untriaged_only']
            bogon = config_data['bogon']
            mail = config_data['mail']
            dst_wl = config_data['dst_wl']

        if dest_detection_types:
            for dest_detection_type in dest_detection_types:
                intel = {
                    'url': brain,
                    'token': token,
                    'detection_type': dest_detection_type
                }
                if active_only:
                    intel.update({'state': 'active'})
                if untriaged_only:
                    intel.update({'triaged': 'false'})
                
                if dst_wl:
                    intel.update({'dst_wl':dst_wl})

                retrieve_detections(intel, destdb)

            ip_addrs = []
            for dest_detection in destdb:
                ip_addrs += ['{ip}\n'.format(ip=ip) for ip in dest_detection['dst_ips']]
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


@app.route('/dbl/tc_dest')
def get_dbl_tc_dst():
    """
    Returns destination IPs for hosts with C2 detections based on host T/C scoring thresholds
    :return: tc_dest.txt
    """
    if update_needed(os.path.abspath(tc_dest_database), 5):
        #  If DB last updated longer than 5 minutes
        tcdestdb = init_db(tc_dest_database, 'tcdest')
        tinydb_tc_dest.drop_table('tcdest')
   
        """Retrieve detections"""

        with open('config.json') as json_config:
            config_data = json.load(json_config)
            brain = config_data['brain']
            token = config_data['token']
            active_only = config_data['active_only']
            untriaged_only = config_data['untriaged_only']
            bogon = config_data['bogon']
            mail = config_data['mail']
            tscore = config_data['c2_threat_gte']
            cscore = config_data['c2_certainty_gte']
            dst_wl = config_data['dst_wl']

        intel = {
            'url': brain,
            'token': token,
            'c2_threat_score':tscore,
            'c2_certainty_score':cscore
        }
        if active_only:
            intel.update({'state': 'active'})
        if untriaged_only:
            intel.update({'triaged': 'false'})
        if dst_wl:
            intel.update({'dst_wl':dst_wl})

        retrieve_c2hosts(intel, tcdestdb)

        ip_addrs = []
        for tcdest in tcdestdb:
            ip_addrs += ['{ip}\n'.format(ip=ip) for ip in tcdest['dst_ips']]

        ip_addrs = set(ip_addrs)

        fh = open('static/tc_dest.txt', 'w')
        if ip_addrs:
            fh.writelines(ip_addrs)
            fh.close()
            if mail['smtp_server']:
                mailer(mail, os.path.abspath('static/tc_dest.txt'), 'destination')
        else:
            fh.writelines(bogon)
            fh.close()

    return app.send_static_file('tc_dest.txt')


if __name__ == '__main__':
    app.run()
