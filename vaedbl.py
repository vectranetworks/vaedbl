import logging
import requests

from tinydb import TinyDB
from flask import Flask, render_template
from scripts.utils import retrieve_hosts, retrieve_detections

requests.packages.urllib3.disable_warnings()

app = Flask(__name__)
app.config['send_file_max_age_default'] = 60
database = '.db.json'
tinydb = TinyDB(database)
logging.basicConfig(filename='/var/log/vae.log', format='%(asctime)s: %(message)s', level=logging.INFO)

# To minimize security risk create service account with read only permissions
brain = 'https://<brain>'
token = '<token>'

# By default, only return active, untriaged detections.  To return both active and inactive detection, comment out the
# det_state variable in intel_args
det_state, det_triaged = 'active', 'false'


@app.route('/')
def hello_world():
    return "VAE is running"


@app.route('/dbl/src')
def get_dbl_source():
    srcdb = tinydb.table('src')
    tinydb.purge_table('src')

    '''
    Retrieve src hosts
    '''
    # args = {
    #     'url': brain,
    #     'token': token,
    #     'tags': '<tags>',
    #     'certainty_gte': 50,
    #     'threat_gte': 50
    # }

    # retrieve_hosts(args, srcdb)

    ip_addrs = []
    ip_addrs += ["{ip}\n".format(ip=host['ip']) for host in srcdb]

    fh = open("static/src.txt", "w")
    fh.writelines(ip_addrs)
    fh.close()

    return app.send_static_file("src.txt")


@app.route('/dbl/dest')
def get_dbl_dst():
    destdb = tinydb.table('dest')
    tinydb.purge_table('dest')

    '''
    Retrieve detections
    '''
    # intel_args = {
    #     'url': brain,
    #     'token': token,
    #     'state': det_state,
    #     'triaged': det_triaged,
    #     'detection_type': '<detection>'
    # }

    # intel2_args = {
    #     'url': brain,
    #     'token': token,
    #     'state': det_state,
    #     'triaged': det_triaged,
    #     'detection_type': '<detection>'
    # }

    # retrieve_detections(intel_args, destdb)
    # retrieve_detections(intel2_args, destdb)

    ip_addrs = []
    for detection in destdb:
        ip_addrs += ["{ip}\n".format(ip=ip) for ip in detection['dst_ips']]

    fh = open("static/dest.txt", "w")
    fh.writelines(ip_addrs)
    fh.close()

    return app.send_static_file("dest.txt")


if __name__ == '__main__':
    app.run()
