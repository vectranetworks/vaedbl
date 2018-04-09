import logging
import requests

from tinydb import TinyDB
from flask import Flask, render_template
from scripts.utils import retrieve_hosts, retrieve_detections

requests.packages.urllib3.disable_warnings()

app = Flask(__name__)
database = '.db.json'
tinydb = TinyDB(database)
logging.basicConfig(filename='/var/log/vae.log', format='%(asctime)s: %(message)s', level=logging.INFO)

brain = 'https://<hostname>'
token = '<token>'

@app.route('/')
def hello_world():
    return 'VAE is running'


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

    hosts = []
    for host in srcdb:
        hosts.append(host['ip'])

    return render_template('dbl.j2', list=set(hosts))


@app.route('/dbl/dest')
def get_dbl_dst():
    destdb = tinydb.table('dest')
    tinydb.purge_table('dest')

    '''
    Retieve detections
    '''
    # intel_args = {
    #     'url': brain,
    #     'token': token,
    #     'detection_type': '<detection>'
    # }

    # intel2_args = {
    #     'url': brain,
    #     'token': token,
    #     'detection_type': '<detection>'
    # }

    # retrieve_detections(intel_args, destdb)
    # retrieve_detections(intel2_args, destdb)

    ip_list = []
    for detection in destdb:
        ip_list += [ip for ip in detection['dst_ips']]

    return render_template('dbl.j2', list=set(ip_list))


if __name__ == '__main__':
    app.run()
