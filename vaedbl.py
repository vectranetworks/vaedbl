import logging
import requests
import os

try:
    from tinydb import TinyDB
    from flask import Flask, render_template
    from scripts.utils import retrieve_hosts, retrieve_detections, update_needed
    from config import bogon, args, det_state, det_triaged
except Exception as error:
    print("\nMissing import requirements: %s\n" % str(error))

requests.packages.urllib3.disable_warnings()

app = Flask(__name__)
app.config['send_file_max_age_default'] = 60
src_database = '.src_db.json'
tinydb_src = TinyDB(src_database)
dest_database = '.dest_db.json'
tinydb_dest = TinyDB(dest_database)
logging.basicConfig(filename='/var/log/vae.log', format='%(asctime)s: %(message)s', level=logging.DEBUG)


@app.route('/')
def hello_world():
    return "VAE is running"


@app.route('/dbl/src')
def get_dbl_source():
    if update_needed(os.path.abspath(src_database), 5):
        #  If DB last updated longer than 5 minutes

        srcdb = tinydb_src.table('src')
        tinydb_src.purge_table('src')

        '''
        Retrieve src hosts
        '''

        if args:
            retrieve_hosts(args, srcdb)

            ip_addrs = []
            ip_addrs += ["{ip}\n".format(ip=host['ip']) for host in srcdb]
            ip_addrs = set(ip_addrs)

            fh = open("static/src.txt", "w")

            if ip_addrs:
                fh.writelines(ip_addrs)
            elif bogon:
                fh.writelines(bogon)
            fh.close()
        elif bogon:
            fh = open("static/src.txt", "w")
            fh.writelines(bogon)
            fh.close()

    return app.send_static_file("src.txt")


@app.route('/dbl/dest')
def get_dbl_dst():

    if not update_needed(os.path.abspath(dest_database), 5):
        #  If DB last updated longer than 5 minutes
        destdb = tinydb_dest.table('dest')
        tinydb_dest.purge_table('dest')

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
        ip_addrs = set(ip_addrs)

        fh = open("static/dest.txt", "w")
        fh.writelines(ip_addrs)
        fh.close()

    return app.send_static_file("dest.txt")


if __name__ == '__main__':
    app.run()
