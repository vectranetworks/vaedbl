#! /usr/bin/env python

import logging
import vat.vectra as vectra
from datetime import datetime, timedelta
import os
import smtplib
from email.message import EmailMessage


def update_needed(db_name, minutes):
    #  Returns False when file has been updated less than minutes, otherwise False
    if os.path.exists(db_name):
        last_modified = datetime.fromtimestamp(os.path.getmtime(db_name))
        logging.debug('Update_Needed:{}'.format(last_modified < (datetime.now() - timedelta(minutes=minutes))))
        return last_modified < (datetime.now() - timedelta(minutes=minutes))
    else:
        logging.debug('OS Path does not exist{}'.format(db_name))
        return True


def mailer(mail_args, block_list, subject):
    with open(block_list) as fp:
        msg = EmailMessage()

        msg["From"] = mail_args.get('sender')
        msg["Subject"] = 'Blocked {} IP addresses, {}'.format(subject, datetime.now().strftime("%Y-%m-%d, %H:%M:%S"))
        msg["To"] = mail_args.get('recipient')
        msg.set_content(fp.read())
        s = smtplib.SMTP(mail_args.get('smtp_server'), mail_args.get('port', 25))

        if bool(mail_args.get('username', None) and mail_args.get('password', None)):
            s.login(USERNAME, PASSWORD)

        s.send_message(msg)
        s.quit()


def retrieve_hosts(args, db):
    vc = vectra.VectraClient(url=args['url'], token=args['token'])

    if args.get('tags', None):
        hosts = vc.get_hosts(tags=args['tags'], state=args['state']).json()
        logging.debug("{count} hosts returned with tags: {tags}".format(count=hosts['count'], tags=args['tags']))

        if len(hosts['results']) > 0:
            for host in hosts['results']:
                logging.debug('host_id:{}, name:{}, ip:{}'.format(host['id'], host['name'], host['last_source']))
                db.insert({"id": host['id'], "name": host['name'], 'ip': host['last_source']})
                logging.debug('host ' + host['name'] + ':' + host['last_source'] + ' added to block list')

    if args.get('certainty_gte', None) or args.get('threat_gte', None):
        hosts = vc.get_hosts(certainty_gte=args.get('certainty_gte', 50), threat_gte=args.get('threat_gte', 50)).json()
        logging.debug("{count} hosts returned with score: certainty {certainty} threat {threat}".format(
            count=hosts['count'], certainty=args.get('certainty_get', 50), threat=args.get('threat_get', 50)))

        if len(hosts['results']) > 0:
            for host in hosts['results']:
                logging.debug('host_id:{}, name:{}, ip:{}'.format(host['id'], host['name'], host['last_source']))
                db.insert({"id": host['id'], "name": host['name'], 'ip': host['last_source']})
                logging.debug('host ' + host['name'] + ':' + host['last_source'] + ' added to block list')

    return


def retrieve_detections(args, db):
    vc = vectra.VectraClient(url=args['url'], token=args['token'])

    if bool(args.get('state', None)) and bool(args.get('triaged', None)):
        detections = vc.get_detections(detection_type=args.get('detection_type', None), state=args['state'],
                                       is_triaged=args['triaged'], tags=args.get('tags', None)).json()

    elif args.get('triaged', None):
        detections = vc.get_detections(detection_type=args.get('detection_type', None), is_triaged=args['triaged'],
                                       tags=args.get('tags', None)).json()

    else:
        detections = vc.get_detections(detection_type=args.get('detection_type', None),
                                       tags=args.get('tags', None)).json()

    logging.debug("{count} detections were returned with detection {detection}".format(
        count=detections['count'], detection=args.get('detection_type', None)))

    for detection in detections['results']:
        if detection['detection_type'] == 'Suspect Domain Activity':
            ips = []
            for detail in detection['grouped_details']:
                ips += detail['dns_response'].split(',') if detail['dns_response'] else []
            ips = list(set(ips))
        else:
            ips = detection['summary']['dst_ips']

        logging.debug('det_id:{}, dst_ips:{}'.format(detection['id'], ips))
        db.insert({"id": detection['id'], 'dst_ips': ips})
        logging.debug(str(ips) + ' added to block list')

    return
