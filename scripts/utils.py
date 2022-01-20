#! /usr/bin/env python

import logging
import vat.vectra as vectra
from datetime import datetime, timedelta
import os
import smtplib
from email.message import EmailMessage
from tinydb import TinyDB
import json
import ipaddress

def init_db(db_file, table):
    '''
    Routine to initialize database file handling a corrupted db by deleting the file and re-initializing.

    :param db_file: database file
    :param table: table name
    :return: database table object
    '''

    db = TinyDB(db_file)
    dbt = db.table(table)
    try:
        db.drop_table(table)
    except json.decoder.JSONDecodeError:
        logging.info('{} database corrupted, deleting.'.format(db_file))
        os.remove(db_file)
        db = TinyDB(db_file)
        dbt = db.table(table)
        return dbt
    return dbt


def update_needed(db_name, minutes):
    #  Returns False when file has been updated less than minutes, otherwise False
    if os.path.exists(db_name):
        last_modified = datetime.fromtimestamp(os.path.getmtime(db_name))
        needs_update = last_modified < (datetime.now() - timedelta(minutes=minutes))
        logging.debug(f'Update_Needed:{needs_update}')
        return needs_update
    else:
        logging.debug(f'OS Path does not exist{db_name}')
        return True


def mailer(mail_args, block_list, subject):
    with open(block_list) as fp:
        msg = EmailMessage()

        msg['From'] = mail_args.get('sender')
        msg['Subject'] = f'Blocked {subject} IP addresses, {datetime.now().strftime("%Y-%m-%d, %H:%M:%S")}'
        msg['To'] = mail_args.get('recipient')
        msg.set_content(fp.read())
        s = smtplib.SMTP(mail_args.get('smtp_server'), mail_args.get('port', 25))

        if bool(mail_args.get('username', None) and mail_args.get('password', None)):
            s.login(mail_args.get('username', mail_args.get('password')))

        s.send_message(msg)
        s.quit()


def in_ip_wl(ip, whitelist):
    ip_addr = ipaddress.ip_address(ip)
    for subnet in whitelist:
        network = ipaddress.ip_network(subnet, False)
        if ip_addr in network or ip == subnet:
            return True
    return False


def in_group_wl(host, wl):
    for group in host['groups']:
        if group['name'] in wl:
            return True
    return False


def remove_wl_ips(detection, wl, vc, ips):
    gnames = []
    for group in detection['groups']:
        gnames.append(group['name'])

    intersect = list(set(wl) & set(gnames))
    if intersect:
        ips_not_in_wl = []
        #converts whitelist of groupnames to list of IPs 
        ip_wl = []
        for groupname in intersect:
            group_details = vc.get_groups_by_name(name=groupname)
            for g in group_details:
                for ip in g['members']:
                    ip_wl.append(str(ip))

        for ip in ips:
            if not in_ip_wl(ip, ip_wl):
                ips_not_in_wl.append(ip)
        ips = ips_not_in_wl
 
    return ips


def retrieve_hosts(args, db):
    vc = vectra.VectraClient(url=args['url'], token=args['token'])
    wl = args.get('src_wl', [])

    if args.get('tags', None):
        hosts = vc.get_hosts(tags=args['tags'], state=args['state'], page_size=1000).json()
        logging.debug(f'{hosts["count"]} hosts returned with tags: {args["tags"]}')

        for host in hosts['results']:
            logging.debug('host_id:{}, name:{}, ip:{}'.format(host['id'], host['name'], host['last_source']))
            if not in_group_wl(host, wl):
                db.insert({'id': host['id'], 'name': host['name'], 'ip': host['last_source']})
                logging.debug('host ' + host['name'] + ':' + host['last_source'] + ' added to block list')

    if args.get('certainty_gte', None) or args.get('threat_gte', None):
        hosts = vc.get_hosts(certainty_gte=args.get('certainty_gte', 50), threat_gte=args.get('threat_gte', 50),
                             page_size=1000).json()
        logging.debug('{count} hosts returned with score: certainty {certainty} threat {threat}'.format(
            count=hosts['count'], certainty=args.get('certainty_gte', 50), threat=args.get('threat_gte', 50)))
       
        for host in hosts['results']:
            logging.debug('host_id:{}, name:{}, ip:{}'.format(host['id'], host['name'], host['last_source']))
            if not in_group_wl(host, wl):
                db.insert({'id': host['id'], 'name': host['name'], 'ip': host['last_source']})
                logging.debug('host ' + host['name'] + ':' + host['last_source'] + ' added to block list')

    if args.get('src_detection_types', None):
        for src_det_type in args.get('src_detection_types'):
            response = vc.advanced_search(stype='hosts', page_size=5000,
                                          query=f"host.detection_summaries.detection_type:\"{src_det_type}\"")
       
            for page in response:
                for host in page.json()['results']:
                    logging.debug('host_id:{}, name:{}, ip:{}'.format(host['id'], host['name'], host['last_source']))
                    if not in_group_wl(host, wl):
                        db.insert({'id': host['id'], 'name': host['name'], 'ip': host['last_source']})
                        logging.debug('host ' + host['name'] + ':' + host['last_source'] + ' added to block list')


def retrieve_detections(args, db):
    vc = vectra.VectraClient(url=args['url'], token=args['token'])
    wl = args.get('dst_wl', [])

    if bool(args.get('state', None)) and bool(args.get('triaged', None)):
        detections = vc.get_detections(detection_type=args.get('detection_type', None), state=args['state'],
                                       is_triaged=args['triaged'], page_size=1000).json()

    elif args.get('triaged', None):
        detections = vc.get_detections(detection_type=args.get('detection_type', None),
                                       is_triaged=args['triaged'], page_size=1000).json()

    else:
        detections = vc.get_detections(detection_type=args.get('detection_type', None), page_size=1000).json()

    logging.debug('{count} detections were returned with detection {detection}'.format(
        count=detections['count'], detection=args.get('detection_type', None)))

    for detection in detections['results']:
        ips = []
        if detection['detection_type'] == 'Suspect Domain Activity':
            for detail in detection['grouped_details']:
                ips += detail['dns_response'].split(',') if detail['dns_response'] else []
            ips = list(set(ips))
        elif detection['detection_type'] == 'Suspicious HTTP':
            for detail in detection['grouped_details']:
                ips.extend(detail['dst_ips'])
        elif detection['detection_type'] == 'Suspicious Relay':
            ips = detection['summary']['origin_ips']
        else:
            ips = detection['summary']['dst_ips']

        if detection['groups'] and wl:
            ips = remove_wl_ips(detection, wl, vc, ips)

        logging.debug(f'det_id:{detection["id"]}, dst_ips:{ips}')
        db.insert({'id': detection['id'], 'dst_ips': ips})
        logging.debug(f'{str(ips)} added to block list')


def retrieve_c2hosts(args, db):
    vc = vectra.VectraClient(url=args['url'], token=args['token'])
    wl = args.get('dst_wl', [])

    if bool(args.get('state', None)) and bool(args.get('triaged', None)):
        detections = vc.get_detections(detection_category='command & control', state=args['state'],
                                      is_triaged=args['triaged'], page_size=1000).json()
    elif args.get('triaged', None):
        detections = vc.get_detections(detection_category='command & control', is_triaged=args['triaged'], page_size=1000).json()
    else:
        detections = vc.get_detections(detection_category='command & control', page_size=1000).json()

    for detection in detections['results']:
        ips = []
        if (detection['src_host']['threat'] >= args['c2_threat_score']
                and detection['src_host']['certainty'] >= args['c2_certainty_score']):
            
            if detection['detection_type'] == 'Suspect Domain Activity':
                for detail in detection['grouped_details']:
                    ips += detail['dns_response'].split(',') if detail['dns_response'] else []
                ips = list(set(ips))
            elif detection['detection_type'] == 'Suspicious HTTP':# or detection['detection_type'] == 'Hidden DNS Tunnel':
                for detail in detection['grouped_details']:
                    ips.extend(detail['dst_ips'])
            #elif detection['detection_type'] == 'Multi-home Fronted Tunnel':
            #    for detail in detection['grouped_details']:
            #        ips.extend(detail['cdn_ips'])
            elif detection['detection_type'] == 'Suspicious Relay':
                ips = detection['summary']['origin_ips']
            elif (detection['detection_type'] == 'Vectra Threat Intelligence Match' or
                    detection['detection_type'] == 'Hidden DNS Tunnel' or
                    detection['detection_type'] == 'Multi-home Fronted Tunnel'):
                pass
            else:
                ips = detection['summary']['dst_ips']

        if detection['groups'] and wl:
            ips = remove_wl_ips(detection, wl, vc, ips)
       
        db.insert({'id':detection['id'], 'dst_ips':ips})
