#! /usr/bin/env python

import logging
import vat.vectra as vectra


def retrieve_hosts(args, db):
    vc = vectra.VectraClient(url=args['url'], token=args['token'])

    if args.get('tags', None):
        hosts = vc.get_hosts(tags=args['tags']).json()
        logging.info("{count} hosts returned with tags: {tags}".format(count=hosts['count'], tags=args['tags']))
    if args.get('certainty_gte', None) or args.get('threat_gte', None):
        hosts = vc.get_hosts(certainty_gte=args.get('certainty_gte', 50), threat_gte=args.get('threat_gte', 50)).json()
        logging.info("{count} hosts returned with score: certainty {certainty} threat {threat}".format(count=hosts['count'], 
            certainty=args.get('certainty_get', 50), threat=args.get('threat_get', 50)))

    for host in hosts['results']:
        db.insert({"id": host['id'], "name": host['name'], 'ip': host['last_source']})
        logging.info('host ' + host['name'] + ':' + host['last_source'] + ' added to block list')

    return


def retrieve_detections(args, db):
    logging.info("retrieve_detections called")
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

    logging.info("{count} detections were returned with detection {detection}".format(
        count=detections['count'], detection=args.get('detection_type', None)))

    for detection in detections['results']:
        if detection['detection_type'] == 'Suspect Domain Activity':
            ips = []
            for detail in detection['grouped_details']:
                ips += detail['dns_response'].split(',') if detail['dns_response'] else []
            ips = list(set(ips))
        else:
            ips = detection['summary']['dst_ips']

        db.insert({"id": detection['id'], 'dst_ips': ips})
        logging.info(str(ips) + ' added to block list')

    return
