# To minimize security risk create service account with read only permissions
brain = 'https://<Cognito Brain>'
token = '<Cognito API Token>'

# By default, only return active, untriaged detections.  To return both active and inactive detection, comment out the
# det_state variable in intel_args
active_state, det_triaged = 'active', 'false'

# Return a bogon IP to firewall to prevent error logs.  Set as '' to return an empty list.
bogon = '240.0.0.1'

#  Define mail settings to enable notification emails.
#  Leave username and password commented out if not SMTP auth is required.
#  Leave port commented for to use default port
mail = {
    #  'smtp_server': '',
    #  'port': '',
    #  'username': '',
    #  'password': '',
    #  'sender': '',
    #  'recipient': ''
}

#  Define parameters for source hosts to block
args = {
    # 'url': brain,
    #  'token': token,
    #  'tags': '<tags>',
    #  'state': active_state,
    #  'certainty_gte': 50,
    #  'threat_gte': 50
}

#  Define parameters for destinations in detections to block (C2 only)
intel_args = [
        # {
        #      'url': brain,
        #      'token': token,
        #      'state': active_state,
        #      'triaged': det_triaged,
        #      'detection_type': '<detection type>'
        # },

        # {
        #      'url': brain,
        #      'token': token,
        #      'state': active_state,
        #      'triaged': det_triaged,
        #      'detection_type': '<detection type>'
        # }
 ]
