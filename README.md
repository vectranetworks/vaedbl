# Vectra Active Enforcement Dynamic Blocklist
## Overview
VAE supplies a list of source or destination IPs via a webserver that can be consumed 
by firewalls and similar technology to enforce a policy when a threat has been detected 
in Cognito Detect.

## Capabilities
* Supply source IP based on threat and certain scoring of the host
* Supply a source IP based on an applied host tag
* Supply a source IP based on the host triggering *Ransomware File Activity* detection
* Supply the destination IP(s) found in specific Command & Control detections

## Getting Started

### System Requirements
The following software and python3 packages are required.
* python3 (apt)
* python3-pip (apt)
* libxml2-dev (apt)
* libxslt-dev (apt)  
#### Example: *sudo apt install python3 python-pip libxml2-dev libxslt-dev*
* flask (pip)
* lxml (pip)
* requests (pip)
* tinydb (pip)
* vectra\_api\_tools (pip)  
#### Example: *sudo pip3 install -r requirements.txt*

### Setup
Setup can be performed manually by following the steps below, or by running the setup
script ```configure.py```.

#### Manual setup
1. Edit conf/systemd.service
    - set user to non-privileged user
    - set working directory to location of repo
    - set flask path for ExecStart (will be different for global vs local install)
2.  Edit conf/supervisor.conf
    - set environment=FLASK_APP= to full path to vaedbl.py
3. ```cp conf/systemd.service /etc/systemd/system/vae.service```
4. ```touch /var/log/vae.log```
5. ```chown <user>:<user> /var/log/vae.log```   
6. ```systemctl enable vae.service```
7. ```systemctl daemon-reload```

### Configuration
Once setup is complete a configuration page is available at ```http://<host>:8080/config```
by default.  The brain's URL, API token are required.  Additional parameters configure
which IPs are supplied in the source and destination blocklists.

**Alternate method**  
Manual configuration of the configuration is also possible:
1. Edit config.py
    - set brain url
    - set token
    - set mail parameters (if desired)
    - configure source host query (tags, scores)
    - configure destination host query (detections)

    *Source hosts:*   
    Queries for source hosts are configured under the dbl/src endpoint.
    There are two options available for retrieving sources hosts: tags, scores.
    Uncomment the *args* dictionary section of config.py and replace the
    <tags> placeholder with a comma separated list of tags. It is important to note
    that there should not be any spaces between values.  
    To configure scores, uncomment and replace the threat and certainty placeholders with the minimum 
    threshold you would like to retrieve.
    
    Tags and Scores are mutually exclusive, so if you would like to disable either option,
    delete or comment out the appropriate parameter(s)
    
    *Destination IPs from C&C detections:*   
    Queries for destination hosts are configured under the
    dbl/dest endpoint. Since only one detection type can be submitted per query,
    you will need to copy the given code block and replace the <detection type> placeholder
    for each detection in the *intel_args* list. When using multiple detections, a dictionary section per
    detection type is required.

2. The default port for vaedbl is 8080. To change this port, edit the configuration 
(systemd.conf or supervisor.conf) and restart the service

3. After any configuration changes to vaedbl, ensure you restart the service  
    ```
    systemctl restart vae.service
    ```
### Blocklist URLs
Source IPs: ```http://<host>:8080/dbl/src```  
Destination IPs: ```http://<host>:8080/dbl/dest```  
*Note: port 8080 by default*  

### Authors

**Chris Johnson** - Original work  
**Matt Pieklik** - Contributing author  
**Carson Ham** - Contributing author  
**Deirdre Murphy** - Contributing author  
