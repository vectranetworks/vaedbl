#Vectra Active Enforcement Dynamic Blocklist
## Overview
VAE supplies a list of source or destination IPs via a webserver that can be consumed 
by firewalls and similar technology to enforce a policy when a threat has been detected 
in Cognito Detect.  
  
## Capabilities
* Supply source IP based on threat and certain scoring of the source host
* Supply a source IP based on an applied host tag
* Supply a source IP based on the host triggering *Ransomware File Activity* detection
* Supply the destination IP(s) found in specific Command & Control detections
* Supply the destination IPs of C&C detections for hosts that meet threat and certainty scoring thresholds  
  
## Getting Started

### System Requirements
The following software and python3 packages are required.
* python3
* python3-pip
* libxml2-dev
* libxslt-dev  
  ####Example: ```sudo apt install python3 python3-pip libxml2-dev libxslt-dev```
  
### Python modules
* flask
* lxml
* requests
* tinydb
* vectra\_api\_tools  
  ####Example: ```sudo -H pip3 install -r requirements.txt```  
  
### Setup
Setup can be performed manually by following the steps below, or by running the setup
script **configure.py**.  

Once configuration has been successfully run, start VAE:
    ```
    systemctl start vae
    ```  
  
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
by default.  The brain's URL, API token are required.  The API token once entered will be 
retained and won't need to be added every time a change is made even though it is not 
displays.  Additional parameters configure
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
    Queries for source hosts are configured under the ```/dbl/src``` endpoint.
    There are two options available for retrieving sources hosts: tags, scores.
    It is important to note that there should not be any spaces between tag values.  
    To configure scores, replace the threat and certainty placeholders ("certainty_gte": 0,
    "threat_gte": 0) with the minimum threshold you would like to retrieve.
    
    *Source host based on detection type:*  
    Queries for source hosts with a specific detection type under the ```/dbl/src_det``` endpoint.
    Configure the placeholder ("src_detection_types") with a list of exact detection type names.
   
    *Destination IPs from C&C detections form source hosts with minimum threat/certainty scoring:*  
    Queries hosts that have minimum T/C scoring thresholds for C&C detections under the ```/dbl/tc_dest``` endpoint.  
    Returns a list of those detections' destination IP addresses.  To configure, replace the placeholders 
    ("c2_certainty_gte": 0, "c2_threat_gte": 0) with minimum values.

    *Destination IPs from C&C detections:*   
    Queries for specified detections that are configured under the ```/dbl/dest``` endpoint. 
    Configured the placeholder ("src_detection_types") with a list of the exact detection type names to return.  
   
2. The default port for vaedbl is 8080. To change this port, edit the configuration 
(systemd.conf or supervisor.conf) and restart the service  

3. After any configuration changes to vaedbl, ensure you restart the service  
    ```
    systemctl restart vae
    ```  
   
### Blocklist URLs
Source IPs based on Host's T/C, tags: ```http://<host>:8080/dbl/src```  
Source IPs based on Host's Detection typ: ```http://<host>:8080/dbl/src_det```  
Destination IPs based on Detection type: ```http://<host>:8080/dbl/dest```  
Destination IPs of C2 detection for Hosts with Threat/Certainty threshold: ```http://<host>:8080/dbl/tc_dest```  

*Note: port 8080 by default*  

### Authors

**Chris Johnson** - Original work  
**Matt Pieklik** - Contributing author  
**Carson Ham** - Contributing author  
**Deirdre Murphy** - Contributing author  
