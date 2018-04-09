
## Getting Started

### System Requirements
* python2 (apt)
* python-pip (apt)
* libxml2-dev (apt)
* libxslt-dev (apt)
* flask (pip)
* tinydb (pip)
* requests (pip)
* vectra\_api\_tools (pip)

### Setup
default credentials (please change on first use):
    username: vectra
    password: password

1. Edit vae\_flask
    - set brain url
    - set token
    - configure soure host query (tags, scores)
    - configure destination host query (detections
2. Edit conf/systemd.service
    - set user to non-privileged user
    - set working directory to location of repo
    - set flask path for ExecStart (will be different for global vs local install)
3. copy conf/systemd.service to /etc/systemd/system/vae.service
4. load vae.service
5. systemctl enable vae.service
6. systemctl daemon-reload

### Configuration
1. Source host: Queries for source hosts are configured under the dbl/src endpoint.
There are two options availabe for retrieving sources hosts: tags, scores
To configure tags, uncomment the 'Retrieve tagged hosts' section of vae_flask
and add replace the <tag> placehodlder with ta comma separated list of tags.
It is important to note that there sshould not be any spaces between values.
To configure scores, uncomment the section marked 'Retrieve scored hosts' and replace
the <threat> and <certainty> placeholders with the minimum threshold you would
like to retrieve.

2. Destination hosts: Queries for destination hosts are configured under the
dbl/dest endpoint. Since only one detection type can be submitted per query,
you will need to copy the given code block and replace the <detection> placeholder
for each detection. When using multiple detections, it is important to change the
variable name and add a new 'retrieve_detections' function call that references
the new variable.

