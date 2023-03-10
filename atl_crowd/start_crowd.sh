#!/bin/bash

# docker volume create crowdVolume

docker run -v crowdVolume:/var/atlassian/application-data/crowd --name="crowd" -d -p 8095:8095 atlassian/crowd

