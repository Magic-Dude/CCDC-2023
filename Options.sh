#!/bin/bash

useradd $1
chpasswd <<<$1:$2
usermod -aG sudo $1