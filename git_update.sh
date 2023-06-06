#!/bin/bash
if [ -z $1 ];then
    echo "Please input your commit content !"
    exit
fi

if [ -d "./basic_glog_design/build" ];then
    rm -rf ./basic_glog_design/build
fi
git add .
git commit -m "$1"
git push origin main
