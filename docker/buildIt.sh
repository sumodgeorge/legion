#!/bin/bash

testBranch=`git branch | grep "development" | grep "*"`

if [[ -z $testBranch ]]
then
    echo "Master Branch"
    docker build -f ./docker/Dockerfile -t legion . --no-cache
else
    echo "Development Branch"
    docker build -f ./docker/Dockerfile.dev -t legion -t development . --no-cache
fi
