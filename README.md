# provence

A simple and minimalistic monitoring solution for any and all systems


# Requirements

 - A mariadb / mysql database, no other db is supported yet


# Install

Simply use `go build .` to make the executable. The html templates and web resources will be embedded in the executable.

Rename the config and edit it
    
    cp config.example.yaml config.yaml
    vim config.yaml

To start it use 

    ./provence >> prov.log

The only 2 files required to start the application are the executable and the config.yaml.

Because of gin's Recovery usage and my added recovery call in gocron's functions the application should never crash.  
It is running since months on my debian server without any crashes.
