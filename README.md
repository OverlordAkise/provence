# provence

A simple and minimalistic monitoring solution for any and all systems

It executes bash scripts on a cron-based interval, saves the output into a database and alerts based on the return code.

**WARNING: This is supposed to be an internal service!**  
It has neither user management nor any security checks in the bash scripts it executes.  
In short: With this you could easily get linux user access!  
Please be careful.


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


# Usage

First create a notifygroup.  
This is the configuration of whom to alert and how to alert them.  
Webhooks were tested with Discord and MS teams.


Then create a cronjob.  
They get grouped by their group on the homepage.  
The "failsneeded" field sets how many failed executions of a cronjob are needed for it to trigger as a failure.  
The "always notify" checkbox makes every execution, even successful ones, trigger a notification.


# NGINX config

This service doesn't need any special nginx configuration.  
Example config that works:

```nginx
location /monitor/ {
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_pass http://localhost:7070/;
}
```


# Example bash scripts


## Check disk usage on remote server via ssh

This will connect to a remote server and check if the disk usage of "sda" is over 95%. If yes then it will exit 1, else 0.

```bash
FSIZE=$(ssh user@127.0.0.2 df -h . | grep sda | awk '{print $5}' | grep -Eo "[0-9][0-9]")
exit $(( $( echo $FSIZE | tr '\r' ' ') > 95 ))
```


## SSL certificate expiry check

This will check if the http certificate expiry of e.g. example.com will be in less than 28days.

```bash
echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null | openssl x509 -noout -checkend 2419200
```


## Verify if host is reachable

This also outputs info about connect-time, time-till-first-byte and total time needed.

```bash
curl -s -w 'Establish Connection: %{time_connect}s\nTTFB: %{time_starttransfer}s\nTotal: %{time_total}s\n' -I https://example.com/
```
