# Running on a docker container

It is very easy to run map646 on a docker container.
You just need to tweak the variables declared on the `docker-compose.yml` file.
Once you're done, simply run `docker-compose up -d`

The script will make sure to change the kernel routes to route both the IPv4 and
the mapping prefix to the tun interface.

# Known problems
## iptable's IP FORWARD rule
Make sure that you iptables rules permit the IP forwarding (i.e. `ACCEPT` and not `DROP`).
Indeed, upon startup the docker engine tweaks those rules and changes the default policy
of the `FORWARD` chain to `DROP`.

A workaround is to copy the `docker-override.conf` file to `etc/systemd/system/docker.service.d/iptablesforward.conf`
and restart the docker service.

## kernel's IP FORWARD policy
Make also sure that your kernel's `ip_forward` policy is set to `1`