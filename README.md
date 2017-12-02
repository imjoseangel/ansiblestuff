# Ansible Scripts and Documentation Repository

## Commands Learned

Run the ansible command that lists all of the hosts configured in your control server 'hosts' file for the system.
`ansible all -m setup -a 'filter=ansible_*_ipv4*'`


Using the 'setup' module for ansible, list all of the known facts on the local | all systems.
`ansible local | all -m setup`

While listing the facts on the local system, filter the list showing only the content pertaining to the system IP addresses.

`ansible local -m setup -a 'filter=ans*ipv4*'`

async: 300 -> Number of seconds
poll: 3 -> Number of simultaneous hosts