### Config File
#### Create Config File Template
~~~
ansible-config init --disabled > ansible.cfg
~~~
#### Ensure this assignment
/etc/ansible.cfg
~~~
host_key_checking=False
~~~