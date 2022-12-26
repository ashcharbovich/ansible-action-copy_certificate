# README

Copies certificate and public key to remote destination.

## Features

* Copy certificate and public key to remote dest based on notbefore certificate date to a location on the remote machine
* Compares the remote certificate start date to avoid overwriting
* Accept options of copy module

**Attention**
Public key has to be placed near the copying certificate.

## Requirements

* python >= 3.9
* pyopenssl >= 22.1.0

## Examples

```
- name: Copy certificate and private key with owner and permissions
  copy_certificate:
    src: /srv/myfiles/foo.cer
    dest: /etc/
    owner: foo
    group: foo
    mode: 0644
    force: yes
```

```
- name: Extract certificate and private key from archive and copy with owner and permissions
  copy_certificate:
    src: /srv/myfiles/foo.tar
    dest: /etc/
    owner: foo
    group: foo
    mode: 0644
    force: yes
```