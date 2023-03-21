from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
action: copy_certificate
short_description: Copies certificate and public key to remote locations
description:
    - Copy certificate and public key to remote dest based on notbefore certificate date to a location on the remote machine.
      Public key has to be placed near the copying certificate.
      Copies the resulting chain and private key files to the destination
      Compares the remote certificate start date to avoid overriting
      Accept options of copy module
      Requires python module 'pyopenssl' for parsing certificates
options:
  src:
    description:
      - Local path to a certificate to copy to the remote server; can be absolute or relative.
        If path is a directory, it is copied recursively. In this case, if path ends
        with "/", only inside contents of that directory are copied to destination.
        Otherwise, if it does not end with "/", the directory itself with all contents
        is copied. This behavior is similar to Rsync.
    required: yes
  dest:
    description:
      - 'Remote absolute path where the file should be copied to. If I(src) is a directory, this must be a directory too.
        If I(dest) is a nonexistent path and if either I(dest) ends with "/" or I(src) is a directory, I(dest) is created.
        If I(src) and I(dest) are files, the parent directory of I(dest) isn''t created: the task fails if it doesn''t already exist.'
    required: yes
  force:
    description:
      - the default is C(no), the file will only be transferred
        if the destination does not exist or expire date lower.
        If C(yes) - certificate will replace the remote file when contents
        are different than the source.
    type: bool
    default: 'no'
'''

EXAMPLES = r'''
- name: example copying certificate with key with owner and permissions
  copy_certificate:
    src: /srv/myfiles/foo.cer
    dest: /etc/
    owner: foo
    group: foo
    mode: 0644
    force: yes

- name: example untaring archive with certificates and key and copying with owner and permissions
  copy_certificate:
    src: /srv/myfiles/foo.tar
    dest: /etc/
    owner: foo
    group: foo
    mode: 0644
    force: yes
'''

import os
import shutil
from datetime import datetime
import tarfile
import tempfile
import base64
from cryptography import x509

from ansible import constants as C
from ansible.errors import AnsibleError, AnsibleActionFail
from ansible.module_utils._text import to_bytes, to_text
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.plugins.action import ActionBase


def _deal_with_tar(src_cert):
    """
    Extract content of certificate and private key
    :param src_cert: Path to tarball
    :return:
    """

    try:
        with tarfile.open(src_cert, 'r') as tar:
            files = tar.getmembers()

            for file in files:
                if file.name == 'privkey.pem':
                    key_content = tar.extractfile(file).read()
                elif file.name == 'fullchain.pem':
                    cert_content = tar.extractfile(file).read()

            if cert_content is None:
                raise AnsibleActionFail('Could not find fullchain.pem file in tar %s' % src_cert)
            elif key_content is None:
                raise AnsibleActionFail('Could not find privkey.pem file in tar %s' % src_cert)

            return cert_content, key_content
    except Exception as e:
        raise AnsibleActionFail('Could not read tarball %s: %s' % (src_cert, str(e)))


def _deal_with_plain(src_cert):
    """
    Find and return content of certificate and associated private key
    :param src_cert: Path to certificate
    :return:
    """

    src_key = src_cert.replace(os.path.splitext(src_cert)[1], '.key')

    if not os.path.exists(src_key):
        raise AnsibleActionFail("src key %s does not exist" % src_key)

    try:
        with open(to_bytes(src_key, errors='surrogate_or_struct'), 'rb') as f:
            key_content = f.read()

        with open(to_bytes(src_cert, errors='surrogate_or_struct'), 'rb') as f:
            cert_content = f.read()
    except (IOError, OSError) as e:
        raise AnsibleActionFail("could not read src=%s, %s" % (src_cert, to_text(e)))

    return cert_content, key_content


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        """ handler for file transfer operations """

        if task_vars is None:
            task_vars = dict()

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        src_cert = self._task.args.get('src', None)
        dest_cert = self._task.args.get('dest', None)
        force = boolean(self._task.args.get('force', False), strict=False)

        src_cert = self._connection._shell.join_path(src_cert)
        src_ext = os.path.splitext(src_cert)[1]

        try:
            if src_cert is None or dest_cert is None:
                raise AnsibleActionFail("src and dest are required")

            if not os.path.exists(src_cert):
                raise AnsibleActionFail("src %s does not exist" % src_cert)

            if src_ext == '.tar':
                cert_content, key_content = _deal_with_tar(src_cert)
            else:
                cert_content, key_content = _deal_with_plain(src_cert)

            try:
                src_x509 = x509.load_pem_x509_certificate(cert_content)
            except ValueError as e:
                src_x509 = x509.load_der_x509_certificate(cert_content)
            src_x509start_date = src_x509.not_valid_before

            dest_cert = self._connection._shell.join_path(dest_cert, 'cert.pem')
            dest_cert = self._remote_expand_user(dest_cert)
            dest_key = dest_cert + '.key'

            # use slurp if permissions are lacking or privileges escalation is needed
            dest_content = None
            slurpres = self._execute_module(module_name='slurp', module_args=dict(src=dest_cert), task_vars=task_vars)
            if slurpres.get('failed'):
                if slurpres.get('msg').startswith('file not found'):
                    force = True
                    dest_x509start_date = datetime(1970, 1, 1)
                else:
                    result.update(slurpres)
                    return result
            else:
                if slurpres['encoding'] == 'base64':
                    dest_content = base64.b64decode(slurpres['content'])

                dest_source = slurpres.get('source')
                if dest_source and dest_source != dest_cert:
                    dest_cert = dest_source

                dest_x509 = x509.load_pem_x509_certificate(dest_content)
                dest_x509start_date = dest_x509.not_valid_before

            # result['remote_issue_date'] = dest_x509start_date
            # result['local_issue_date'] = src_x509start_date
            # result['force'] = force

            if (src_x509start_date > dest_x509start_date) or force:
                local_tempdir = tempfile.mkdtemp(dir=C.DEFAULT_LOCAL_TMP)

                try:
                    result_cert = os.path.join(local_tempdir, os.path.basename('cert.pem'))
                    with open(to_bytes(result_cert, errors='surrogate_or_strict'), 'wb') as f:
                        f.write(to_bytes(cert_content, errors='surrogate_or_strict'))
                        # f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, src_x509))

                    result_key = os.path.join(local_tempdir, os.path.basename('privkey.pem'))
                    with open(to_bytes(result_key, errors='surrogate_or_strict'), 'wb') as f:
                        f.write(to_bytes(key_content, errors='surrogate_or_strict'))

                    new_cert_task = self._task.copy()
                    new_cert_task.args.update(
                        dict(
                            src=result_cert,
                            dest=dest_cert
                        ),
                    )
                    # copy cert
                    copy_cert_action = self._shared_loader_obj.action_loader.get('copy',
                                                                                 task=new_cert_task,
                                                                                 connection=self._connection,
                                                                                 play_context=self._play_context,
                                                                                 loader=self._loader,
                                                                                 templar=self._templar,
                                                                                 shared_loader_obj=self._shared_loader_obj)

                    result.update({'cert_result': copy_cert_action.run(task_vars=task_vars)})

                    # copy key
                    new_key_task = self._task.copy()
                    new_key_task.args.update(
                        dict(
                            src=result_key,
                            dest=dest_key,
                            force=True
                        ),
                    )
                    copy_key_action = self._shared_loader_obj.action_loader.get('copy',
                                                                                task=new_key_task,
                                                                                connection=self._connection,
                                                                                play_context=self._play_context,
                                                                                loader=self._loader,
                                                                                templar=self._templar,
                                                                                shared_loader_obj=self._shared_loader_obj)

                    result.update({'key_result': copy_key_action.run(task_vars=task_vars)})

                    result['changed'] = True
                finally:
                    shutil.rmtree(to_bytes(local_tempdir, errors='surrogate_or_strict'))
            else:
                result['changed'] = False

        except AnsibleError as e:
            result.update(e.result)

        return result
