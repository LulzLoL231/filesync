# -*- coding: utf-8 -*-
#
#  FileSync - Main file.
#  Created by LulzLoL231 at 25/02/2021
#
import os
import sys
import json
import time
import socket
import secrets
import hashlib
import logging
from typing import Optional, Union

from paramiko import SSHClient, ssh_exception
from scp import SCPClient, SCPException


if 'FILESYNC_DEBUG' in os.environ:
    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(levelname)s] %(name)s (%(lineno)d) >> %(message)s')
    logging.getLogger('paramiko.transport').setLevel(logging.INFO)
else:
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)s] %(name)s (%(lineno)d) >> %(message)s')


def secure_compare(hash1: str, hash2: str) -> bool:
    """
    Returns True if the two strings are equal, False otherwise.

    The time taken is independent of the number of characters that match.

    For the sake of simplicity, this function executes in constant time only
    when the two strings have the same length. It short-circuits when they
    have different lengths.

    Args:
        hash1 (str): hash #1.
        hash2 (str): hash #2.
    
    Returns:
        bool: True or False.
    """
    if len(hash1) != len(hash2):
        return False
    return hash1 == hash2


class FileSync:
    '''Main class.
    '''
    def __init__(self):
        self.NAME = self.__class__.__name__
        self.VERSION = '0.1'
        self.CONFIG_TEMPLATE = {
            'hostname': '',
            'port': 22,
            'username': '',
            'password': '',
            'local_files': [],
            'local_hashes': {},
            'remote_hashes': {}
        }
        self.REMOTE_PATH = f'.{self.NAME}'
        self.TEMP_PATH = os.environ.get('TEMP')
        self.log = logging.getLogger(self.NAME)
        self.config = self.initConfig()
        if self.checkConnection():
            self.log.info(f'{self.NAME} v{self.VERSION} Loaded!')

    def initConfig(self) -> dict:
        '''Returns config or init new and return it.

        Returns:
            dict: config data.
        '''
        if os.path.exists('config.json'):
            try:
                with open('config.json', 'r') as f:
                    data = f.read()
            except Exception as e:
                self.log.critical(f'"initConfig": Open config file error: {str(e)}')
                sys.exit(1)
            else:
                try:
                    data = json.loads(data)
                except Exception as e:
                    self.log.critical(f'"initConfig": JSON loads error: {str(e)}')
                    sys.exit(1)
                else:
                    return data
        else:
            self.log.warning('"initConfig": Config file not found. Creating...')
            config = self.CONFIG_TEMPLATE.copy()
            config['hostname'] = input('Enter hostname: ')
            while True:
                port = input('Enter port (default: 22): ')
                if port and port.isdigit():
                    config['port'] = int(port)
                    break
                elif (not port):
                    break
                print('Enter correct port!')
            config['username'] = input(f'Enter username (default: "{os.environ.get("USERNAME")}"): ')
            if (not config['username']):
                config['username'] = os.environ.get('USERNAME')
            config['password'] = input('Enter password (user/key): ')
            stop_count = 0
            while True:
                file = input('Enter path to files (type "stop" for stop adding files.): ')
                if file.lower() == 'stop':
                    if len(config['local_files']) < 0:
                        if stop_count > 1:
                            self.log.error('No files added for syncing.')
                            sys.exit(1)
                        print('You need add at least 1 file!')
                        stop_count += 1
                        continue
                    break
                if os.path.exists(file):
                    config['local_files'].append(file)
            for file in config['local_files']:
                config['local_hashes'].update({file: self.getMD5(file)})
            try:
                with open('config.json', 'w') as f:
                    f.write(json.dumps(config))
            except Exception as e:
                self.log.critical(f'"initConfig": Config save failed: {str(e)}')
                sys.exit(1)
            else:
                self.log.info('"initConfig": Config initiated.')
                return config

    def getMD5(self, filepath: str) -> str:
        '''Returns MD5 hash for file.

        Args:
            filepath (str): Path to file for hashing.

        Returns:
            str: MD5 hash.
        '''
        h = hashlib.md5()
        with open(filepath, 'rb') as f:
            h.update(f.read())
        return h.hexdigest()

    def getTempFileName(self) -> str:
        '''Returns random tempfile name.

        Returns:
            str: tempfile name.
        '''
        return f'sunc_temp_{str(secrets.randbits(6))}'
    
    def checkConnection(self) -> bool:
        '''Check connection to server.

        Returns:
            bool: True or False.
        '''
        cli = SSHClient()
        cli.load_system_host_keys()
        try:
            cli.connect(
                self.config['hostname'],
                self.config['port'],
                self.config['username'],
                self.config['password']
            )
            cli.close()
        except socket.gaierror as e:
            self.log.error(f'"checkConnection": Can\'t connect to remote host: {str(e)}')
            return False
        except TimeoutError as e:
            self.log.error(f'"checkConnection": TimeoutError: {str(e)}')
            return False
        except ssh_exception.PasswordRequiredException as e:
            self.log.error(f'"checkConnection": Password required error: {str(e)}')
            return False
        except ssh_exception.AuthenticationException as e:
            self.log.error(f'"checkConnection": Authentication error: {str(e)}')
            return False
        except ssh_exception.BadAuthenticationType:
            self.log.error(f'"checkConnection": Bad username or password.')
            return False
        except Exception:
            exc_type, exc_obj, _ = sys.exc_info()
            self.log.error(f'"checkConnection": Unexpected {exc_type.__name__}: {str(exc_obj)}')
            return False
        else:
            cli.close()
            self.log.debug('"checkConnection": Connection established.')
            return True

    def getSSHClient(self) -> Optional[Union[SSHClient, None]]:
        '''Returns SSHClient connected to remote host.

        Returns:
            Optional[Union[SSHClient, None]]: SSHClient or None.
        '''
        cli = SSHClient()
        cli.load_system_host_keys()
        try:
            cli.connect(
                self.config['hostname'],
                self.config['port'],
                self.config['username'],
                self.config['password']
            )
        except Exception as e:
            exc_type, exc_obj, _ = sys.exc_info()
            self.log.error(
                f'"getSSHClient": Can\'t connect to remote host: {exc_type.__name__}: {str(exc_obj)}')
            return None
        else:
            return cli

    def getSCPClient(self) -> Optional[Union[SCPClient, None]]:
        '''Returns SCPClient.

        Returns:
            Optional[Union[SCPClient, None]]: SCPClient or None.
        '''
        cli = self.getSSHClient()
        if cli:
            return SCPClient(cli.get_transport())
        else:
            self.log.error('"getSCPClient": Can\'t take SSHClient.')
            return None

    def initRemote(self) -> bool:
        '''Init remote folder for syncing.

        Returns:
            bool: True or False.
        '''
        cli = self.getSSHClient()
        if cli:
            std = cli.exec_command('mkdir .FileSync')
            cli.close()
            stderr = std[2].read().decode()
            if stderr == '':
                self.log.debug('"initRemote": Successfull created a .FileSync folder on remote host.')
                return True
            else:
                if 'File exists' in stderr:
                    self.log.info('"initRemote": .FileSync folder exists on remote host. No actions required.')
                    return True
                else:
                    self.log.error(f'"initRemote": Can\'t create .FileSync folder on remote host: {stderr}')
                    return False
        else:
            self.log.error('"initRemote": Can\'t take SSHClient.')
            return False

    def initLocal(self) -> bool:
        '''Initialize local folder for syncing.

        Returns:
            bool: True or False.
        '''
        path = os.path.join(
            os.environ.get('HOMEPATH'),
            'Documents',
            '.FileSync'
        )
        try:
            os.mkdir(path)
        except FileExistsError:
            self.log.info(f'"initLocal": Folder ({path}) already exists.')
            return True
        except Exception as e:
            self.log.error(f'"initLocal": Can\'t create folder ({path}): {str(e)}')
            return False
        else:
            self.log.info(f'"initLocal": Folder {path} is successfull created.')
            return True

    def upload(self, filepath: str) -> bool:
        '''Upload filepath to remote.

        Args:
            filepath (str): file path to upload.
        
        Returns:
            bool: True or False.
        '''
        scp = self.getSCPClient()
        if scp:
            remote_path = f'{self.REMOTE_PATH}/{filepath.split(os.path.sep)[::-1][0]}'
            try:
                scp.put(filepath, remote_path)
                scp.close()
            except SCPException as e:
                self.log.error(f'"upload": SCPException: {str(e)}')
                return False
            else:
                self.log.info(f'"upload": File ({str(filepath)}) is uploaded.')
                return True
        else:
            self.log.error('"upload": Can\'t take SCPClient.')
            return False

    def download(self, filepath: str) -> bool:
        '''Download file to LOCAL_PATH.

        Args:
            filepath (str): file path.

        Returns:
            bool: True or False.
        '''
        scp = self.getSCPClient()
        if scp:
            remote_filepath = f'{self.REMOTE_PATH}/{filepath.split(os.path.sep)[::-1][0]}'
            try:
                scp.get(remote_filepath, filepath)
                scp.close()
            except Exception as e:
                self.log.error(f'"download": Can\'t get file ({remote_filepath}): {str(e)}.')
                return False
            else:
                if os.path.exists(filepath):
                    self.log.info(
                        f'"download": File ({filepath}) is downloaded!')
                    return True
                else:
                    self.log.error(
                        f'"download": Can\'t found downloaded file: {filepath}.')
                    return False
        else:
            self.log.critical('"download": Can\'t take SCPClient.')
            return False

    def checkRemoteFile(self, filepath: str) -> bool:
        '''Check hash for remote file.

        Args:
            filepath (str): local file path for check.

        Returns:
            bool: True or False.
        '''
        ssh = self.getSSHClient()
        if ssh:
            remote_path = f'{self.REMOTE_PATH}/{filepath.split(os.path.sep)[::-1][0]}'
            _, stdout, stderr = ssh.exec_command(f'md5sum {remote_path}')
            ssh.close()
            stdout = stdout.read().decode()
            stderr = stderr.read().decode()
            if stderr:
                self.log.error(f'"checkRemoteFile": File check error: {str(stderr)}')
                return False
            if stdout:
                hash = stdout.split()[0]
                if self.config['remote_hashes'] and self.config["remote_hashes"][remote_path]:
                    self.log.debug(
                        f'"checkRemoteFile": File ({filepath}) MD5 hash: {self.getMD5(filepath)}')
                    self.log.debug(
                        f'"checkRemoteFile": File ({filepath}) Local MD5 hash: {self.config["remote_hashes"][remote_path]}')
                    if secure_compare(hash, self.config['remote_hashes'][remote_path]):
                        self.log.info(f'"checkRemoteFile": File ({filepath}) hash is verified.')
                        return True
                    else:
                        self.log.warning(f'"checkRemoteFile": File ({filepath}) hash verification is failed.')
                        return False
                else:
                    self.log.error(f'"checkRemoteFile": File ({filepath}) check failed: Hash not found in config file.')
                    return False
        else:
            self.log.error('"checkRemoteFile": Can\'t take SSHClient.')
            return False

    def checkLocalFile(self, filepath: str) -> bool:
        '''Check hash for local file.

        Args:
            filepath (str): file path for check.

        Returns:
            bool: True or False.
        '''
        if os.path.exists(filepath):
            if self.config['local_hashes']:
                if filepath in self.config['local_hashes']:
                    self.log.debug(f'"checkLocalFile": File ({filepath}) MD5 hash: {self.getMD5(filepath)}')
                    self.log.debug(f'"checkLocalFile": File ({filepath}) Local MD5 hash: {self.config["local_hashes"][filepath]}')
                    if secure_compare(self.getMD5(filepath), self.config['local_hashes'][filepath]):
                        self.log.info(f'"checkLocalFile": File ({filepath}) hash is verified.')
                        return True
                    else:
                        self.log.warning(f'"checkLocalFile": File ({filepath}) hash verification is failed.')
                        return False
            self.log.error(f'"checkLocalFile": File ({filepath}) check failed: Hash not found in config file.')
            return False
        else:
            self.log.error(f'"checkLocalFile": File ({filepath}) not found.')
            return False

    def updateConfig(self, key: str, value: Optional[Union[str, dict]]) -> bool:
        '''Update key:value pair in config file.

        Args:
            key (str): key for change.
            value (Optional[Union[str, dict]]): value for change.

        Returns:
            bool: True or False.
        '''
        if os.path.exists('config.json'):
            try:
                with open('config.json', 'r') as f:
                    config = f.read()
            except Exception as e:
                self.log.critical(f'"updateConfig": Can\'t read config file: {str(e)}')
                sys.exit(1)
            else:
                try:
                    config = json.loads(config)
                except Exception as e:
                    self.log.critical(f'"updateConfig": JSON error: {str(e)}')
                    sys.exit(1)
                else:
                    if key in config:
                        if config[key] and type(value) is dict:
                            config[key] = config[key].update(value)
                        else:
                            config[key] = value
                    else:
                        config[key] = value
                    try:
                        with open('config.json', 'w') as f:
                            f.write(json.dumps(config))
                    except Exception as e:
                        self.log.critical(f'"updateConfig": Can\'t write config file: {str(e)}')
                        sys.exit(1)
                    else:
                        self.log.info('"updateConfig": Update complete.')
                        return True
        else:
            self.log.critical('"updateConfig": Can\'t found config file.')
            sys.exit(1)
                        
    def updateRemoteHash(self, filepath: str) -> bool:
        '''Update hash info for remote file.

        Args:
            filepath (str): local file path for hashing.

        Returns:
            bool: True or False.
        '''
        ssh = self.getSSHClient()
        if ssh:
            remote_path = f'{self.REMOTE_PATH}/{filepath.split(os.path.sep)[::-1][0]}'
            _, stdout, stderr = ssh.exec_command(f'md5sum {remote_path}')
            ssh.close()
            stdout = stdout.read().decode()
            stderr = stderr.read().decode()
            if stderr:
                self.log.error(
                    f'"updateRemoteHash": File check error: {str(stderr)}')
                return False
            if stdout:
                hash = stdout.split()[0]
                self.updateConfig('remote_hashes', {remote_path: hash})
                return True
        else:
            self.log.error('"updateRemoteHash": Can\'t take SSHClient.')
            return False

    def updateLocalHash(self, filepath: str) -> bool:
        '''Updates hash info for local file.

        Args:
            filepath (str): file path for hashing.

        Returns:
            bool: True or False.
        '''
        if os.path.exists(filepath):
            hash = self.getMD5(filepath)
            self.updateConfig('local_hashes', {filepath: hash})
            return True
        else:
            self.log.error(f'"updateLocalHash": File ({filepath}) not found.')
            return False

    def sync(self) -> None:
        '''Syncing files.
        '''
        self.log.info('"sunc": Starting syncing files...')
        while True:
            self.log.info('"sync": Start checking files...')
            for file in self.config['local_files']:
                if os.path.exists(file):
                    if (not self.checkLocalFile(file)):
                        if self.config['local_hashes'] and file in self.config['local_hashes']:
                            self.log.info(f'"sync": Local copy of file ({file}) is changed. Upload to server...')
                            self.upload(file)
                            self.updateLocalHash(file)
                            self.updateRemoteHash(file)
                            self.log.info(f'"sync": Remote copy of file ({file}) is updated.')
                        else:
                            self.log.warning(f'"sync": Local hash for file ({file}) not found in config. Creating and check with remote copy.')
                            self.updateLocalHash(file)
                            if (not self.checkLocalFile(file)):
                                self.log.info(
                                    f'"sync": Local copy of file ({file}) is changed. Upload to server...')
                                self.upload(file)
                                self.updateLocalHash(file)
                                self.updateRemoteHash(file)
                                self.log.info(f'"sync": Remote copy of file ({file}) is updated.')
                    elif (not self.checkRemoteFile(file)):
                        if self.config['remote_hashes'] and file in self.config['remote_hashes']:
                            self.log.info(f'"sync": Remote copy of file ({file}) is changed. Download...')
                            self.download(file)
                            self.updateRemoteHash(file)
                            self.updateLocalHash(file)
                            self.log.info(f'"sync": Local copy of file ({file}) is updated.')
                        else:
                            self.log.warning(
                                f'"sync": Remote hash for file ({file}) not found in config. Creating and check with local copy.')
                            self.updateRemoteHash(file)
                            if (not self.checkLocalFile(file)):
                                self.log.info(
                                    f'"sync": Remote copy of file ({file}) is changed. Download...')
                                self.download(file)
                                self.updateRemoteHash(file)
                                self.updateLocalHash(file)
                                self.log.info(
                                    f'"sync": Local copy of file ({file}) is updated.')
                    else:
                        self.log.info(f'"sync" File ({file}) is already up-to-date.')
                        continue
                else:
                    self.log.info(f'"sync": Local copy of file ({file}) not found. Try to download...')
                    if self.download(file):
                        self.updateLocalHash(file)
                        self.updateRemoteHash(file)
                        self.log.info(f'"sync": File copied. No actions required.')
                        continue
                    else:
                        self.log.error(f'"sync": File ({file}) not found in remote and local. Skipping.')
            self.log.info('"sync": All files checked. Sleeping...')
            time.sleep(10)


if __name__ == '__main__':
    fs = FileSync()
    if fs.initLocal():
        if fs.initRemote():
            fs.sync()
    sys.exit(1)
