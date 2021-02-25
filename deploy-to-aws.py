import apscheduler.schedulers.blocking
import argparse
import boto3
import botocore.exceptions
import fabric
import logging
import os
import paramiko
import pathlib
import signal
import sys

log = logging.getLogger('qualys_deployment.deploy_to_aws')

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('instance_id', nargs='?')
    return parser.parse_args()

class Settings:
    @staticmethod
    def as_bool(value: str) -> bool:
        return value.lower() in ('true', 'yes', 'on', '1')

    @staticmethod
    def as_int(value: str, default: int) -> int:
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    @property
    def keyfile_location(self) -> pathlib.Path:
        return pathlib.Path(os.getenv('KEYFILE_LOCATION', '/keys')).resolve()

    @property
    def log_format(self) -> str:
        return os.getenv('LOG_FORMAT', '%(levelname)s [%(name)s] %(message)s')

    @property
    def log_level(self) -> str:
        return os.getenv('LOG_LEVEL', 'INFO')

    @property
    def other_log_levels(self) -> dict:
        result = {}
        for log_spec in os.getenv('OTHER_LOG_LEVELS', '').split():
            logger, _, level = log_spec.partition(':')
            result[logger] = level
        return result

    @property
    def qualys_activation_id(self) -> str:
        return os.getenv('QUALYS_ACTIVATION_ID')

    @property
    def qualys_customer_id(self) -> str:
        return os.getenv('QUALYS_CUSTOMER_ID')

    @property
    def qualys_deb(self) -> pathlib.Path:
        return pathlib.Path(os.getenv('QUALYS_DEB', '/packages/QualysCloudAgent.deb')).resolve()

    @property
    def qualys_rpm(self) -> pathlib.Path:
        return pathlib.Path(os.getenv('QUALYS_RPM', '/packages/QualysCloudAgent.rpm')).resolve()

    @property
    def run_and_exit(self) -> bool:
        return self.as_bool(os.getenv('RUN_AND_EXIT', 'false'))

    @property
    def run_interval(self) -> int:
        # number of minutes between runs
        # default run interval is 24 hours
        return self.as_int(os.getenv('RUN_INTERVAL'), 60 * 24)

    @property
    def version(self) -> str:
        return os.getenv('APP_VERSION', 'unknown')

def get_instance_tag(instance, tag_key):
    if instance.tags is None:
        return None
    for tag in instance.tags:
        if tag.get('Key') == tag_key:
            return tag.get('Value')

def get_keyfile(keyfile_name: str):
    if keyfile_name is None:
        return
    s = Settings()
    keyfile = s.keyfile_location / keyfile_name
    if keyfile.is_file():
        return keyfile

def get_ssh_user(instance, default: str = 'ec2-user') -> str:
    user_from_tag = get_instance_tag(instance, 'machine__ssh_user')
    if user_from_tag is None:
        return default
    return user_from_tag

def yield_instances(ec2):
    filters = [
        {
            'Name': 'instance-state-name',
            'Values': ['running']
        }
    ]
    yield from ec2.instances.filter(Filters=filters)


def upload_and_install_deb(cnx: fabric.Connection):
    s = Settings()
    cnx.put(s.qualys_deb, s.qualys_deb.name)
    cnx.sudo(f'dpkg --install {s.qualys_deb.name}')
    cnx.sudo(f'/usr/local/qualys/cloud-agent/bin/qualys-cloud-agent.sh ActivationId={s.qualys_activation_id} '
             f'CustomerId={s.qualys_customer_id}', hide=True)

def upload_and_install_rpm(cnx: fabric.Connection):
    s = Settings()
    cnx.put(s.qualys_rpm, s.qualys_rpm.name)
    cnx.sudo(f'rpm --install {s.qualys_rpm.name}', hide=True)
    cnx.sudo(f'/usr/local/qualys/cloud-agent/bin/qualys-cloud-agent.sh ActivationId={s.qualys_activation_id} '
             f'CustomerId={s.qualys_customer_id}', hide=True)

def process_instance(region, instance):
    if instance.platform == 'windows':
        return
    keyfile_name = get_instance_tag(instance, 'machine__ssh_keyfile')
    if keyfile_name is None:
        keyfile_name = instance.key_name
    keyfile = get_keyfile(keyfile_name)
    if keyfile is None:
        log.error(f'{region} / {instance.id} / Missing keyfile {keyfile_name}')
        return
    ssh_user = get_ssh_user(instance)
    cnx_args = {
        'key_filename': str(keyfile)
    }

    log.info(f'trying {region} / {instance.id} / {ssh_user}@{instance.public_ip_address} with {keyfile}')
    cnx = fabric.Connection(host=instance.public_ip_address, user=ssh_user, connect_kwargs=cnx_args)

    try:
        result = cnx.run('systemctl is-active qualys-cloud-agent', warn=True, hide=True)
    except paramiko.ssh_exception.SSHException as e:
        log.error(f'* ssh connection failed: {e}')
        log.error('* check that the username (machine__ssh_user tag) and keyfile are correct')
        return
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        log.error(f'* no valid connection: {e}')
        return

    status = result.stdout.strip()
    log.info(f'* qualys-cloud-agent is {status}')
    if status == 'active':
        return
    log.info('* checking for presence of `rpm`')
    result = cnx.run('which rpm', warn=True, hide=True)
    if result.ok:
        log.info('* uploading and installing agent')
        upload_and_install_rpm(cnx)
        return
    log.info('* checking for presence of `dpkg`')
    result = cnx.run('which dpkg', warn=True, hide=True)
    if result.ok:
        log.info('* uploading and installing agent')
        upload_and_install_deb(cnx)

def main_job():
    boto_session = boto3.session.Session()
    args = parse_args()
    if args.instance_id is None:
        for region in boto_session.get_available_regions('ec2'):
            log.info(f'checking {region}')
            ec2 = boto3.resource('ec2', region_name=region)
            try:
                for instance in yield_instances(ec2):
                    process_instance(region, instance)
            except botocore.exceptions.ClientError as e:
                log.critical(e)
                log.critical(f'skipping {region}')
    else:
        region, _, instance_id = args.instance_id.partition('/')
        ec2 = boto3.resource('ec2', region_name=region)
        process_instance(region, ec2.Instance(instance_id))

def main():
    s = Settings()
    logging.basicConfig(format=s.log_format, level=logging.DEBUG, stream=sys.stdout)
    log.debug(f'{log.name} {s.version}')
    if not s.log_level == 'DEBUG':
        log.debug(f'Setting log level to {s.log_level}')
    logging.getLogger().setLevel(s.log_level)

    for logger, level in s.other_log_levels.items():
        log.debug(f'Setting log level for {logger} to {level}')
        logging.getLogger(logger).setLevel(level)

    if s.run_and_exit:
        main_job()
        return

    scheduler = apscheduler.schedulers.blocking.BlockingScheduler()
    scheduler.add_job(main_job, 'interval', minutes=s.run_interval)
    scheduler.add_job(main_job)
    scheduler.start()

def handle_sigterm(_signal, _frame):
    sys.exit()

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, handle_sigterm)
    main()
