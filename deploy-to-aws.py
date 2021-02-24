import apscheduler.schedulers.blocking
import boto3
import botocore.exceptions
import logging
import os
import signal
import sys

log = logging.getLogger('qualys_deployment.deploy_to_aws')

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

def get_instances(ec2):
    filters = [
        {
            'Name': 'instance-state-name',
            'Values': ['running']
        }
    ]
    yield from ec2.instances.filter(Filters=filters)

def main_job():
    boto_session = boto3.session.Session()
    for region in boto_session.get_available_regions('ec2'):
        log.info(f'Checking {region}')
        ec2 = boto3.resource('ec2', region_name=region)
        try:
            for instance in get_instances(ec2):
                log.debug(f'Checking {instance.id} / {instance.platform} / {instance.key_name}')
        except botocore.exceptions.ClientError as e:
            log.critical(e)
            log.critical(f'Skipping {region}')

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
