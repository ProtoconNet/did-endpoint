import logging
import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration

_level = {
    "debug" : logging.DEBUG,
    "info" : logging.INFO,
    "warning" : logging.WARNING,
    "error" : logging.ERROR,
    "critical" : logging.CRITICAL
}

def __get_logger(level):
    __logger = logging.getLogger('logger')
    formatter = logging.Formatter(
        '%(levelname)s#%(asctime)s#%(message)s >> @file::%(filename)s@line::%(lineno)s')
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    __logger.addHandler(stream_handler)
    __logger.setLevel(_level[level])
    logging.basicConfig(filename='debug.log',level=_level[level])
    return __logger


sentry_logging = LoggingIntegration(
    level=logging.WARNING,         # Capture ''
    event_level=logging.WARNING    # Send '' as events
)

def init(sentryURL):
    try:
        sentry_sdk.init(
            sentryURL,
            # Set traces_sample_rate to 1.0 to capture 100%
            # of transactions for performance monitoring.
            # We recommend adjusting this value in production.
            traces_sample_rate=1.0,
            integrations=[sentry_logging]
            # Bottle : https://docs.sentry.io/platforms/python/guides/bottle/performance/
            # dsn="https://examplePublicKey@o0.ingest.sentry.io/0",
            # traces_sample_rate=0.2,
            # traces_sampler=traces_sampler
        )
    except Exception:
        return "Error"
