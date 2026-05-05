import logging
import sys


_LOGGER_INITIALIZED = False


def setup_logging():
    global _LOGGER_INITIALIZED

    if _LOGGER_INITIALIZED:
        return

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    _LOGGER_INITIALIZED = True


def get_logger(name):
    setup_logging()
    return logging.getLogger(name)
