import logging
import os
from logging.handlers import RotatingFileHandler

_configured = False


def get_logger(base_dir):
    global _configured
    logger = logging.getLogger("novadns")
    if _configured:
        return logger
    logger.setLevel(logging.INFO)
    log_dir = os.path.join(base_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    handler = RotatingFileHandler(os.path.join(log_dir, "novadns.log"), maxBytes=5_000_000, backupCount=3)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(threadName)s] %(message)s"))
    logger.addHandler(handler)
    stream = logging.StreamHandler()
    stream.setFormatter(handler.formatter)
    logger.addHandler(stream)
    _configured = True
    return logger
