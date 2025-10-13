import os
import sys
import logging

_DEVNULL = open(os.devnull, "w")
_ORIG_STDOUT = sys.stdout


def invalidate_print():
    """Suppress stdout output"""
    global _DEVNULL
    sys.stdout = _DEVNULL


def printf(text):
    """Print to stdout bypassing suppression"""
    global _ORIG_STDOUT, _DEVNULL
    sys.stdout = _ORIG_STDOUT
    print(text)
    sys.stdout = _DEVNULL


def setup_logging(log_file='attack.log'):
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)
