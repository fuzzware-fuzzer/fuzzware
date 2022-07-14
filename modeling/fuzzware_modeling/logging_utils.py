import logging

LOGGER_NAMES = (
    "ANA",
    "utils",
    "BASESTATE",
    "EXPLORE",
    "MMIO",
    "LIVENESS",
    "QUIRKS",
    "UTIL",
    "persist_results",
)

def set_log_levels(level):
    for name in LOGGER_NAMES:
        logger = logging.getLogger(name)
        logger.setLevel(level)
