from __future__ import annotations

import datetime

PRODUCT_NAME = "CE Runtime Foundation"
LAUNCHER_PRODUCT_NAME = PRODUCT_NAME + " Launcher"
AUTHOR = "Yaroslav Kibysh"
AUTHOR_URL = "https://yaroslavkibysh.com"
FIRST_YEAR = 2019


def copyright_years() -> str:
    year = datetime.date.today().year
    if year <= FIRST_YEAR:
        return str(FIRST_YEAR)
    return "{}-{}".format(FIRST_YEAR, year)


def copyright_line() -> str:
    return "Copyright (c) {} {}".format(copyright_years(), AUTHOR)
