#!/usr/bin/env python3
#  pylint: disable=too-few-public-methods,missing-class-docstring,missing-function-docstring
"""
Quick and dirty OnePassword .1pif KeePass importer.

This will add the following document types (note the exclusion of Identity and
Credit Card):

    - passwords.Password,
    - securenotes.SecureNote,
    - wallet.computer.Router,
    - wallet.computer.UnixServer,
    - wallet.onlineservices.Email.v2, and
    - webforms.WebForm.

Multiple OTP codes for the same entry is not supported by KeePassXC at the time
of writing, so if you use that you'll need to manually edit any entries. One
possible solution would be to clone the entry.
"""

from getpass import getpass, GetPassWarning
from random import randint
from typing import Any, NamedTuple, List, Optional, Set, Mapping, Type
import argparse
import io
import json
import os
import sys
import logging
from unittest import mock

from pykeepass import PyKeePass  # type: ignore
import pykeepass.exceptions  # type: ignore

log = logging.getLogger(__name__)


class Item:  # pylint: disable=too-many-instance-attributes
    """
    Data handler for interacting with "rows" from 1Password and KeePass.
    """

    def __init__(
        self,
        title: str = "",
        username: str = "",
        password: str = "",
        uuid: str = "",
        tags: List[str] = [],
        urls: List[str] = [],
        otp: List[str] = [],
        notes: List[str] = [],
    ):  # pylint: disable=dangerous-default-value, too-many-arguments
        self.title: str = title
        self.username: str = username
        self.password: str = password
        self.uuid: str = uuid
        self.tags: List[str] = tags
        self.urls: List[str] = urls
        self.otp: List[str] = otp
        self.notes: List[str] = notes

    def merge(self, other: "Item"):
        """
        The assumption I'm making here is that we will be merging onto the
        Common data.
        """
        self.tags.extend(other.tags)
        self.urls.extend(other.urls)
        self.otp.extend(other.otp)
        self.notes.extend(other.notes)
        if other.title:
            self.title = other.title
        if other.username:
            self.username = other.username
        if other.password:
            self.password = other.password

    def persist(self, kdbx: Any):
        """
        One feature which didn't quite map nicely from 1Password to KeePass is
        Multi-Multi Factor Auth support. Looking at the code here:

            https://github.com/keepassxreboot/keepassxc/blob/develop/src/totp/totp.h

        I don't see any support for multiple OTP support.

        My use case is to use Amazon store and AWS. You use the same
        username/password to log into the Amazon Store and AWS, but you can
        have different MFA devices set up.

        So far, this is the only odd mapping. I decided not to map Credit Card
        and Identities, though given how things are set up adding it shouldn't
        be too much work.
        """

        try:
            entry = kdbx.add_entry(
                kdbx.root_group,
                self.title,
                self.username or "",
                self.password or "",
            )
        except Exception:  # pylint: disable=broad-except
            log.error("Ran into duplicate, trying to create a numbered duplicate.")
            self.title = f"{self.title} {randint(0, 99999)}"
            try:
                entry = kdbx.add_entry(
                    kdbx.root_group,
                    self.title,
                    self.username or "",
                    self.password or "",
                )
            except Exception:  # pylint: disable=broad-except
                log.critical("Cannot create %s", self.title)
                sys.exit(1)

        entry.tags = self.tags
        entry.notes = "\n".join(self.notes)
        entry.set_custom_property("1password_uuid", self.uuid)

        # See: https://github.com/keepassxreboot/keepassxc/pull/3558
        for index, url in enumerate(self.urls):
            if index == 0:
                entry.url = url
            elif index == 1:
                entry.set_custom_property("KP2A_URL", url)
            else:
                entry.set_custom_property(f"KP2A_URL_{index-1}", url)

        # No support for this, so we're just going to deal with this
        # afterwards.
        for (
            index,
            otp,
        ) in enumerate(self.otp):
            if index == 0:
                entry.set_custom_property("otp", otp)
            else:
                entry.set_custom_property(f"otp_{index}", otp)

        log.info("Imported %s", self.title)


class Base:
    @staticmethod
    def process(blob):
        raise NotImplementedError("Don't use the Base class.")


class Unknown(Base):
    @staticmethod
    def process(blob) -> Item:
        return Item(
            title="",
            uuid="",
            username="",
            password="",
            tags=[],
            urls=[],
            otp=[],
            notes=[],
        )


class Common(Base):
    """
    Adds data for some of the "non-specialized" attributes:

    - URLs,
    - OTP,
    - tags, and
    - notes.
    """

    @staticmethod
    def process(blob):
        title = blob.get("title", f"Unknown {randint(0, 99999)}")
        uuid = blob.get("uuid", "Unknown")

        urls = []
        for url in blob.get("secureContents", {}).get("URLs", []):
            if "url" not in url:
                continue
            urls.append(url["url"])

        notes = []
        notes.append(blob.get("secureContents", {}).get("notesPlain", ""))

        tags = blob.get("openContents", {}).get("tags", [])

        otp = []
        for section in blob.get("secureContents", {}).get("sections", []):
            notes.append(f"""{section.get("title", "Extra data")}""")
            notes.append("-----------------")
            for field in section.get("fields", []):
                if field.get("n", "").startswith("TOTP"):
                    otp.append(field.get("v"))
                    continue
                notes.append(f"""{field.get("t")}: {field.get("v")}""")

        return Item(
            title=title,
            uuid=uuid,
            urls=urls,
            notes=notes,
            tags=tags,
            otp=otp,
        )


class Password(Base):
    @staticmethod
    def process(blob):
        return Item(
            password=blob.get("secureContents", {}).get("password", ""),
        )


class UnixServer(Base):
    @staticmethod
    def process(blob):
        return Item(
            password=blob.get("secureContents", {}).get("password", ""),
            username=blob.get("secureContents", {}).get("username", ""),
        )


class WebForm(Base):
    @staticmethod
    def process(blob):
        username = ""
        password = ""
        for field in blob.get("secureContents", {}).get("fields", []):
            if field.get("designation") == "username":
                username = field.get("value")
            elif field.get("designation") == "password":
                password = field.get("value")
        return Item(
            password=password,
            username=username,
        )


class EmailV2(Base):
    @staticmethod
    def process(blob):
        urls = []
        urls.append(blob.get("secureContents", {}).get("smtp_server", ""))
        urls.append(blob.get("secureContents", {}).get("pop_server", ""))
        username = blob.get("secureContents", {}).get("smtp_username", "")
        password = blob.get("secureContents", {}).get("smtp_password", "")
        return Item(
            password=password,
            urls=urls,
            username=username,
        )


class Router(Base):
    @staticmethod
    def process(blob):
        title = blob.get("secureContents", {}).get("network_name", "")
        password = blob.get("secureContents", {}).get("wireless_password", "")
        return Item(
            title=title,
            password=password,
        )


VISITORS: Mapping[str, Type[Base]] = {
    "passwords.Password": Password,
    "wallet.computer.UnixServer": UnixServer,
    "webforms.WebForm": WebForm,
    "wallet.onlineservices.Email.v2": EmailV2,
    "wallet.computer.Router": Router,
    "securenotes.SecureNote": Common,
}


def add_to_keepass(duplicate_detector: Set[str], kdbx: Any, blob):
    """
    Logic glue.
    """
    title = blob.get("title")
    uuid = blob.get("uuid")
    _type = blob.get("typeName")

    # If we notice a duplicate then use a very naieve strategy: leave it up to
    # the user afterwards to resolve.
    if title not in duplicate_detector:
        duplicate_detector.add(title)
    else:
        title = f"""{title} - {randint(0, 99999)}"""

    # If AB adds a new type we don't support then we'll at least log a message.
    if blob.get("typeName") not in VISITORS:
        log.error("""Skipping unknown type: %s %s (%s)""", _type, title, uuid)
        return

    entry = Common.process(blob)
    entry.merge(VISITORS.get(blob["typeName"], Unknown).process(blob))
    entry.persist(kdbx)


def get_kdbx_handle(dry_run: bool, kdbx: str):
    """
    We take the easy way out with dry-run and return a mock instead of a real
    handle to the database.
    """
    if dry_run:
        return mock.MagicMock()

    try:
        password = getpass("Password for kdbx file: ")
        if not password:
            raise ValueError("no password entered.")
    except GetPassWarning as exc:
        log.critical("Could not read password for kdbx file: %s", exc)
        sys.exit(1)

    try:
        kdbx = PyKeePass(kdbx, password=password)
    except pykeepass.exceptions.CredentialsError:
        log.critical("Invalid credentials for kdbx file %s", kdbx)
        sys.exit(1)

    return kdbx


def main() -> None:
    """
    Main entrypoint.
    """
    logging.basicConfig(level=logging.INFO)
    args = argparse.ArgumentParser(
        description="tl;dr: 1pif -> kdbx",
        exit_on_error=True,
    )
    args.add_argument("opif", metavar="OPIF", help="path/to/data.1pif")
    args.add_argument("kdbx", metavar="KDBX", help="path/to/tax-returns.kdbx")
    args.add_argument(
        "-D", "--dry-run", action="store_true", default=False, help="No writing!"
    )
    argv = args.parse_args()

    if not os.path.isfile(argv.opif) or not os.path.isfile(argv.kdbx):
        log.critical("Make sure the 1pif and kdbx files exist.")
        sys.exit(1)

    kdbx = get_kdbx_handle(argv.dry_run, argv.kdbx)

    duplicate_detector: Set[str] = set()
    with io.open(argv.opif, "r", encoding="utf-8") as opif:
        while (line := opif.readline()) :
            try:
                add_to_keepass(duplicate_detector, kdbx, json.loads(line))
            except json.JSONDecodeError:
                continue

    log.info("Saving database %s", argv.kdbx)
    kdbx.save()
