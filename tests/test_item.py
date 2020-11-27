# pylint: disable=missing-module-docstring, missing-class-docstring, missing-function-docstring, invalid-name
import unittest
from unittest import mock

from kdbx_1pif_importer import Item


class ItemTest(unittest.TestCase):

    def test_merge(self):
        a = Item()
        b = Item(title="cafebabe")
        a.merge(b)
        self.assertTrue(a.title == "cafebabe")

    def test_persist(self):
        kdbx = mock.MagicMock()
        a = Item()
        a.persist(kdbx)
        kdbx.add_entry.assert_called()
