"""Class for validating the Revocation type"""
from secure_all.data.attributes.attribute import Attribute


class Revocation(Attribute):
    """Class for validating emails according to a regex"""
    #pylint: disable=too-few-public-methods
    def __init__(self, attr_value):
        self._validation_pattern = r'(Temporal|Final)'
        self._error_message = "Wrong revocation type"
        self._attr_value = self._validate(attr_value)
