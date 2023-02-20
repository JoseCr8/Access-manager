"""Class for validating the revocation reason"""
from secure_all.data.attributes.attribute import Attribute


class RevocationReason(Attribute):
    """Class for validating emails according to a regex"""
    #pylint: disable=too-few-public-methods
    def __init__(self, attr_value):
        self._validation_pattern = r'[a-zA-Z0-9_\s]{0,100}'
        self._error_message = "Wrong Reason value"
        self._attr_value = self._validate(attr_value)
