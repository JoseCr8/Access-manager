"""Module revoke_key_manager with RevokeKey class"""
from secure_all.data.attributes.attribute_revocation import Revocation
from secure_all.data.attributes.attribute_revocation_reason import RevocationReason
from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.data.attributes.attribute_key import Key
from secure_all.storage.revoked_keys_storage import RevokedKeysStorage
from secure_all.parser.revoke_json_parser import RevokeJsonParser


class RevokeKey:
    """Revoke key Class"""
    # pylint: disable=too-few-public-methods
    @staticmethod
    def revoke(filepath):
        """Function that returns the emails"""
        data = RevokeJsonParser(filepath).json_content
        Revocation(data['Revocation']).value
        RevocationReason(data['Reason']).value
        key = data['Key']
        keys_store = KeysJsonStore()
        key_object = keys_store.find_item(Key(key).value)
        RevokedKeysStorage().add_item(data)
        return key_object['_AccessKey__notification_emails']
