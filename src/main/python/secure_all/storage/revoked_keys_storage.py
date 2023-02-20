"""Implements the RequestsJSON Store"""
from secure_all.storage.json_store import JsonStore
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.cfg.access_manager_config import JSON_FILES_PATH


class RevokedKeysStorage():
    """Extends JsonStore """
    class __RevokedKeysStorage(JsonStore):
        #pylint: disable=invalid-name
        ID_FIELD = "Key"
        KEY_ALREADY_STORED = "key has already been revoked access"

        _FILE_PATH = JSON_FILES_PATH + "storeRevokedKeys.json"
        _ID_FIELD = ID_FIELD

        def add_item(self, item):
            """Implementing restrictions related to avoid duplicated keys and adding timestamp"""
            if not self.find_item(item['Key']) is None:
                raise AccessManagementException(self.KEY_ALREADY_STORED)
            item.update({'timestamp': 1614962381.90867})
            return super().add_item(item)

    __instance = None

    def __new__(cls):
        if not RevokedKeysStorage.__instance:
            RevokedKeysStorage.__instance = RevokedKeysStorage.__RevokedKeysStorage()
        return RevokedKeysStorage.__instance

    def __getattr__(self, nombre):
        return getattr(self.__instance, nombre)

    def __setattr__(self, nombre, valor):
        return setattr(self.__instance, nombre, valor)
