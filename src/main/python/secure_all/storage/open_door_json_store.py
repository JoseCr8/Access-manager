"""Implements the OpenDoorJsonStore class"""
from secure_all.storage.json_store import JsonStore
from secure_all.cfg.access_manager_config import JSON_FILES_PATH


class OpenDoorJsonStore():
    """Extends JsonStore"""
    class __OpenDoorJsonStore(JsonStore):
        ID_FIELD = "_AccessKey__key"

        _FILE_PATH = JSON_FILES_PATH + "storeOpenDoor.json"
        _ID_FIELD = ID_FIELD

        def add_item(self, key):
            """Add the time and the key to the file"""
            item = {'_OpenDoor__key': key, '_OpenDoor__time': 1614962381.90867}
            return super().add_item(item)

    __instance = None

    def __new__(cls):
        if not OpenDoorJsonStore.__instance:
            OpenDoorJsonStore.__instance = OpenDoorJsonStore.__OpenDoorJsonStore()
        return OpenDoorJsonStore.__instance

    def __getattr__(self, nombre):
        return getattr(self.__instance, nombre)

    def __setattr__(self, nombre, valor):
        return setattr(self.__instance, nombre, valor)
