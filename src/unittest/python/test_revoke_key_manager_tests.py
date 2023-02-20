"""Test revoke_key_manager"""
import unittest
from secure_all import AccessManager, AccessManagementException, \
     JSON_FILES_PATH, RevokedKeysStorage


PROYECT_DIR = "/PyCharmProjects/G80.T12.FP/src/JsonFiles/"


class MyTestCase(unittest.TestCase):
    "Wrong file or file path"
    # pylint: disable=no-member
    # pylint: disable=too-many-public-methods
    @classmethod
    def setUpClass(cls):
        """ inicializo el entorno de prueba """
        revoke_key_store = RevokedKeysStorage()
        revoke_key_store.empty_store()

    def test_revoke_key_good(self):
        """Test que funciona"""
        myfile = JSON_FILES_PATH + "revoke_key_good.json"
        manager = AccessManager()
        emails = manager.key_removal(myfile)
        self.assertEqual(emails, [
      "mail1@uc3m.es",
      "mail2@uc3m.es"])


    def test_revocation_wrong(self):
        """Test"""
        myfile = JSON_FILES_PATH + "revocation_wrong.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "Wrong revocation type")

    def test_revocation_reason_wrong(self):
        """Test"""
        myfile = JSON_FILES_PATH + "revocation_reason_wrong.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "Wrong Reason value")

    def test_revoke_key_bad(self):
        """Test"""
        myfile = JSON_FILES_PATH + "revoke_key_bad.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_bad_fichero(self):
        """Test"""
        myfile = JSON_FILES_PATH + "no_existe_fichero.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_no_soy_json_txt(self):
        """Test"""
        myfile = JSON_FILES_PATH + "no_soy_json.txt"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_falta_llave(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_me_falta_llave.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_llave_duplicada(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_llave_duplicada.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_solo_llaves(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_solo_llaves.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_campo1_no_esta(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_campo1_no_esta.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_campo1_duplicado(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_campo1_duplicado.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_no_hay_separador(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_no_hay_separador.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_demasiados_separadores(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_varios_separadores.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_campo2_no_esta(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_campo2_no_esta.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_campo2_duplicado(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_campo2_duplicado.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_campo3_no_esta(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_campo3_no_esta.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_campo3_duplicado(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_campo3_duplicado.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_etiqueta1_no_esta(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_etiqueta1_no_esta.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_etiqueta1_duplicada(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_etiqueta1_duplicada.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_falta_igualdad(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_falta_igualdad.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_igualdad_duplicada(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_igualdad_duplicada.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_dato1_no_esta(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_dato1_no_esta.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_dato1_duplicado(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_dato1_duplicado.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_etiqueta2_no_esta(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_etiqueta2_no_esta.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_etiqueta2_duplicada(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_etiqueta2_duplicada.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_dato2_2_no_esta(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_dato2_no_esta.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_dato2_2_duplicado(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_dato2_2_duplicado.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_etiqueta3_no_esta(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_etiqueta3_no_esta.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_etiqueta3_duplicado(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_etiqueta3_duplicado.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_dato3_no_esta(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_dato3_no_esta.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_dato3_duplicado(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_dato3_duplicado.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_faltan_comillas(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_faltan_comillas.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_comillas_duplicadas(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_comillas_duplicadas.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_valor_etiqueta1_no_esta(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_valor_etiqueta1_no_esta.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_valor_etiqueta1_duplicado(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_valor_etiqueta1_duplicado.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_valor1_no_esta(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_valor1_no_esta.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_valor1_esta_duplicado(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_valor1_esta_duplicado.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_valor_etiqueta2_no_esta(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_valor_etiqueta2_no_esta.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_valor_etiqueta2_duplicado(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_valor_etiqueta2_duplicado.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

    def test_revoke_key_valor_etiqueta3_no_esta(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_valor_etiqueta3_no_esta.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")
    def test_revoke_key_valor_etiqueta3_esta_duplicada(self):
        """Test"""
        myfile = JSON_FILES_PATH + "json_valor_etiqueta3_esta_duplicada.json"
        manager = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            manager.key_removal(myfile)
            self.assertEqual(c_m.exception.message, "JSON Decode Error - Wrong label")

if __name__ == '__main__':
    unittest.main()
