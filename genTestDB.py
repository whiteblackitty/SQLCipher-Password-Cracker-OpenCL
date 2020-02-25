import sys
import os
from pysqlcipher3 import dbapi2 as sqlite

PBKDF2_ITER = 4000 # sqlcipherv2 standard is 4000
PAGE_SIZE = 1024

if not (len(sys.argv)==2 and len(sys.argv[1])>0):
    password="0090456"
    print("Password is not explicitly specified via argument.")
    print("Using default password:\""+password+"\"")
else:
    password=sys.argv[1]
    print("Using password:\""+password+"\"")

Target_DB_PATH="EnCrypted_keyis_"+password+".db"
if os.path.exists(Target_DB_PATH):
    print("The db file has already exists, so no new file generated.")
    exit(0)

try:
    conn = sqlite.connect(":memory:")
    c = conn.cursor()
    c.execute("CREATE TABLE testTable(col1 INTEGER, col2 INTEGER)") # create a nonsense table just for test
    c.execute("SELECT name FROM sqlite_master WHERE type='table'")

    c.execute("ATTACH DATABASE '" + Target_DB_PATH + "' AS db KEY '" + password + "';")
    c.execute("PRAGMA db.cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;")
    c.execute("PRAGMA db.cipher_use_hmac = OFF;")
    c.execute("PRAGMA db.cipher_page_size = "+str(PAGE_SIZE)+";")
    c.execute("PRAGMA db.kdf_iter = "+str(PBKDF2_ITER)+";")
    c.execute("SELECT sqlcipher_export('db');")
    c.execute("DETACH DATABASE db;")
    print("Encrypted db creation is finished for "+Target_DB_PATH)
except Exception as e:
    print(str(e))
finally:
    conn.close()