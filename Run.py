# -*- coding: utf-8 -*-
import sys
import os
import time
from pysqlcipher3 import dbapi2 as sqlite
from Lib import opencl


TOTAL_PASS_LENGTH = 7 # max=16, otherwise will out of the range of uint64 used by opencl code. this value will affect the '0' padding if passphrase less than length
OUTER_PASS_LENGTH = 2 # control the outer cycle number, more cycle means more context change overhead and more exchange rate and less useless computation in last cycle
PASS_CHARS_Variety = 16 # 0-9,a-f

PBKDF2_ITER = 4000 # sqlcipherv2 standard is 4000
PAGE_SIZE = 1024 # value varies on application specification, we assume db is encrypted by each page, of 1024 byte


Encrypted_DB_PATH="EnCrypted_keyis_0205541.db"
PASS_RESULT_FILE="password.txt"

PYOPENCL_COMPILER_OUTPUT='1' # set to '1' to see the openCL compile errors

correct_pw=""


def tryDecryptSQLiteDB(passwordnumlist):

    for value in passwordnumlist:

        passphrase=""
        pwords=[1] * TOTAL_PASS_LENGTH

        for i in range(0,TOTAL_PASS_LENGTH,1):
            val=value%16
            if(val>=10):
                pwords[TOTAL_PASS_LENGTH-1-i]=val+87 # hex char, sqlcipher db uses lower case of abcdef, a means 10, 'a'=97, offset=97-10=87
            else:
                pwords[TOTAL_PASS_LENGTH-1-i]=val+48 # numbers, 0 means 0, '0'=48, offset=48-0=48
            value=value/16

        for pword in pwords:
            passphrase+=chr(pword)

        print("     After validating first 4 bytes of the decrypted data on GPU, possible password is "+passphrase)
        print("     Now try to use SQLite driver to formally decrypt the database using this password.")

        successMark=False
        try:
            conn = sqlite.connect(Encrypted_DB_PATH)
            c = conn.cursor()

            c.execute("PRAGMA key = '" + passphrase + "';")
            c.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;")
            c.execute("PRAGMA cipher_use_hmac = OFF;")
            c.execute("PRAGMA cipher_page_size = "+str(PAGE_SIZE)+";")
            c.execute("PRAGMA kdf_iter = "+str(PBKDF2_ITER)+";")
            c.execute("SELECT name FROM sqlite_master WHERE type='table'")

            c.execute("ATTACH DATABASE '" + Encrypted_DB_PATH+".decrypted.db" + "' AS db KEY '';")
            c.execute("SELECT sqlcipher_export('db');")
            c.execute("DETACH DATABASE db;")

            print("     Decrypt and dump database to {} ... ".format(Encrypted_DB_PATH+".decrypted.db"))
            print('     OK!')
            successMark=True
        except Exception as e:
            print("     Error: "+str(e))
            if str(e)=="file is not a database":
                print("     This password is wrong, just proceed on trying......")
            elif str(e).endswith("already exists"):
                successMark=True
                print("     The dumped database filename has already exist, so the error occur, but the password is correct.")
            else:
                print("     Unknown error for database decrypting.")
        finally:
            conn.close()
            if successMark==True: # finnaly get the correct answer
                global correct_pw
                correct_pw=passphrase
                return True

    return False


def main(argv):

    os.system("title PBKDF2-noHMAC-SHA1--AES-256-CBC encrypted SQLite database cracking")

    program_start=time.perf_counter()

    if (not (len(argv)==2)):
        print("PBKDF2-noHMAC-SHA1--AES-256-CBC encrypted SQLite database cracking v2018")
        info=opencl.opencl_information()
        info.printfullinfo()
        print("============================================================")
        info.printplatforms()
        print("============================================================")
        print("\nPlease run as: python opencl_test.py [platform number]")
        os.system("pause")
        exit(0)

    strx=r'''
        ____  _____  _    _ _______ ______      _____  ____  _  _______  ______ ___  
        |  _ \|  __ \| |  | |__   __|  ____|    |  __ \|  _ \| |/ /  __ \|  ____|__ \ 
        | |_) | |__) | |  | |  | |  | |__       | |__) | |_) | ' /| |  | | |__     ) |
        |  _ <|  _  /| |  | |  | |  |  __|      |  ___/|  _ <|  < | |  | |  __|   / / 
        | |_) | | \ \| |__| |  | |  | |____     | |    | |_) | . \| |__| | |     / /_ 
        |____/|_|  \_\\____/   |_|  |______|    |_|    |____/|_|\_\_____/|_|    |____|
                                                                               
            '''
    stry=r'''                                                                                    
                                                                                                                                                                                                                                                                                                                                                                       
                                                                                                    
                itLDEW#WKKEKEKEEEEDDEWKG                 tGWEGGGGGDDDGGGLLLDKWEGLfti                
           #############################KGLKKWKKKWWW#WKKKW####################W#WWWWWK,             
           W#####WKKWDfjtttttttttititLKW###GE######WK#W###KKtiiiiiiiiiiiiiitfDWKW##WWWi             
           W####LttttttttttttttttttttttiiW###DG#W##KK##WLttttttttttttttttttttittLK##WW              
          ,W###WjttttttttttttttttttttttttttE###EDD####EttttttttttttttttttttttttttG##WW              
           W###E                   ttttt, ,,W########K  ,itttt,,,,,,,,,,,,,,,,,,,G##WW              
           jW##D                   tttt,  ,,K########E  , tttt,,,,,,,,,,,,,,,,,,,jW#Wt              
            jW#E                  ttttt    ,K########E  ,,,tttt,,,,,,,,,,,,,,,,,,G#Wi               
             K#K                  tttt      W#W   i##W ,  ,tttt  ,,,,,,,,,,,,,,, L#W                
              #W                  tttt      W#t    K#K ,  , tttt,,,,,,,,,,,,,,,, E#K                
              W#t                tttt       ##,     #Ki     tttt,           ,,,,jK#                 
             ,W#j                ttj       L##      WWt      ttt                L#W                 
              G#G               ,ttt       K#,      L#j     ,tttt              iG#W                 
               WK                tt        W#        #E       ttt               K#W                 
               W#j               i        G##        WWt      , ,              fW#i                 
               K#D                        ##         i#Ki                     tE#W                  
                #Wfi                    tW#f          K#EL                   jD#WG                  
                K#KEj                 iW##W,           W#EEi              ,jLK##K,                  
                 KW#fGf           , j####j              WW#GEGjiiiiitttjLLLWE#W#                    
                  tW##KGDE###WWW##KW###K                  WW#WLfLGDGGGLLGE##WW                      
                    ,E#WWW#########WWi                      iWW##W#WW#W#WWWt                        
                            itjji                                                                   
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    '''

    print(strx)

    print("Encrypted Database: "+Encrypted_DB_PATH)
    print("Reading encrypted data...")

    with open(Encrypted_DB_PATH, 'rb') as infile:

        salt=infile.read(16) # salt for PBKDF2-SHA1 iteration
        encrypted_data=infile.read(16*1) # AES Block size, 16, the minimum size to be decrypt. We only need the first 4 byte to do initial validation, so read first 16 byte.
        # The more data sent for decryption, the more time will be wasted. The whole validation will be done through pycrypto if a pass phrase passed the initial validation.
        infile.read(PAGE_SIZE-16-16*1-16)
        iv = infile.read(16) # iv for AES-256-CBC decryption, the last 16 byte


    print("Init OpenCL...")
    print(" ")
    platform = int(argv[1])
    opencl_ctx = opencl.pbkdf2_aes_opencl(platform,salt,iv,encrypted_data)

    print(" ")
    print("Compiling OpenCL Code...")
    os.environ['PYOPENCL_COMPILER_OUTPUT'] = PYOPENCL_COMPILER_OUTPUT
    opencl_ctx.compile({"CONST_BYT_ACTUAL_PWLEN":str(TOTAL_PASS_LENGTH),"PBKDFITER":str(PBKDF2_ITER)})# redefine marcos in OpenCL code using new value

    print(" ")
    print("Starting OpenCL Kernel...")
    print(" ")

    Outercycle=PASS_CHARS_Variety**OUTER_PASS_LENGTH
    Innercycle=PASS_CHARS_Variety**(TOTAL_PASS_LENGTH-OUTER_PASS_LENGTH)

    for i in range(Outercycle):

        time_begin=time.perf_counter()

        result=opencl_ctx.run(Innercycle*i,Innercycle,False) # core function, it's suggested that the Innercycle should be integer number of workgroupsize
        
        if(tryDecryptSQLiteDB(result)==True): # validation
           break
        
        time_end=time.perf_counter()

        print("Cycle (each "+str(Innercycle)+" passphrase) "+str(i+1)+" of "+str(Outercycle)+", Time: "+str(round(time_end-time_begin,6))+" secs, TotalSpeed: "+str(round(Innercycle/1000/(time_end-time_begin),2))+" K Passphrase/s, "+
            "Estimated worst finish time: "+str(round((time_end-time_begin)*(Outercycle-i-1)/60,1))+" min,")
    
    os.system("title Brute Try Completed")
    print(" ")
    print("Brute Try completed after a total time of "+str(round((time.perf_counter()-program_start)/60,1))+" min.")

    if correct_pw=="":
        print("Sorry, no correct password is found.")
    else:
        print("The password is: "+correct_pw)
        with open(PASS_RESULT_FILE, 'a') as f:
            f.write("Password of "+Encrypted_DB_PATH+" is:\""+correct_pw+"\"")
            f.write('\n')
        print("Password is written to file: "+PASS_RESULT_FILE)

    print("Thank you for your usage.")
    exit(0)

if __name__ == '__main__':
    main(sys.argv)


