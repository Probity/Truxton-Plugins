'''
This script grabs password hashes and uses hashcat to crack them
Created By: Brett Lipkin for Probity Inc.
8/16/2021
'''

# imports
import sys
from msoffcrypto.format import base
sys.path.append('C:/Program Files/Truxton/SDK')
import truxton
import shutil
import subprocess
import os
import msoffcrypto # pip install msoffcrypto-tool
from pathlib import Path

# Directories
basedir = os.getcwd()
truxCrackDir = '.\Truxcrack-dependencies'
hashcatDir = '.\hashcat-6.2.5'
hashcatPath = '.\hashcat-6.2.5\hashcat.exe'
hashcatDict = ".\hashcat-6.2.5\example.dict" # Change to different dictionary if needed
sdkPath = 'C:\\Program Files\\Truxton\\SDK\\'

class PDFcracker:
    def pdfhashgrabber(file):
        pdf2hashcat = basedir + truxCrackDir + "\\Tools\\pdf2hashcat_v2.py"

        filename = file.hash
        inputfilename = basedir + truxCrackDir + "\\PDFFileOutput\\" + str(filename)
        f = open(inputfilename, 'wb')
        shutil.copyfileobj(file, f)
        f.close()
        print(inputfilename)
        proc = subprocess.run(["python", pdf2hashcat, inputfilename], stdout=subprocess.PIPE)
        output = proc.stdout
        print(type(output))
        # Turn output into string
        output = output.decode("utf-8")
        output = output.replace("\r\n","")
        return output
    
    def pdfCracker(file, pdfHash, hashresult):
        encryptedFile = basedir + truxCrackDir + "\\PDFFileOutput\\" + file.hash
        proc = subprocess.run([basedir + truxCrackDir + hashcatPath, "-a", "0", "-m", hashresult, pdfHash, basedir + truxCrackDir + hashcatDict], stdout=subprocess.PIPE)
        output = proc.stdout

        # Turn output into string
        output = output.decode("utf-8")

        crackedCheck = cracked_password(output)

        if crackedCheck == 1:
            proc = subprocess.run([basedir + truxCrackDir + hashcatPath, "-a", "0", "-m", hashresult, "--show", pdfHash, basedir + truxCrackDir + hashcatDict], stdout=subprocess.PIPE)
            output = proc.stdout
            # Turn output into string
            output = output.decode("utf-8")
            output = output.replace("\r\n","")
            output = output.split(":")
            print(output[1])
            add_file(file, output[1])
        elif crackedCheck == 2:
            print(output[1])
            add_file(file, output[1])
        elif crackedCheck == 3:
            print("password cracking exhausted for " + file)
        elif crackedCheck == 4:
            print("Unknown stage in hashcat")

    def create_pdf_dir():
        # Change directory to TruxCrack
        os.chdir(basedir + truxCrackDir)
        # Create file output directory
        try:
            fileDir = ".\\PDFFileOutput"
            checkExist = os.path.isdir(fileDir)
            if not checkExist:
                os.mkdir(fileDir)
                print("PDFFileOutput created successfully!")
        except OSError:
            print("Creation of PDFFileOutput failed... Exiting...")
            sys.exit(0)
        # Change the directory back
        print(os.getcwd())
        os.chdir(hashcatDir)
    
    def pdf_encryption_detector(hash):
        print(type(hash))
        print(hash)
        if "$pdf$1*2*40*" in hash:
            if str(hash).count == 199:
                return "10420"
            else:
                return "10400"
        elif "$pdf$2*3*128*" in hash or "$pdf$4*4*128*" in hash:
            return "10500"
        elif "$pdf$5*5*256*" in hash:
            return "10600"
        elif "$pdf$5*6*256*" in hash:
            return "10700"
    
class OfficeCracker:
    def create_office_dir():
        # Change directory to TruxCrack
        os.chdir(basedir + truxCrackDir)
        # Create file output directory
        try:
            fileDir = ".\\OfficeFileOutput"
            checkExist = os.path.isdir(fileDir)
            if not checkExist:
                os.mkdir(fileDir)
                print("OfficeFileOutput created successfully!")
        except OSError:
            print("Creation of OfficeFileOutput failed... Exiting...")
            sys.exit(0)
        # Change the directory back
        print(os.getcwd())
        os.chdir(hashcatDir)

    def decrypt_office_file(encryptedOfficeFile, officePassword, officeFile):
        # Variable Declaration
        officeDecryptedFile = basedir + truxCrackDir + "\\OfficeFileOutput\\" + "decrypted-" + officeFile.hash

        # 
        encrypted = open(encryptedOfficeFile, "rb")
        file = msoffcrypto.OfficeFile(encrypted)
        
        file.load_key(password=officePassword)

        with open(officeDecryptedFile, "wb") as f:
            file.decrypt(f)
        
        encrypted.close()
        return officeDecryptedFile


    def Office_Hash_Grabber(officeHash):
        # Variable Declaration
        office2hashcat = basedir + "\\Truxcrack\\Tools\\office2hashcat_v2.py"

        filename = officeHash.hash
        inputfilename = basedir + '.\Truxcrack\\OfficeFileOutput\\'+ str(filename)
        f = open(inputfilename, 'wb')
        shutil.copyfileobj(officeHash, f)
        f.close()
        print(inputfilename)
        proc = subprocess.run(["python", office2hashcat, inputfilename], stdout=subprocess.PIPE)
        output = proc.stdout
        # Turn output into string
        output = output.decode("utf-8")
        output = output.replace("\r\n","")
        return output


    def Office_Crack(officeFile):
        encryptedFile = basedir + truxCrackDir + "\\OfficeFileOutput\\" + officeFile.hash
        #Create office output directory
        OfficeCracker.create_office_dir()

        officeHash = OfficeCracker.Office_Hash_Grabber(officeFile)
        print(basedir + hashcatPath)
        proc = subprocess.run([basedir + truxCrackDir + hashcatPath, "-a", "0", "-m", "9600", officeHash, basedir + truxCrackDir + hashcatDict], stdout=subprocess.PIPE)
        output = proc.stdout

        # Turn output into string
        output = output.decode("utf-8")

        crackedCheck = cracked_password(output)

        if crackedCheck == 1:
            proc = subprocess.run([basedir + truxCrackDir + hashcatPath, "-a", "0", "-m", "9600", "--show", officeHash, basedir + truxCrackDir + hashcatDict], stdout=subprocess.PIPE)
            output = proc.stdout
            # Turn output into string
            output = output.decode("utf-8")
            output = output.replace("\r\n","")
            output = output.split(":")
            decryptedFile = OfficeCracker.decrypt_office_file(encryptedFile, output[1], officeFile)
            add_file(officeFile, decryptedFile)
        elif crackedCheck == 2:
            decryptedFile = OfficeCracker.decrypt_office_file(encryptedFile, output[1], officeFile)
            add_file(officeFile, decryptedFile)
        elif crackedCheck == 3:
            print("password cracking exhausted for " + officeHash)
        elif crackedCheck == 4:
            print("Unknown stage in hashcat")

def NTLM_Crack(ntlmHash):
    ntlmHashes = ntlmHash.readall()
    # Turn bytecode into string
    ntlmHashes = ntlmHashes.decode('utf-8')
    # Split hashes into seperate accounts
    ntlmHashes = ntlmHashes.split("\r\n")
    # Grab the non default account (Note, make this expandable, use VM to create test accounts)
    accountInfo = ntlmHashes[5]
    # Split the data up
    accountInfo = accountInfo.split(":")
    # Grab the password hash
    userAccountHash = str(accountInfo[3])

    # Run Hashcat and save the output
    proc = subprocess.run([hashcatPath, "-a", "0", "-m", "1000", userAccountHash , hashcatDict], stdout=subprocess.PIPE)
    output = proc.stdout
    # Turn output into string
    output = output.decode("utf-8")

    crackedCheck = cracked_password(output)

    if crackedCheck == 1:
        proc = subprocess.run([hashcatPath, "-a", "0", "-m", "1000", "--show", userAccountHash , hashcatDict], stdout=subprocess.PIPE)
        output = proc.stdout
        # Turn output into string
        output = output.decode("utf-8")
        ntlmCrackedPassword = password_grabber(output, userAccountHash)
        add_file(ntlmHash, ntlmCrackedPassword)
    elif crackedCheck == 2:
        ntlmCrackedPassword = password_grabber(output, userAccountHash)
        add_file(ntlmHash, ntlmCrackedPassword)
    elif crackedCheck == 3:
        print("password cracking exhausted for " + userAccountHash)
    elif crackedCheck == 4:
        print("Unknown stage in hashcat")

def password_grabber(hashcatO, ntlmHash):
    for line in hashcatO:
        if ntlmHash in hashcatO:
            return line

def add_file(parent_truxton_file, filename):
  child = parent_truxton_file.newchild()
  with open(filename, "rb") as source_file:
    child.name = Path(filename).name
    shutil.copyfileobj(source_file, child)
    child.save()
  return child

def cracked_password(hashcatO):
    # We need to see if hashcat has already cracked this password, if so, just show the password
    if "INFO: All hashes found in potfile! Use --show to display them." in hashcatO:
        return 1
    # check to see if password is cracked; if so, grab the password from the output.
    elif "Status...........: Cracked" in hashcatO:
        return 2
    # check to see if password cracking failed from dictionary exhaustion
    elif "Status...........: Exhausted" in hashcatO:
        return 3
    # if you get here, im unaware of that status
    else:
        return 4

def file_identification(file, fileType):
    # Identify file, then send to correct exploitation function
    if fileType == 714:
        NTLM_Crack(file)
    elif fileType == 757:
        OfficeCracker.Office_Crack(file)
    elif fileType == 223: # real filetype 336
        PDFcracker.create_pdf_dir()
        hash = PDFcracker.pdfhashgrabber(file)
        hashresult = PDFcracker.pdf_encryption_detector(hash)
        PDFcracker.pdfCracker(file, hash, hashresult)

def main():
    # create truxton variable
    t = truxton.create()
    t.createtag("Cracked Password", "Hashcat cracked this password")
    
    etl = truxton.etl()
    etl.name = "Hashcat Exploitation"
    etl.description = "This exploits various hashes with hashcat"
    etl.queue = "hashcat"
    etl.stage = 40
    etl.depot = "hashcat"
 
    etl.sendmefiles(truxton.Type_Password_Dump, 500)
    etl.sendmefiles(truxton.Type_Encrypted_Office_2016_Document, 500)
    etl.sendmefiles(truxton.Type_Adobe_PDF, 500)
    os.chdir(truxCrackDir + hashcatDir)

    message = etl.getmessage()
    while message is not None:
        # Get incoming file
        incomingfile = message.file()

        # Identify the file
        '''if incomingfile.type == 714:
            x = incomingfile.readall()
            x = x.decode('utf-8')
            x = x.split('\r\n')
            print(x)
            print("\n")
            y = x[5]
            print(y)
            print("\n")
            y = y.split(':')
            z = y[3]
            print(z)'''
        print(incomingfile.type)
        if incomingfile.type == 223:
            file_identification(incomingfile, incomingfile.type)
        print(incomingfile)
        
        # wait for incoming message...
        message = etl.getmessage()

if __name__ == '__main__':
    # Start the program
    main()