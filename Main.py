import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

SALT = b'tugas_kripto_salt_2025' 
KEY_SIZE = 16       
ITERATIONS = 100000 

def get_key(password: str) -> bytes:
    """Menghasilkan kunci standar AES dari string password menggunakan PBKDF2."""
    return PBKDF2(password, SALT, dkLen=KEY_SIZE, count=ITERATIONS)

def encrypt_file(input_pdf: str, password: str):
    """Mengenkripsi file PDF menggunakan algoritma AES mode CBC."""
    if not os.path.exists(input_pdf):
        print(f"[-] Error: File '{input_pdf}' tidak ditemukan.")
        return

    key = get_key(password)
    
    cipher = AES.new(key, AES.MODE_CBC)
    
    with open(input_pdf, 'rb') as f:
        original_data = f.read()
        
    padded_data = pad(original_data, AES.block_size)
    
    encrypted_data = cipher.encrypt(padded_data)
    
    output_file = input_pdf + ".enc"
    with open(output_file, 'wb') as f:
        f.write(cipher.iv) 
        f.write(encrypted_data)
        
    print(f"[+] ENKRIPSI SUKSES: {input_pdf} -> {output_file}")

def decrypt_file(encrypted_file: str, password: str):
    """Mendekripsi file PDF yang telah dienkripsi menggunakan AES mode CBC."""
    if not os.path.exists(encrypted_file):
        print(f"[-] Error: File '{encrypted_file}' tidak ditemukan.")
        return

    key = get_key(password)
    
    with open(encrypted_file, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()
        
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    
    try:
        decrypted_padded_data = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)
        
        output_file = encrypted_file.replace(".enc", "_decrypted.pdf")
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
            
        print(f"[+] DEKRIPSI SUKSES: {encrypted_file} -> {output_file}")
        
    except ValueError:
        print("[-] DEKRIPSI GAGAL: Password salah atau file korup!")

# === EKSEKUSI PROGRAM ===
if __name__ == "__main__":
    print("=== APLIKASI ENKRIPSI PDF (AES) ===")
    print("-" * 45)
    
    # Meminta input interaktif dari pengguna melalui terminal
    target_pdf = input("Masukkan nama file PDF (contoh: tugas.pdf) : ")
    user_password = input("Masukkan password rahasia                  : ")
    
    print("\n[ Memulai Proses... ]")
    
    # Cek apakah file yang diinputkan ada di dalam folder
    if os.path.exists(target_pdf):
        # Proses Enkripsi
        encrypt_file(target_pdf, user_password)
        
        # Proses Dekripsi otomatis untuk pembuktian
        encrypted_target = target_pdf + ".enc"
        decrypt_file(encrypted_target, user_password)
    else:
        print(f"[-] Error: File '{target_pdf}' tidak ditemukan di folder ini.")
        print("    Pastikan nama file dan ekstensinya (.pdf) diketik dengan benar.")
        
    print("-" * 45)
    print("=== SELESAI ===")