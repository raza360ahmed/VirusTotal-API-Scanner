from utils import check_hash, check_ip

def main():
    print(" === VirusTotal API Scanner ===")
    print("1. Check File Hash")
    print("2. Check IP Address")

    choice = input("Choose an option:").strip()
    if choice == "1":
        file_hash = input("Enter the file hash (SHA256/MD5/SHA1): ").strip()
        if file_hash:
            check_hash(file_hash)
        else:
            print("Invalid hash input.")
    elif choice == "2":
        ip = input("Enter IP address: ").strip()
        if ip:
            check_ip(ip)
        else:
            print("Invalid option. Please enter 1 or 2.")
    else:
        print("Invalid option. Please enter 1 or 2.")

if __name__ == "__main__":
    main()
