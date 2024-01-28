# main.py

if __name__ == '__main__':
    while True:
        print("\nWelcome to St John's Clinic")
        print("1. User Login")
        print("2. Admin Login")
        print("3. Exit")

        menu_choice = int(input("Enter your choice: "))

        if menu_choice == 1:
            while True:
                print("\nUser Login")
                print("1. Normal Login")
                print("2. SSO (Single-Sign-On) Login")
                print("3. Exit")

                user_login_choice = int(input("Enter your choice: "))

                if user_login_choice == 1:
                    print("Normal Login")
                    break
                elif user_login_choice == 2:
                    print("SSO Login")
                    break
                elif user_login_choice == 3:
                    break
                else:
                    print("\nInvalid choice. Please try again.")

        elif menu_choice == 2:
            print("\nAdmin Login")
            admin_login_choice = int(input("Enter your choice: "))
            break
        elif menu_choice == 3:
            break
        else:
            print("\nInvalid choice. Please try again.\n")
