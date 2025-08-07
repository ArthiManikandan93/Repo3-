# Repo3-
import random
import string
import re

def generate_password(length=12, use_upper=True, use_digits=True, use_symbols=True):
    """Generate a random password."""
    characters = string.ascii_lowercase
    if use_upper:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if length < 4:
        raise ValueError("Password length should be at least 4 characters")

    # Ensure password has at least one of each selected character type
    password = [
        random.choice(string.ascii_lowercase),
    ]
    if use_upper:
        password.append(random.choice(string.ascii_uppercase))
    if use_digits:
        password.append(random.choice(string.digits))
    if use_symbols:
        password.append(random.choice(string.punctuation))

    # Fill the rest of the password length with random chars
    password += random.choices(characters, k=length - len(password))

    random.shuffle(password)
    return ''.join(password)

def validate_password(password):
    """Validate password strength."""
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is None

    errors = {
        "length_error": length_error,
        "digit_error": digit_error,
        "uppercase_error": uppercase_error,
        "lowercase_error": lowercase_error,
        "symbol_error": symbol_error,
    }

    is_valid = not any(errors.values())
    return is_valid, errors

def main():
    print("=== Password Generator ===")
    length = int(input("Enter desired password length (min 8): "))
    password = generate_password(length)
    print(f"Generated password: {password}")

    print("\n=== Password Validator ===")
    pwd_to_check = input("Enter a password to validate: ")
    valid, errors = validate_password(pwd_to_check)

    if valid:
        print("Password is strong!")
    else:
        print("Password is weak due to:")
        if errors["length_error"]:
            print("- Password must be at least 8 characters")
        if errors["digit_error"]:
            print("- Password must include at least one digit")
        if errors["uppercase_error"]:
            print("- Password must include at least one uppercase letter")
        if errors["lowercase_error"]:
            print("- Password must include at least one lowercase letter")
        if errors["symbol_error"]:
            print("- Password must include at least one special symbol")

if __name__ == "__main__":
    main()
