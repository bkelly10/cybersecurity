import re
import hashlib

# Create a criteria check list to determine password strength

def password_strength(password):

    length_error    = len(password) < 12
    digit_error     = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error    = re.search(r"[^a-zA-Z0-9]", password) is None
    repeat_error = re.search(r"(.)\1\1", password) is not None

     # Collect results in a dictionary before calculating overall score
    
    errors = {
        "Too short (min 12 chars)": length_error,
        "Missing digit": digit_error,
        "Missing uppercase letter": uppercase_error,
        "Missing lowercase letter": lowercase_error,
        "Missing special character": symbol_error,
        "Contains character repeated 3+ times": repeat_error
    }

    score = 6 - sum(errors.values())

    # Create strength buckets
    
    if score == 6:
        strength = "Very Strong"
    elif score == 5:
        strength = "Strong"
    elif score == 4:
        strength = "Moderate"
    else:
        strength = "Weak"

    # Hash password
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    
    issues = [err for err, failed in errors.items() if failed]
    
    return strength, issues, score, hashed_pw

# Main program execution
# Prints results, hash, and also stores hash into a txt file

if __name__ == "__main__":
    pwd = input("Enter a password to check: ")
    strength, issues, score, hashed_pw = password_strength(pwd)
    print(f"\nPassword Strength: {strength} ({score}/6)")
    if issues:
        print("Issues:")
        for issue in issues:
            print(f"- {issue}")
    else:
        print("This password meets all requirements!")
    
    print(f"\nSHA-256 Hash:\n{hashed_pw}")
    with open ("hashed_passwords.txt", "a") as file:
        file.write(f"{hashed_pw}\n")
    
    print("\n Hashed saved securely to 'hashed_passwords.txt'")
    


    



















