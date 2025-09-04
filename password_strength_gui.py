"""
Password Strength Analyzer (GUI Version)
Author: Krish Patel
Date: September 2025
Description:
A graphical tool built with Tkinter that checks password strength
based on security rules and gives suggestions for improvement.
"""

import re
import tkinter as tk
from tkinter import messagebox

def check_password_strength(password):
    strength = 0
    remarks = []

    # Rule 1: Length check
    if len(password) >= 8:
        strength += 1
    else:
        remarks.append("❌ Password should be at least 8 characters long.")

    # Rule 2: Uppercase check
    if re.search(r"[A-Z]", password):
        strength += 1
    else:
        remarks.append("❌ Add at least one uppercase letter.")

    # Rule 3: Lowercase check
    if re.search(r"[a-z]", password):
        strength += 1
    else:
        remarks.append("❌ Add at least one lowercase letter.")

    # Rule 4: Digit check
    if re.search(r"[0-9]", password):
        strength += 1
    else:
        remarks.append("❌ Add at least one number.")

    # Rule 5: Special character check
    if re.search(r"[@#$!%*?&]", password):
        strength += 1
    else:
        remarks.append("❌ Add at least one special character (@,#, $, !, %, *, ?, &).")

    # Strength classification
    if strength == 5:
        return "✅ Strong Password", remarks
    elif 3 <= strength < 5:
        return "⚠️ Moderate Password", remarks
    else:
        return "❌ Weak Password", remarks


def analyze_password():
    password = entry.get()
    if not password:
        messagebox.showwarning("Warning", "Please enter a password.")
        return

    result, feedback = check_password_strength(password)

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, f"Password Strength: {result}\n\n")

    if feedback:
        output_text.insert(tk.END, "Suggestions:\n")
        for item in feedback:
            output_text.insert(tk.END, f"- {item}\n")


# GUI Setup
root = tk.Tk()
root.title("Password Strength Analyzer")
root.geometry("500x400")
root.config(bg="#f0f4f7")

# Heading
heading = tk.Label(root, text="🔐 Password Strength Analyzer", 
                   font=("Arial", 16, "bold"), bg="#f0f4f7", fg="#2c3e50")
heading.pack(pady=10)

# Entry field
entry_label = tk.Label(root, text="Enter Password:", font=("Arial", 12), bg="#f0f4f7")
entry_label.pack(pady=5)

entry = tk.Entry(root, show="*", width=30, font=("Arial", 12))
entry.pack(pady=5)

# Button
analyze_btn = tk.Button(root, text="Analyze", command=analyze_password, 
                        font=("Arial", 12, "bold"), bg="#3498db", fg="white", padx=10, pady=5)
analyze_btn.pack(pady=10)

# Output text box
output_text = tk.Text(root, height=10, width=55, font=("Arial", 10))
output_text.pack(pady=10)

# Run GUI
root.mainloop()
