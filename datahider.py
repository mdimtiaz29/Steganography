import os
import json
import hashlib
import secrets
from tkinter import *
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from stegano import lsb

# CONFIG persistence settings
CONFIG_FILE = "config.json"
DEFAULT_PASSCODE = "1234"

# COLOR PALETTE
BG_DARK = "#0f172a"        
CARD_BG = "#1e293b"        
ACCENT_CYAN = "#06b6d4"    
ACCENT_GREEN = "#10b981"   
ACCENT_PURPLE = "#a855f7"  
ACCENT_AMBER = "#f59e0b"   
TEXT_LIGHT = "#f8fafc"     
TEXT_MUTED = "#94a3b8"     
BORDER_COLOR = "#334155"   

# FONTS
FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_SUBTITLE = ("Segoe UI", 10)
FONT_LABEL = ("Segoe UI", 10, "bold")
FONT_BODY = ("Segoe UI", 10)
FONT_BUTTON = ("Segoe UI", 10, "bold")

# Security Helper Functions
def hash_passcode(passcode: str, salt: bytes = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', passcode.encode('utf-8'), salt, 100000)
    return salt.hex(), key.hex()

def verify_passcode(passcode: str) -> bool:
    if not os.path.exists(CONFIG_FILE):
        init_config()
    try:
        with open(CONFIG_FILE, 'r') as f:
            data = json.load(f)
        salt = bytes.fromhex(data['salt'])
        stored_hash = data['passcode_hash']
        _, calc_hash = hash_passcode(passcode, salt)
        return secrets.compare_digest(stored_hash, calc_hash)
    except Exception:
        return False

def save_passcode_hash(passcode: str):
    salt_hex, key_hex = hash_passcode(passcode)
    config_data = {
        'salt': salt_hex,
        'passcode_hash': key_hex
    }
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_data, f, indent=4)

def init_config():
    if not os.path.exists(CONFIG_FILE):
        save_passcode_hash(DEFAULT_PASSCODE)

# Initialize Passcode Storage Configuration
init_config()

win = Tk()
win.title("SteganoCrypt - Visual Steganography")
win.geometry("960x650")
win.minsize(800, 500)
win.config(bg=BG_DARK)

# Enable maximizing and window resizing
win.resizable(True, True)

open_file = None
hide_msg = None

def reset_all():
    global open_file, hide_msg
    open_file = None
    hide_msg = None
    
    # Hide the Save Image button again on reset
    btn_save.pack_forget()
    
    # Reset Preview
    lf1.configure(image='', text="No Image Loaded\nClick 'Open Image' to select")
    lf1.image = None
    
    # Reset Inputs
    text1.delete(1.0, END)
    code_entry.delete(0, END)

def open_img():
    global open_file
    file_path = filedialog.askopenfilename(
        initialdir=os.getcwd(),
        title='Select Image File',
        filetypes=(
            ('PNG and BMP Files', '*.png *.PNG *.bmp *.BMP'),
            ('PNG Files', '*.png *.PNG'),
            ('BMP Files', '*.bmp *.BMP'),
            ('All Files', '*.*')
        )
    )
    if file_path:
        open_file = file_path
        img = Image.open(open_file)
        
        img.thumbnail((380, 260))
        tk_img = ImageTk.PhotoImage(img)
        
        lf1.configure(image=tk_img, text="")
        lf1.image = tk_img

def hide():
    global hide_msg
    if not open_file:
        messagebox.showerror('Error', 'Please select an image first!')
        return

    password = code_entry.get()
    msg = text1.get(1.0, END).strip()

    if not password:
        messagebox.showerror('Error', 'Please enter Secret Key')
        return

    if not msg:
        messagebox.showerror('Error', 'Please enter a secret message to hide.')
        return

    if verify_passcode(password):
        hide_msg = lsb.hide(str(open_file), msg)
        messagebox.showinfo('Success', 'Message encrypted into image! Click "Save Image" to keep it.')
        
        # Show the Save Image button only after successful encryption
        btn_save.pack(side=LEFT, padx=3)
    else:
        messagebox.showerror('Error', 'Incorrect Secret Key')
        code_entry.delete(0, END)

def save_img():
    if hide_msg is None:
        messagebox.showerror('Error', 'No hidden data ready. Please hide a message first!')
        return
        
    save_path = filedialog.asksaveasfilename(
        initialdir=os.getcwd(),
        title='Save Encrypted Image',
        defaultextension='.png',
        filetypes=(('PNG file', '*.png'), ('All files', '*.*'))
    )
    
    if save_path:
        hide_msg.save(save_path)
        messagebox.showinfo('Saved', 'Image saved successfully!')
        reset_all()

def show():
    if not open_file:
        messagebox.showerror('Error', 'Please select an image first!')
        return

    password = code_entry.get()
    if not password:
        messagebox.showerror('Error', 'Please enter Secret Key')
        return

    if verify_passcode(password):
        try:
            show_msg = lsb.reveal(open_file)
            text1.delete(1.0, END)
            if show_msg:
                text1.insert(END, show_msg)
            else:
                messagebox.showwarning('Warning', 'No hidden message found in this image.')
        except Exception:
            messagebox.showerror('Error', 'Could not extract data from this image.')
    else:
        messagebox.showerror('Error', 'Incorrect Secret Key')
        code_entry.delete(0, END)

# HELP & SETTINGS DIALOGS
def open_help():
    help_win = Toplevel(win)
    help_win.title("Help Guide - SteganoCrypt")
    help_win.geometry("500x420")
    help_win.config(bg=BG_DARK)
    help_win.transient(win)
    help_win.grab_set()

    Label(help_win, text="How to Use SteganoCrypt", font=FONT_TITLE, bg=BG_DARK, fg=TEXT_LIGHT).pack(pady=(15, 5))
    
    help_text = (
        "1. Open Image:\n"
        "   Click 'Open Image' to select a base image (PNG or BMP format works best).\n\n"
        "2. Hide Data:\n"
        "   - Type your text message in the 'SECRET MESSAGE' box.\n"
        "   - Enter the Passcode Key (Default is 1234).\n"
        "   - Click 'Hide Data' to inject the message into the image.\n"
        "   - Click 'Save Image' to export the carrier file.\n\n"
        "3. Reveal Data:\n"
        "   - Load an image containing hidden data using 'Open Image'.\n"
        "   - Enter the correct Passcode Key.\n"
        "   - Click 'Show Data' to reveal the hidden text."
    )

    txt_label = Label(help_win, text=help_text, font=FONT_BODY, bg=CARD_BG, fg=TEXT_LIGHT, justify=LEFT, padx=15, pady=15, wraplength=440)
    txt_label.pack(padx=20, pady=10, fill=BOTH, expand=True)

    Button(help_win, text="Close", font=FONT_BUTTON, bg=ACCENT_CYAN, fg=BG_DARK, bd=0, padx=15, pady=4, cursor="hand2", command=help_win.destroy).pack(pady=(0, 15))

def change_passcode():
    current_input = simpledialog.askstring("Reset Passcode", "Enter CURRENT Passcode Key:", show="*")
    if current_input is None:
        return
        
    if not verify_passcode(current_input):
        messagebox.showerror("Error", "Incorrect current passcode.")
        return

    new_passcode = simpledialog.askstring("Reset Passcode", "Enter NEW Passcode Key (4-16 characters):", show="*")
    if new_passcode is None:
        return

    if not (4 <= len(new_passcode) <= 16):
        messagebox.showerror("Error", "Passcode must be between 4 and 16 characters long.")
        return

    confirm_passcode = simpledialog.askstring("Reset Passcode", "Confirm NEW Passcode Key:", show="*")
    if confirm_passcode is None:
        return

    if new_passcode != confirm_passcode:
        messagebox.showerror("Error", "Passcodes do not match.")
        return

    save_passcode_hash(new_passcode)
    messagebox.showinfo("Success", "Passcode Key updated successfully!")

def open_settings():
    settings_win = Toplevel(win)
    settings_win.title("Settings & About")
    settings_win.geometry("520x450")
    settings_win.config(bg=BG_DARK)
    settings_win.transient(win)
    settings_win.grab_set()

    Label(settings_win, text="Settings & About App", font=FONT_TITLE, bg=BG_DARK, fg=TEXT_LIGHT).pack(pady=(15, 5))

    about_text = (
        "SteganoCrypt v1.0\n"
        "------------------------------------\n"
        "SteganoCrypt is an advanced desktop steganography tool designed to covertly "
        "embed encrypted alphanumeric data directly within image pixel metadata using "
        "Least Significant Bit (LSB) manipulation.\n\n"
        "Key Features:\n"
        "• Lossless Image Format Support (PNG, BMP)\n"
        "• LSB Image Encoding & Decoding\n"
        "• Key-gated Authorization Layer\n"
        "• Dark Modern User Interface"
    )

    info_label = Label(settings_win, text=about_text, font=FONT_BODY, bg=CARD_BG, fg=TEXT_LIGHT, justify=LEFT, padx=15, pady=15, wraplength=460)
    info_label.pack(padx=20, pady=10, fill=BOTH, expand=True)

    btn_frame_dialog = Frame(settings_win, bg=BG_DARK)
    btn_frame_dialog.pack(pady=(5, 15))

    Button(btn_frame_dialog, text="🔑 Reset Passcode Key", font=FONT_BUTTON, bg=ACCENT_PURPLE, fg=TEXT_LIGHT, bd=0, padx=10, pady=5, cursor="hand2", command=change_passcode).pack(side=LEFT, padx=5)
    Button(btn_frame_dialog, text="Close", font=FONT_BUTTON, bg=CARD_BG, fg=TEXT_LIGHT, bd=0, padx=15, pady=5, cursor="hand2", command=settings_win.destroy).pack(side=LEFT, padx=5)

# HEADER SECTION
header_frame = Frame(win, bg=BG_DARK)
header_frame.pack(fill=X, padx=30, pady=(15, 10))

logo_canvas = Canvas(header_frame, width=36, height=36, bg=BG_DARK, highlightthickness=0)
logo_canvas.pack(side=LEFT, padx=(0, 10))
logo_canvas.create_polygon(18, 2, 34, 10, 34, 26, 18, 34, 2, 26, 2, 10, fill=ACCENT_CYAN, outline="")
logo_canvas.create_text(18, 18, text="🔒", font=("Segoe UI", 11))

title_label = Label(header_frame, text="SteganoCrypt", font=FONT_TITLE, bg=BG_DARK, fg=TEXT_LIGHT)
title_label.pack(side=LEFT)

subtitle_label = Label(header_frame, text="• Image Steganography Suite", font=FONT_SUBTITLE, bg=BG_DARK, fg=TEXT_MUTED)
subtitle_label.pack(side=LEFT, padx=(10, 0), pady=(6, 0))

# Header Navigation Buttons
reload_btn = Button(header_frame, text="🔄 Refresh", font=FONT_SUBTITLE, bg=CARD_BG, fg=TEXT_LIGHT, activebackground=BORDER_COLOR, activeforeground=TEXT_LIGHT, bd=0, padx=8, pady=4, cursor='hand2', command=reset_all)
reload_btn.pack(side=RIGHT, padx=(4, 0))

settings_btn = Button(header_frame, text="⚙️ Settings", font=FONT_SUBTITLE, bg=CARD_BG, fg=TEXT_LIGHT, activebackground=BORDER_COLOR, activeforeground=TEXT_LIGHT, bd=0, padx=8, pady=4, cursor='hand2', command=open_settings)
settings_btn.pack(side=RIGHT, padx=(4, 0))

help_btn = Button(header_frame, text="❓ Help", font=FONT_SUBTITLE, bg=CARD_BG, fg=TEXT_LIGHT, activebackground=BORDER_COLOR, activeforeground=TEXT_LIGHT, bd=0, padx=8, pady=4, cursor='hand2', command=open_help)
help_btn.pack(side=RIGHT, padx=(4, 0))

# SECURITY & ACTION CONTROLS (Anchored at bottom)
controls_frame = Frame(win, bg=CARD_BG, highlightbackground=BORDER_COLOR, highlightthickness=1)
controls_frame.pack(side=BOTTOM, fill=X, padx=30, pady=(10, 20))

# Passcode Input
key_frame = Frame(controls_frame, bg=CARD_BG)
key_frame.pack(side=LEFT, expand=True, padx=20, pady=12)

Label(key_frame, text="Passcode Key", font=FONT_LABEL, bg=CARD_BG, fg=TEXT_LIGHT).pack(anchor=CENTER)

code_entry = Entry(
    key_frame, 
    font=('Segoe UI', 11, 'bold'), 
    bg='#334155', 
    fg='#ffffff', 
    insertbackground='#ffffff', 
    bd=0, 
    width=14, 
    justify='center',
    show='*',
    highlightthickness=1, 
    highlightbackground='#64748b', 
    highlightcolor=ACCENT_CYAN
)
code_entry.pack(pady=(4, 0), ipady=4)

# Action Buttons
btn_frame = Frame(controls_frame, bg=CARD_BG)
btn_frame.pack(side=RIGHT, expand=True, padx=20, pady=12)

btn_open = Button(btn_frame, text="Open Image", bg=ACCENT_CYAN, fg=BG_DARK, activebackground="#0891b2", font=FONT_BUTTON, bd=0, cursor="hand2", padx=10, pady=5, command=open_img)
btn_open.pack(side=LEFT, padx=3)

btn_hide = Button(btn_frame, text="Hide Data", bg=ACCENT_PURPLE, fg=TEXT_LIGHT, activebackground="#9333ea", font=FONT_BUTTON, bd=0, cursor="hand2", padx=10, pady=5, command=hide)
btn_hide.pack(side=LEFT, padx=3)

btn_show = Button(btn_frame, text="Show Data", bg=ACCENT_AMBER, fg=BG_DARK, activebackground="#d97706", font=FONT_BUTTON, bd=0, cursor="hand2", padx=10, pady=5, command=show)
btn_show.pack(side=LEFT, padx=3)

btn_save = Button(btn_frame, text="Save Image", bg=ACCENT_GREEN, fg=BG_DARK, activebackground="#059669", font=FONT_BUTTON, bd=0, cursor="hand2", padx=10, pady=5, command=save_img)

# MAIN WORKSPACE PANELS (Fills central region)
body_frame = Frame(win, bg=BG_DARK)
body_frame.pack(fill=BOTH, expand=True, padx=30, pady=5)

body_frame.columnconfigure(0, weight=1, uniform="equal_cols")
body_frame.columnconfigure(1, weight=1, uniform="equal_cols")
body_frame.rowconfigure(0, weight=1)

# Left Panel for Image Preview
left_card = Frame(body_frame, bg=CARD_BG, highlightbackground=BORDER_COLOR, highlightthickness=1)
left_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

Label(left_card, text="IMAGE PREVIEW", font=FONT_LABEL, bg=CARD_BG, fg=TEXT_MUTED).pack(anchor=W, padx=15, pady=(10, 5))

preview_container = Frame(left_card, bg=BG_DARK)
preview_container.pack(padx=15, pady=(0, 15), fill=BOTH, expand=True)

lf1 = Label(preview_container, text="No Image Loaded\nClick 'Open Image' to select", font=FONT_SUBTITLE, bg=BG_DARK, fg=TEXT_MUTED)
lf1.pack(fill=BOTH, expand=True)

# Right Panel for Message Entry
right_card = Frame(body_frame, bg=CARD_BG, highlightbackground=BORDER_COLOR, highlightthickness=1)
right_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

Label(right_card, text="SECRET MESSAGE", font=FONT_LABEL, bg=CARD_BG, fg=TEXT_MUTED).pack(anchor=W, padx=15, pady=(10, 5))

text1 = Text(
    right_card, 
    font=FONT_BODY, 
    bg=BG_DARK, 
    fg=TEXT_LIGHT, 
    insertbackground=TEXT_LIGHT, 
    bd=0, 
    padx=10, 
    pady=10, 
    wrap=WORD, 
    highlightthickness=1, 
    highlightbackground=BORDER_COLOR
)
text1.pack(padx=15, pady=(0, 15), fill=BOTH, expand=True)

win.mainloop()