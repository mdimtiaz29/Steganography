import os
from tkinter import *
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from stegano import lsb

# --- COLOR PALETTE (Cyber Dark Theme) ---
BG_DARK = "#0f172a"        
CARD_BG = "#1e293b"        
ACCENT_CYAN = "#06b6d4"    
ACCENT_GREEN = "#10b981"   
ACCENT_PURPLE = "#a855f7"  
ACCENT_AMBER = "#f59e0b"   
TEXT_LIGHT = "#f8fafc"     
TEXT_MUTED = "#94a3b8"     
BORDER_COLOR = "#334155"   

# --- FONTS ---
FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_SUBTITLE = ("Segoe UI", 10)
FONT_LABEL = ("Segoe UI", 10, "bold")
FONT_BODY = ("Segoe UI", 10)
FONT_BUTTON = ("Segoe UI", 10, "bold")

win = Tk()
win.title("SteganoCrypt - Visual Steganography")
win.geometry("920x650")
win.config(bg=BG_DARK)
win.resizable(False, False)

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
            ('All Supported Images', '*.png *.jpg *.jpeg *.PNG *.JPG *.JPEG'),
            ('PNG Files', '*.png *.PNG'),
            ('JPG Files', '*.jpg *.jpeg *.JPG *.JPEG'),
            ('All Files', '*.*')
        )
    )
    if file_path:
        open_file = file_path
        img = Image.open(open_file)
        
        # Scale image up to fit the preview frame
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

    if not msg:
        messagebox.showerror('Error', 'Please enter a secret message to hide.')
        return

    if password == '1234':
        hide_msg = lsb.hide(str(open_file), msg)
        messagebox.showinfo('Success', 'Message encrypted into image! Click "Save Image" to keep it.')
        
        # Show the Save Image button only after successful encryption
        btn_save.pack(side=LEFT, padx=3)
        
    elif password == '':
        messagebox.showerror('Error', 'Please enter Secret Key')
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
    if password == '1234':
        try:
            show_msg = lsb.reveal(open_file)
            text1.delete(1.0, END)
            if show_msg:
                text1.insert(END, show_msg)
            else:
                messagebox.showwarning('Warning', 'No hidden message found in this image.')
        except Exception:
            messagebox.showerror('Error', 'Could not extract data from this image.')
    elif password == '':
        messagebox.showerror('Error', 'Please enter Secret Key')
    else:
        messagebox.showerror('Error', 'Incorrect Secret Key')
        code_entry.delete(0, END)

# --- HEADER SECTION ---
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

reload_btn = Button(
    header_frame, 
    text="🔄 Reset All", 
    font=FONT_SUBTITLE, 
    bg=CARD_BG, 
    fg=TEXT_LIGHT, 
    activebackground=BORDER_COLOR, 
    activeforeground=TEXT_LIGHT,
    bd=0, 
    padx=10, 
    pady=4, 
    cursor='hand2', 
    command=reset_all
)
reload_btn.pack(side=RIGHT)

# --- MAIN WORKSPACE PANELS ---
body_frame = Frame(win, bg=BG_DARK)
body_frame.pack(fill=BOTH, expand=True, padx=30, pady=5)

body_frame.columnconfigure(0, weight=1, uniform="equal_cols")
body_frame.columnconfigure(1, weight=1, uniform="equal_cols")
body_frame.rowconfigure(0, weight=1)

# Left Panel: Image Preview
left_card = Frame(body_frame, bg=CARD_BG, highlightbackground=BORDER_COLOR, highlightthickness=1)
left_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

Label(left_card, text="IMAGE PREVIEW", font=FONT_LABEL, bg=CARD_BG, fg=TEXT_MUTED).pack(anchor=W, padx=15, pady=(10, 5))

preview_container = Frame(left_card, bg=BG_DARK, height=260)
preview_container.pack_propagate(False)
preview_container.pack(padx=15, pady=(0, 15), fill=BOTH, expand=True)

lf1 = Label(preview_container, text="No Image Loaded\nClick 'Open Image' to select", font=FONT_SUBTITLE, bg=BG_DARK, fg=TEXT_MUTED)
lf1.pack(fill=BOTH, expand=True)

# Right Panel: Message Entry
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

# --- SECURITY & ACTION CONTROLS ---
controls_frame = Frame(win, bg=CARD_BG, highlightbackground=BORDER_COLOR, highlightthickness=1)
controls_frame.pack(fill=X, padx=30, pady=(10, 20))

# Left Sub-Container: Passcode Input
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
    highlightthickness=1, 
    highlightbackground='#64748b', 
    highlightcolor=ACCENT_CYAN
)
code_entry.pack(pady=(4, 0), ipady=4)

# Right Sub-Container: Action Buttons
btn_frame = Frame(controls_frame, bg=CARD_BG)
btn_frame.pack(side=RIGHT, expand=True, padx=20, pady=12)

btn_open = Button(btn_frame, text="Open Image", bg=ACCENT_CYAN, fg=BG_DARK, activebackground="#0891b2", font=FONT_BUTTON, bd=0, cursor="hand2", padx=10, pady=5, command=open_img)
btn_open.pack(side=LEFT, padx=3)

btn_hide = Button(btn_frame, text="Hide Data", bg=ACCENT_PURPLE, fg=TEXT_LIGHT, activebackground="#9333ea", font=FONT_BUTTON, bd=0, cursor="hand2", padx=10, pady=5, command=hide)
btn_hide.pack(side=LEFT, padx=3)

btn_show = Button(btn_frame, text="Show Data", bg=ACCENT_AMBER, fg=BG_DARK, activebackground="#d97706", font=FONT_BUTTON, bd=0, cursor="hand2", padx=10, pady=5, command=show)
btn_show.pack(side=LEFT, padx=3)

# Initialized without .pack() so it stays hidden on launch
btn_save = Button(btn_frame, text="Save Image", bg=ACCENT_GREEN, fg=BG_DARK, activebackground="#059669", font=FONT_BUTTON, bd=0, cursor="hand2", padx=10, pady=5, command=save_img)

win.mainloop()