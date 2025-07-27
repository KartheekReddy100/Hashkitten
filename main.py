#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Hashkitten - Advanced Hash Toolkit (Python GUI Port)

A versatile, all-in-one crypto utility for hashing, encoding, and more,
ported from the original Hashkitten web application to a Python GUI.

Author: Nallamilli Satya Sai Kartheek Reddy (Ported by Gemini)
Date: 2025-07-27
"""

import customtkinter as ctk
import hashlib
import hmac
import base64
import sys
import os
import re
import threading
import pyperclip
from urllib.parse import quote, unquote
from tkinter import filedialog, messagebox

# --- Constants ---
CHUNK_SIZE = 8192  # 8KB chunk size for reading files

# --- Core Hashing & Utility Logic ---

def get_hash_object(algorithm_name):
    """Returns a hash object from hashlib based on the algorithm name."""
    algorithm_name = algorithm_name.lower().replace('-', '')
    try:
        return hashlib.new(algorithm_name)
    except ValueError:
        messagebox.showerror("Error", f"Unsupported hash algorithm '{algorithm_name}'.")
        return None

def hash_file(filepath, algorithm, progress_callback=None):
    """
    Calculates the hash of a single file, with optional progress reporting.
    Returns the hex digest on success, None on failure.
    """
    hasher = get_hash_object(algorithm)
    if not hasher: return None
    try:
        file_size = os.path.getsize(filepath)
        with open(filepath, 'rb') as f:
            bytes_read = 0
            while chunk := f.read(CHUNK_SIZE):
                hasher.update(chunk)
                bytes_read += len(chunk)
                if progress_callback:
                    progress = (bytes_read / file_size) * 100
                    progress_callback(progress)
        return hasher.hexdigest()
    except (IOError, FileNotFoundError) as e:
        messagebox.showerror("File Error", f"Error reading file '{os.path.basename(filepath)}':\n{e}")
        return None
    except Exception as e:
        messagebox.showerror("Hashing Error", f"An unexpected error occurred while hashing '{os.path.basename(filepath)}':\n{e}")
        return None

def hash_text(text, algorithm):
    """Calculates the hash of a given string."""
    hasher = get_hash_object(algorithm)
    if not hasher: return None
    hasher.update(text.encode('utf-8'))
    return hasher.hexdigest()

def generate_hmac(key, message, algorithm):
    """Generates a Keyed-Hash Message Authentication Code (HMAC)."""
    key_bytes = key.encode('utf-8')
    message_bytes = message.encode('utf-8')
    digestmod = algorithm.lower().replace('-', '')
    try:
        h = hmac.new(key_bytes, message_bytes, getattr(hashlib, digestmod))
        return h.hexdigest()
    except Exception as e:
        messagebox.showerror("HMAC Error", f"Failed to generate HMAC: {e}")
        return None

# --- Main Application Class ---

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- App State ---
        self.selected_files = []
        self.file_widgets = []
        self.checksum_file = None
        self.checksum_local_files = []

        self._setup_window()
        self._create_widgets()

    def _setup_window(self):
        """Configure the main application window."""
        self.title("🐾 Hashkitten - Advanced Hash Toolkit")
        self.geometry("800x700")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

    def _create_widgets(self):
        """Create all the UI elements for the application."""
        self._create_header()
        self._create_algo_selector()
        self._create_tab_view()
        self._create_status_bar()

    def _create_header(self):
        header_frame = ctk.CTkFrame(self, corner_radius=0)
        header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        header_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header_frame, text="Hashkitten", font=ctk.CTkFont(size=24, weight="bold")).grid(row=0, column=0, pady=(5,0))
        ctk.CTkLabel(header_frame, text="A versatile crypto utility for hashing, encoding, and more.", text_color="gray60").grid(row=1, column=0, pady=(0,5))

    def _create_algo_selector(self):
        algo_frame = ctk.CTkFrame(self)
        algo_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")
        algo_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(algo_frame, text="Algorithm:").grid(row=0, column=0, padx=10, pady=10)
        algo_options = ["SHA-256", "SHA-512", "SHA-384", "SHA-1", "MD5"]
        self.algo_menu = ctk.CTkOptionMenu(master=algo_frame, values=algo_options)
        self.algo_menu.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

    def _create_tab_view(self):
        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
        tab_names = ["File Hash", "Text Hash", "Compare", "HMAC", "Base64", "Checksum", "Password", "URL"]
        for name in tab_names:
            tab = self.tab_view.add(name)
            tab.grid_columnconfigure(0, weight=1)
        self.create_file_hash_widgets()
        self.create_text_hash_widgets()
        self.create_compare_widgets()
        self.create_hmac_widgets()
        self.create_base64_widgets()
        self.create_checksum_widgets()
        self.create_password_widgets()
        self.create_url_widgets()

    def _create_status_bar(self):
        self.status_bar = ctk.CTkLabel(self, text="Ready", anchor="w", text_color="gray60")
        self.status_bar.grid(row=3, column=0, padx=10, pady=(0, 5), sticky="ew")

    def set_status(self, message):
        self.status_bar.configure(text=message)
        self.update_idletasks()

    # --- Widget Creation for Each Tab ---

    def create_file_hash_widgets(self):
        tab = self.tab_view.tab("File Hash")
        tab.grid_rowconfigure(1, weight=1)
        
        add_files_btn = ctk.CTkButton(tab, text="Select Files (Max 10)", command=self.select_files)
        add_files_btn.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        self.file_list_frame = ctk.CTkScrollableFrame(tab, label_text="Selected Files")
        self.file_list_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")

        btn_frame = ctk.CTkFrame(tab, fg_color="transparent")
        btn_frame.grid(row=2, column=0, sticky="ew")
        btn_frame.grid_columnconfigure((0,1), weight=1)
        
        self.generate_file_hash_btn = ctk.CTkButton(btn_frame, text="Generate Hashes", command=self.run_file_hash_in_thread, state="disabled")
        self.generate_file_hash_btn.grid(row=0, column=0, padx=5, pady=10, sticky="ew")
        
        clear_btn = ctk.CTkButton(btn_frame, text="Clear All", command=self.clear_file_list, fg_color="#D32F2F", hover_color="#C62828")
        clear_btn.grid(row=0, column=1, padx=5, pady=10, sticky="ew")

        verify_frame = ctk.CTkFrame(tab)
        verify_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
        verify_frame.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(verify_frame, text="Verify Single File Hash").grid(row=0, column=0, columnspan=2, pady=5)
        self.hash_to_check_entry = ctk.CTkEntry(verify_frame, placeholder_text="Paste hash to verify here...")
        self.hash_to_check_entry.grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        
        self.verify_hash_btn = ctk.CTkButton(verify_frame, text="Verify", command=self.verify_file_hash, state="disabled")
        self.verify_hash_btn.grid(row=1, column=1, padx=5, pady=5)

    def create_text_hash_widgets(self):
        tab = self.tab_view.tab("Text Hash")
        tab.grid_rowconfigure(0, weight=1)
        self.text_to_hash_box = ctk.CTkTextbox(tab, wrap="word")
        self.text_to_hash_box.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        generate_btn = ctk.CTkButton(tab, text="Generate Hash", command=self.generate_text_hash)
        generate_btn.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

    def create_compare_widgets(self):
        tab = self.tab_view.tab("Compare")
        tab.grid_rowconfigure((0,1), weight=1)
        self.hash1_box = ctk.CTkTextbox(tab, wrap="word", height=100)
        self.hash1_box.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.hash1_box.insert("0.0", "Paste first hash here...")
        self.hash2_box = ctk.CTkTextbox(tab, wrap="word", height=100)
        self.hash2_box.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        self.hash2_box.insert("0.0", "Paste second hash here...")
        compare_btn = ctk.CTkButton(tab, text="Compare Hashes", command=self.compare_hashes)
        compare_btn.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

    def create_hmac_widgets(self):
        tab = self.tab_view.tab("HMAC")
        tab.grid_rowconfigure(1, weight=1)
        self.hmac_key_entry = ctk.CTkEntry(tab, placeholder_text="Secret Key")
        self.hmac_key_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.hmac_message_box = ctk.CTkTextbox(tab, wrap="word")
        self.hmac_message_box.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        generate_btn = ctk.CTkButton(tab, text="Generate HMAC", command=self.generate_hmac_hash)
        generate_btn.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

    def create_base64_widgets(self):
        tab = self.tab_view.tab("Base64")
        tab.grid_rowconfigure((1,3), weight=1)
        ctk.CTkLabel(tab, text="Plain Text").grid(row=0, column=0, sticky="w", padx=10)
        self.base64_plain_box = ctk.CTkTextbox(tab, wrap="word")
        self.base64_plain_box.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.base64_plain_box.bind("<KeyRelease>", self.encode_base64)
        ctk.CTkLabel(tab, text="Base64 Encoded").grid(row=2, column=0, sticky="w", padx=10)
        self.base64_encoded_box = ctk.CTkTextbox(tab, wrap="word")
        self.base64_encoded_box.grid(row=3, column=0, padx=10, pady=5, sticky="nsew")
        self.base64_encoded_box.bind("<KeyRelease>", self.decode_base64)
        
    def create_checksum_widgets(self):
        tab = self.tab_view.tab("Checksum")
        tab.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(tab, text="1. Upload Checksum File").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.checksum_file_btn = ctk.CTkButton(tab, text="Select Checksum File", command=self.select_checksum_file)
        self.checksum_file_btn.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        self.checksum_file_label = ctk.CTkLabel(tab, text="No file selected.", text_color="gray60")
        self.checksum_file_label.grid(row=2, column=0, padx=10, sticky="w")
        ctk.CTkLabel(tab, text="2. Select Local Files to Verify").grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.checksum_local_files_btn = ctk.CTkButton(tab, text="Select Local Files", command=self.select_checksum_local_files)
        self.checksum_local_files_btn.grid(row=4, column=0, padx=10, pady=5, sticky="ew")
        self.checksum_local_files_label = ctk.CTkLabel(tab, text="0 files selected.", text_color="gray60")
        self.checksum_local_files_label.grid(row=5, column=0, padx=10, sticky="w")
        self.verify_checksum_btn = ctk.CTkButton(tab, text="Verify Checksum", command=self.verify_checksum, state="disabled")
        self.verify_checksum_btn.grid(row=6, column=0, padx=10, pady=20, sticky="ew")

    def create_password_widgets(self):
        tab = self.tab_view.tab("Password")
        tab.grid_columnconfigure(0, weight=1)
        self.password_entry = ctk.CTkEntry(tab, placeholder_text="Type a password to check its strength")
        self.password_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.password_entry.bind("<KeyRelease>", self.update_password_strength)
        self.password_strength_bar = ctk.CTkProgressBar(tab)
        self.password_strength_bar.set(0)
        self.password_strength_bar.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        self.password_strength_text = ctk.CTkLabel(tab, text="", font=ctk.CTkFont(size=14, weight="bold"))
        self.password_strength_text.grid(row=2, column=0, padx=10, pady=5)
        self.password_feedback_frame = ctk.CTkFrame(tab, fg_color="transparent")
        self.password_feedback_frame.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")
        # Create feedback labels once to be updated later
        self.password_feedback_labels = []
        for _ in range(4):
            label = ctk.CTkLabel(self.password_feedback_frame, text="")
            label.pack(anchor="w")
            self.password_feedback_labels.append(label)

    def create_url_widgets(self):
        tab = self.tab_view.tab("URL")
        tab.grid_rowconfigure((1,3), weight=1)
        ctk.CTkLabel(tab, text="Decoded Text").grid(row=0, column=0, sticky="w", padx=10)
        self.url_decoded_box = ctk.CTkTextbox(tab, wrap="word")
        self.url_decoded_box.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.url_decoded_box.bind("<KeyRelease>", self.encode_url)
        ctk.CTkLabel(tab, text="Encoded Text").grid(row=2, column=0, sticky="w", padx=10)
        self.url_encoded_box = ctk.CTkTextbox(tab, wrap="word")
        self.url_encoded_box.grid(row=3, column=0, padx=10, pady=5, sticky="nsew")
        self.url_encoded_box.bind("<KeyRelease>", self.decode_url)

    # --- Event Handlers and Logic Methods ---

    def select_files(self):
        files = filedialog.askopenfilenames(title="Select up to 10 files")
        if not files: return
        for f in files:
            if f not in self.selected_files and len(self.selected_files) < 10:
                self.selected_files.append(f)
        if len(self.selected_files) >= 10 and len(files) > 0:
            messagebox.showwarning("Limit Reached", "Maximum of 10 files has been reached.")
        self.update_file_list_ui()

    def update_file_list_ui(self):
        for widget in self.file_widgets:
            widget.destroy()
        self.file_widgets.clear()

        for filepath in self.selected_files:
            frame = ctk.CTkFrame(self.file_list_frame)
            frame.pack(fill="x", pady=2, padx=2)
            frame.grid_columnconfigure(0, weight=1)
            
            label = ctk.CTkLabel(frame, text=os.path.basename(filepath), anchor="w")
            label.grid(row=0, column=0, padx=5, sticky="ew")
            
            remove_btn = ctk.CTkButton(frame, text="X", width=30, command=lambda f=filepath: self.remove_file(f), fg_color="#D32F2F", hover_color="#C62828")
            remove_btn.grid(row=0, column=1, padx=5)
            self.file_widgets.append(frame)
        
        self.update_file_buttons_state()

    def remove_file(self, filepath_to_remove):
        self.selected_files.remove(filepath_to_remove)
        self.update_file_list_ui()

    def update_file_buttons_state(self):
        has_files = bool(self.selected_files)
        is_single_file = len(self.selected_files) == 1
        self.generate_file_hash_btn.configure(state="normal" if has_files else "disabled")
        self.verify_hash_btn.configure(state="normal" if is_single_file else "disabled")

    def clear_file_list(self):
        self.selected_files.clear()
        self.update_file_list_ui()

    def run_file_hash_in_thread(self):
        self.generate_file_hash_btn.configure(state="disabled", text="Hashing...")
        self.set_status("Starting file hashing...")
        thread = threading.Thread(target=self.generate_file_hashes)
        thread.daemon = True
        thread.start()

    def generate_file_hashes(self):
        if not self.selected_files: return
        results = []
        algo = self.algo_menu.get()
        total_files = len(self.selected_files)
        for i, f in enumerate(self.selected_files):
            filename = os.path.basename(f)
            self.after(0, self.set_status, f"Hashing file {i+1} of {total_files}: {filename}...")
            file_hash = hash_file(f, algo)
            if file_hash:
                results.append(f"{file_hash} *{filename}")
        self.after(0, self.show_results, "File Hashes", "\n".join(results))
        self.after(0, lambda: self.generate_file_hash_btn.configure(state="normal", text="Generate Hashes"))
        self.after(0, self.set_status, "Ready")

    def verify_file_hash(self):
        if len(self.selected_files) != 1: return
        hash_to_check = self.hash_to_check_entry.get().strip().lower()
        if not hash_to_check:
            messagebox.showerror("Error", "Please paste a hash to verify.")
            return
        filepath = self.selected_files[0]
        algo = self.algo_menu.get()
        self.set_status(f"Verifying {os.path.basename(filepath)}...")
        calculated_hash = hash_file(filepath, algo)
        self.set_status("Ready")
        if calculated_hash:
            result_text = f"Calculated Hash: {calculated_hash}\nProvided Hash:   {hash_to_check}\n\n"
            if calculated_hash.lower() == hash_to_check:
                messagebox.showinfo("Success", result_text + "✅ Hashes match!")
            else:
                messagebox.showerror("Failure", result_text + "❌ Hashes DO NOT match.")

    def generate_text_hash(self):
        text = self.text_to_hash_box.get("0.0", "end-1c")
        if not text: return
        algo = self.algo_menu.get()
        text_hash = hash_text(text, algo)
        if text_hash: self.show_results("Text Hash", text_hash)

    def compare_hashes(self):
        hash1 = self.hash1_box.get("0.0", "end-1c").strip().lower()
        hash2 = self.hash2_box.get("0.0", "end-1c").strip().lower()
        if not hash1 or not hash2:
            messagebox.showerror("Error", "Please provide two hashes to compare.")
            return
        if hash1 == hash2:
            messagebox.showinfo("Success", "✅ Hashes are identical.")
        else:
            messagebox.showerror("Failure", "❌ Hashes are different.")

    def generate_hmac_hash(self):
        key = self.hmac_key_entry.get()
        message = self.hmac_message_box.get("0.0", "end-1c")
        if not key or not message:
            messagebox.showerror("Error", "Key and message cannot be empty.")
            return
        algo = self.algo_menu.get()
        hmac_hash = generate_hmac(key, message, algo)
        if hmac_hash: self.show_results("HMAC Result", hmac_hash)
        
    def encode_base64(self, event=None):
        plain_text = self.base64_plain_box.get("0.0", "end-1c")
        try:
            encoded = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
            current_encoded = self.base64_encoded_box.get("0.0", "end-1c")
            if encoded != current_encoded:
                self.base64_encoded_box.delete("0.0", "end")
                self.base64_encoded_box.insert("0.0", encoded)
        except Exception: pass

    def decode_base64(self, event=None):
        encoded_text = self.base64_encoded_box.get("0.0", "end-1c")
        try:
            decoded = base64.b64decode(encoded_text).decode('utf-8')
            current_plain = self.base64_plain_box.get("0.0", "end-1c")
            if decoded != current_plain:
                self.base64_plain_box.delete("0.0", "end")
                self.base64_plain_box.insert("0.0", decoded)
        except (base64.binascii.Error, UnicodeDecodeError): pass

    def select_checksum_file(self):
        filepath = filedialog.askopenfilename(title="Select checksum file", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filepath:
            self.checksum_file = filepath
            self.checksum_file_label.configure(text=os.path.basename(filepath))
            self.update_checksum_button_state()
            
    def select_checksum_local_files(self):
        files = filedialog.askopenfilenames(title="Select local files to verify")
        if files:
            self.checksum_local_files = files
            self.checksum_local_files_label.configure(text=f"{len(files)} files selected.")
            self.update_checksum_button_state()

    def update_checksum_button_state(self):
        state = "normal" if self.checksum_file and self.checksum_local_files else "disabled"
        self.verify_checksum_btn.configure(state=state)

    def verify_checksum(self):
        try:
            with open(self.checksum_file, 'r') as f:
                checksum_lines = f.readlines()
        except Exception as e:
            messagebox.showerror("Error", f"Could not read checksum file: {e}")
            return
        checksum_map = { ' '.join(line.strip().split()[1:]).lstrip('* '): line.strip().split()[0] for line in checksum_lines if len(line.strip().split()) >= 2 }
        results = []
        for filepath in self.checksum_local_files:
            filename = os.path.basename(filepath)
            if filename not in checksum_map:
                results.append(f"[SKIP] {filename}: Not in checksum file.")
                continue
            expected_hash = checksum_map[filename]
            algo_map = {32: 'md5', 40: 'sha1', 64: 'sha256', 96: 'sha384', 128: 'sha512'}
            algorithm = algo_map.get(len(expected_hash))
            if not algorithm:
                results.append(f"[ERROR] {filename}: Could not determine algorithm.")
                continue
            calculated_hash = hash_file(filepath, algorithm)
            if calculated_hash and calculated_hash.lower() == expected_hash.lower():
                results.append(f"[OK] {filename}")
            else:
                results.append(f"[FAILED] {filename}")
        self.show_results("Checksum Verification", "\n".join(results))

    def update_password_strength(self, event=None):
        password = self.password_entry.get()
        score = 0
        feedback = []
        if not password:
            self.password_strength_bar.set(0)
            self.password_strength_text.configure(text="")
            for label in self.password_feedback_labels: label.configure(text="")
            return
        if len(password) >= 8: score += 1; feedback.append(("✅ At least 8 characters", "#4CAF50"))
        else: feedback.append(("❌ Less than 8 characters", "#F44336"))
        if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password): score += 1; feedback.append(("✅ Mix of uppercase and lowercase", "#4CAF50"))
        else: feedback.append(("❌ Missing case mix", "#F44336"))
        if re.search(r"\d", password): score += 1; feedback.append(("✅ Contains numbers", "#4CAF50"))
        else: feedback.append(("❌ No numbers", "#F44336"))
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 1; feedback.append(("✅ Contains symbols", "#4CAF50"))
        else: feedback.append(("❌ No symbols", "#F44336"))
        if len(password) >= 12: score += 1
        strength_map = {
            0: ("Very Weak", 0.1, "#F44336"), 1: ("Weak", 0.25, "#FF9800"),
            2: ("Moderate", 0.5, "#FFC107"), 3: ("Strong", 0.75, "#8BC34A"),
            4: ("Very Strong", 1.0, "#4CAF50"), 5: ("Excellent", 1.0, "#4CAF50"),
        }
        strength_text, bar_value, color = strength_map.get(score, ("Unknown", 0, "gray"))
        self.password_strength_bar.set(bar_value)
        self.password_strength_bar.configure(progress_color=color)
        self.password_strength_text.configure(text=strength_text, text_color=color)
        for i, label in enumerate(self.password_feedback_labels):
            if i < len(feedback):
                text, color = feedback[i]
                label.configure(text=text, text_color=color)
            else:
                label.configure(text="")

    def encode_url(self, event=None):
        decoded_text = self.url_decoded_box.get("0.0", "end-1c")
        try:
            encoded = quote(decoded_text)
            current_encoded = self.url_encoded_box.get("0.0", "end-1c")
            if encoded != current_encoded:
                self.url_encoded_box.delete("0.0", "end")
                self.url_encoded_box.insert("0.0", encoded)
        except Exception: pass

    def decode_url(self, event=None):
        encoded_text = self.url_encoded_box.get("0.0", "end-1c")
        try:
            decoded = unquote(encoded_text)
            current_decoded = self.url_decoded_box.get("0.0", "end-1c")
            if decoded != current_decoded:
                self.url_decoded_box.delete("0.0", "end")
                self.url_decoded_box.insert("0.0", decoded)
        except Exception: pass

    def show_results(self, title, content):
        result_window = ctk.CTkToplevel(self)
        result_window.title(title)
        result_window.geometry("600x400")
        result_window.grid_columnconfigure(0, weight=1)
        result_window.grid_rowconfigure(0, weight=1)
        
        textbox = ctk.CTkTextbox(result_window, wrap="word")
        textbox.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        textbox.insert("0.0", content)
        textbox.configure(state="disabled")
        
        copy_btn = ctk.CTkButton(result_window, text="Copy to Clipboard", command=lambda: self.copy_to_clipboard(content))
        copy_btn.grid(row=1, column=0, padx=10, pady=10)

        result_window.transient(self)
        result_window.grab_set()
        self.wait_window(result_window)
    
    def copy_to_clipboard(self, content):
        try:
            pyperclip.copy(content)
            self.set_status("Results copied to clipboard.")
        except pyperclip.PyperclipException:
            messagebox.showwarning("Copy Error", "Could not copy to clipboard. Make sure you have xclip or xsel installed on Linux.")


if __name__ == "__main__":
    app = App()
    app.mainloop()

