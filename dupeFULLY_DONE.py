import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from send2trash import send2trash

class DuplicateFileFinder:
    def __init__(self, root):
        self.root = root
        self.root.title("Duplicate File Finder")
        self.root.geometry("900x600")
        
        self.setup_ui()
        
    def setup_ui(self):
        self.frame = tk.Frame(self.root)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.path_label = tk.Label(self.frame, text="Select Directory:")
        self.path_label.grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.path_entry = tk.Entry(self.frame, width=50)
        self.path_entry.grid(row=0, column=1, padx=5, pady=5)
        
        self.browse_button = tk.Button(self.frame, text="Browse", command=self.browse_directory)
        self.browse_button.grid(row=0, column=2, padx=5, pady=5)
        
        self.scan_button = tk.Button(self.frame, text="Scan for Duplicates", command=self.scan_duplicates)
        self.scan_button.grid(row=1, column=1, pady=10)
        
        self.tree = ttk.Treeview(self.frame, columns=("Path", "Hash"), show="headings")
        self.tree.heading("Path", text="File Path")
        self.tree.heading("Hash", text="File Hash")
        self.tree.column("Path", width=600)
        self.tree.column("Hash", width=200)
        self.tree.grid(row=2, column=0, columnspan=4, sticky="nsew")
        
        self.scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=self.scrollbar.set)
        self.scrollbar.grid(row=2, column=4, sticky="ns")
        
        self.show_button = tk.Button(self.frame, text="Show in Folder", command=self.show_in_folder)
        self.show_button.grid(row=3, column=0, pady=10)
        
        self.delete_button = tk.Button(self.frame, text="Delete Duplicates", command=self.delete_duplicates)
        self.delete_button.grid(row=3, column=1, pady=10)
        
        self.select_all_button = tk.Button(self.frame, text="Select All", command=self.select_all)
        self.select_all_button.grid(row=3, column=2, pady=10)
        
        self.deselect_all_button = tk.Button(self.frame, text="Deselect All", command=self.deselect_all)
        self.deselect_all_button.grid(row=3, column=3, pady=10)
        
    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, directory)
    
    def scan_duplicates(self):
        directory = self.path_entry.get()
        if not os.path.isdir(directory):
            messagebox.showerror("Error", "Invalid directory")
            return
        
        self.tree.delete(*self.tree.get_children())
        file_hashes = {}
        
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = self.calculate_hash(file_path)
                if file_hash in file_hashes:
                    file_hashes[file_hash].append(file_path)
                else:
                    file_hashes[file_hash] = [file_path]
        
        for file_hash, paths in file_hashes.items():
            if len(paths) > 1:
                for path in paths:
                    self.tree.insert("", tk.END, values=(path, file_hash))
        
        messagebox.showinfo("Scan Complete", "Duplicate scan complete!")
    
    def calculate_hash(self, file_path, chunk_size=1024*1024):
        hash_alg = hashlib.sha256()
        with open(file_path, "rb") as file:
            while chunk := file.read(chunk_size):
                hash_alg.update(chunk)
        return hash_alg.hexdigest()
    
    def show_in_folder(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "No file selected")
            return
        
        file_path = self.tree.item(selected_item[0])["values"][0]
        os.startfile(os.path.dirname(file_path))
        
    def delete_duplicates(self):
        selected_items = self.tree.selection()
        duplicates = {}
        
        for item in selected_items:
            file_path, file_hash = self.tree.item(item)["values"]
            if file_hash not in duplicates:
                duplicates[file_hash] = file_path
            else:
                send2trash(file_path)
                self.tree.delete(item)
        
        messagebox.showinfo("Deletion Complete", "Duplicate files moved to trash!")
    
    def select_all(self):
        for item in self.tree.get_children():
            self.tree.selection_add(item)
    
    def deselect_all(self):
        for item in self.tree.selection():
            self.tree.selection_remove(item)
        
if __name__ == "__main__":
    root = tk.Tk()
    app = DuplicateFileFinder(root)
    root.mainloop()
