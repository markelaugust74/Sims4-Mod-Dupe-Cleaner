import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from send2trash import send2trash
from concurrent.futures import ThreadPoolExecutor, as_completed

class DuplicateFileFinder:
    def __init__(self, root):
        self.root = root
        self.root.title("TS4 Duplicate File Finder")
        self.root.geometry("1000x600")
        
        self.size_unit = tk.StringVar(value="KB")
        
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
        
        self.unit_label = tk.Label(self.frame, text="Size Unit:")
        self.unit_label.grid(row=0, column=3, padx=5, pady=5)
        
        self.unit_combobox = ttk.Combobox(self.frame, textvariable=self.size_unit, values=["KB", "MB", "GB"])
        self.unit_combobox.grid(row=0, column=4, padx=5, pady=5)
        self.unit_combobox.bind("<<ComboboxSelected>>", self.update_size_unit)
        
        self.tree = ttk.Treeview(self.frame, columns=("Path", "Hash", "Size"), show="headings")
        self.tree.heading("Path", text="File Path")
        self.tree.heading("Hash", text="File Hash")
        self.tree.heading("Size", text="File Size")
        self.tree.column("Path", width=500)
        self.tree.column("Hash", width=200)
        self.tree.column("Size", width=100)
        self.tree.grid(row=2, column=0, columnspan=5, sticky="nsew")
        
        self.scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=self.scrollbar.set)
        self.scrollbar.grid(row=2, column=5, sticky="ns")
        
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
        files_to_process = []

        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                files_to_process.append(file_path)
        
        with ThreadPoolExecutor(max_workers=16) as executor:
            future_to_file = {executor.submit(self.calculate_hash, file_path): file_path for file_path in files_to_process}
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_hash = future.result()
                    file_size = os.path.getsize(file_path)
                    if file_hash in file_hashes:
                        file_hashes[file_hash].append((file_path, file_size))
                    else:
                        file_hashes[file_hash] = [(file_path, file_size)]
                except Exception as exc:
                    print(f'{file_path} generated an exception: {exc}')
        
        for file_hash, paths in file_hashes.items():
            if len(paths) > 1:
                for path, size in paths:
                    self.tree.insert("", tk.END, values=(path, file_hash, self.format_size(size)))
        
        messagebox.showinfo("Scan Complete", "Duplicate scan complete!")
    
    def calculate_hash(self, file_path, chunk_size=1024*1024*16):
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
        total_freed_size = 0
        
        for item in selected_items:
            file_path, file_hash, file_size = self.tree.item(item)["values"]
            file_size = self.convert_size_to_bytes(file_size)
            if file_hash not in duplicates:
                duplicates[file_hash] = file_path
            else:
                send2trash(file_path)
                total_freed_size += file_size
                self.tree.delete(item)
        
        total_freed_size = self.format_size(total_freed_size)
        messagebox.showinfo("Deletion Complete", f"Duplicate files moved to trash! Freed up {total_freed_size}.")
    
    def select_all(self):
        for item in self.tree.get_children():
            self.tree.selection_add(item)
    
    def deselect_all(self):
        for item in self.tree.selection():
            self.tree.selection_remove(item)
    
    def update_size_unit(self, event):
        for item in self.tree.get_children():
            path, file_hash, file_size = self.tree.item(item)["values"]
            file_size = self.convert_size_to_bytes(file_size)
            new_size = self.format_size(file_size)
            self.tree.item(item, values=(path, file_hash, new_size))
    
    def format_size(self, size):
        unit = self.size_unit.get()
        if unit == "MB":
            return f"{size / (1024 ** 2):.2f} MB"
        elif unit == "GB":
            return f"{size / (1024 ** 3):.2f} GB"
        else:
            return f"{size / 1024:.2f} KB"
    
    def convert_size_to_bytes(self, size_str):
        size, unit = size_str.split()
        size = float(size)
        if unit == "MB":
            return size * (1024 ** 2)
        elif unit == "GB":
            return size * (1024 ** 3)
        else:
            return size * 1024
    
if __name__ == "__main__":
    root = tk.Tk()
    app = DuplicateFileFinder(root)
    root.mainloop()
