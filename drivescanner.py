import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import platform
import ctypes
import subprocess

class TextRedirector:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, str):
        self.text_widget.after(0, self.text_widget.insert, tk.END, str)
        self.text_widget.after(0, self.text_widget.see, tk.END)

    def flush(self):
        pass

class FolderSizeScanner(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ryan's UltraFast Scanner")


        # Check for admin rights before proceeding
        if not self.is_admin():
            self.request_admin_rights()
            sys.exit(0)  # Exit the non-admin process after requesting admin rights

        # Variables
        self.drive_var = tk.StringVar()
        self.stop_scan = threading.Event()
        self.scan_thread = None
        self.folder_sizes = {}
        self.updating = False
        self.total_drive_size = 0
        self.free_space = 0

        # Set the background color of the main window
        self.configure(bg='white')  # Set to 'white' or any preferred color

        # Main window setup
        self.title("Ryan's UltraFast Scanner")
        self.geometry("1200x700")  # Adjusted for extra space

        # Set the theme for the main window
        style = ttk.Style()
        style.theme_use('clam')

        # Customize styles for widgets
        style.configure('TButton', font=('Arial', 10), relief='raised', padding=5)
        style.configure('TCombobox', padding=5)
        style.configure('Treeview.Heading', font=('Arial', 10, 'bold'))
        style.configure('Treeview', font=('Arial', 10))

        # Create the menu bar
        self.create_menu()

        # Create Widgets
        self.create_widgets()

        # Redirect stdout and stderr
        sys.stdout = TextRedirector(self.log_text)
        sys.stderr = TextRedirector(self.log_text)

        # Bind right-click event to the treeview
        self.tree.bind("<Button-3>", self.show_context_menu)

    def create_menu(self):
        menubar = tk.Menu(self)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def show_about(self):
        messagebox.showinfo("About", "Simple and fast folder scanner by Ryan")

    def create_widgets(self):
        # Create a frame to hold the widgets and set background to match main window
        main_frame = tk.Frame(self, bg='white')
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Top frame for drive selection and info
        top_frame = tk.Frame(main_frame, bg='white')
        top_frame.pack(fill=tk.X, padx=10, pady=10)

        # Drive selection dropdown
        drive_label = ttk.Label(top_frame, text="Select Drive:", font=('Arial', 12), background='white')
        drive_label.pack(side=tk.LEFT, pady=5)

        self.drive_combobox = ttk.Combobox(top_frame, textvariable=self.drive_var, state='readonly', font=('Arial', 12))
        self.drive_combobox['values'] = self.get_drives()
        self.drive_combobox.pack(side=tk.LEFT, pady=5, padx=5)

        # Buttons
        self.scan_button = ttk.Button(top_frame, text="Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(top_frame, text="Stop", command=self.stop_scan_thread, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Drive info (free space and total size)
        drive_info_frame = tk.Frame(top_frame, bg='white')
        drive_info_frame.pack(side=tk.RIGHT, padx=10)

        self.drive_info_label = tk.Label(drive_info_frame, text="", font=('Arial', 16), bg='white', anchor='e', justify='left')
        self.drive_info_label.pack()

        # Results treeview
        tree_frame = tk.Frame(main_frame, bg='white')
        tree_frame.pack(expand=True, fill=tk.BOTH, pady=5, padx=10)

        columns = ('Folder', 'Size', 'Percentage')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        self.tree.heading('Folder', text='Folder')
        self.tree.heading('Size', text='Size')
        self.tree.heading('Percentage', text='Percentage')
        self.tree.column('Folder', width=500)
        self.tree.column('Size', width=150, anchor=tk.E)
        self.tree.column('Percentage', width=100, anchor=tk.E)

        # Scrollbar for treeview
        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.configure(yscrollcommand=y_scroll.set)
        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        # Log messages text box
        log_frame = tk.Frame(main_frame, bg='white')
        log_frame.pack(fill=tk.BOTH, padx=10, pady=(0, 10))

        log_label = ttk.Label(log_frame, text="Logs:", background='white')
        log_label.pack(anchor='w')

        self.log_text = tk.Text(log_frame, height=10, font=('Arial', 10))
        self.log_text.pack(expand=True, fill=tk.BOTH)

        # Create the context menu
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Open Here in Windows Explorer", command=self.open_in_explorer)
        self.context_menu.add_command(label="Delete...", command=self.delete_folder)

    def get_drives(self):
        drives = []
        system = platform.system()
        if system == "Windows":
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                if bitmask & 1:
                    drives.append(f"{letter}:\\")
                bitmask >>= 1
        else:
            # On Unix-based systems, list root and mounted volumes
            drives.append("/")
        return drives

    def get_drive_size(self, drive):
        system = platform.system()
        try:
            if system == "Windows":
                free_bytes = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                total_free_bytes = ctypes.c_ulonglong(0)
                ret = ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p(drive),
                    ctypes.byref(free_bytes),
                    ctypes.byref(total_bytes),
                    ctypes.byref(total_free_bytes)
                )
                if ret == 0:
                    raise ctypes.WinError()
                used_bytes = total_bytes.value - total_free_bytes.value
                self.free_space = total_free_bytes.value
                self.total_drive_size = total_bytes.value
                return used_bytes
            else:
                statvfs = os.statvfs(drive)
                used_bytes = (statvfs.f_blocks - statvfs.f_bfree) * statvfs.f_frsize
                self.free_space = statvfs.f_bavail * statvfs.f_frsize
                self.total_drive_size = statvfs.f_blocks * statvfs.f_frsize
                return used_bytes
        except Exception as e:
            messagebox.showerror("Error", f"Unable to get drive size: {e}")
            return None

    def start_scan(self):
        drive = self.drive_var.get()
        if not drive:
            messagebox.showwarning("No Drive Selected", "Please select a drive to scan.")
            return

        used_space = self.get_drive_size(drive)
        if used_space is None:
            return

        # Update drive info label
        total_size_formatted = self.format_size(self.total_drive_size)
        free_space_formatted = self.format_size(self.free_space)
        drive_info_text = f"Total Size: {total_size_formatted}\nFree Space: {free_space_formatted}"
        self.drive_info_label.config(text=drive_info_text)

        # Store the root path
        self.root_path = os.path.abspath(drive)

        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.tree.delete(*self.tree.get_children())
        self.log_text.delete('1.0', tk.END)
        self.stop_scan.clear()
        self.folder_sizes = {}

        # Start the scanning thread
        self.scan_thread = threading.Thread(target=self.scan_folder, args=(drive,))
        self.scan_thread.start()

        # Start checking if the thread is alive
        self.check_scan_thread()

    def stop_scan_thread(self):
        self.stop_scan.set()
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def check_scan_thread(self):
        if self.scan_thread.is_alive():
            self.after(1000, self.check_scan_thread)
            self.update_results()
        else:
            self.update_results(final=True)
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def update_results(self, final=False):
        # Update the tree with current results
        if self.updating:
            return
        self.updating = True

        sorted_folders = sorted(self.folder_sizes.items(), key=lambda x: x[1], reverse=True)
        self.tree.delete(*self.tree.get_children())

        if not sorted_folders:
            self.updating = False
            print("No folders to display.")
            return

        for folder, size in sorted_folders:
            size_formatted = self.format_size(size)
            percentage = (size / self.total_drive_size) * 100 if self.total_drive_size else 0
            self.tree.insert('', tk.END, values=(
                folder,
                size_formatted,
                f"{percentage:.4f}%"
            ))

        # Add free space as a row
        free_space_formatted = self.format_size(self.free_space)
        free_space_percentage = (self.free_space / self.total_drive_size) * 100 if self.total_drive_size else 0
        self.tree.insert('', tk.END, values=(
            'Free Space',
            free_space_formatted,
            f"{free_space_percentage:.4f}%"
            
        ))

        self.updating = False

    def format_size(self, size_in_bytes):
        units = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB']
        size = float(size_in_bytes)
        for unit in units:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"

    def scan_folder(self, folder_path):
        try:
            total_folders = 0
            stack = [folder_path]
            while stack:
                current_folder = stack.pop()
                if self.stop_scan.is_set():
                    break
                folder_size = 0
                try:
                    with os.scandir(current_folder) as entries:
                        for entry in entries:
                            if self.stop_scan.is_set():
                                break
                            if entry.is_file(follow_symlinks=False):
                                try:
                                    folder_size += entry.stat(follow_symlinks=False).st_size
                                except Exception as e:
                                    print(f"Error getting size of {entry.path}: {e}")
                            elif entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                except Exception as e:
                    print(f"Error scanning {current_folder}: {e}")
                self.folder_sizes[current_folder] = folder_size
                total_folders += 1
                if total_folders % 100 == 0:
                    print(f"Scanned {total_folders} folders...")
            print(f"Total folders scanned: {total_folders}")
        except Exception as e:
            print(f"Exception in scan_folder: {e}")

    def on_error(self, err):
        print(f"Error: {err}")

    def is_admin(self):
        try:
            if os.name == 'nt':
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except Exception as e:
            print(f"Admin check failed: {e}")
            return False

    def request_admin_rights(self):
        if os.name == 'nt':
            # Windows
            try:
                # Build command line arguments
                params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
                # Run the script with admin rights
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, f'"{sys.argv[0]}" {params}', None, 1)
            except Exception as e:
                messagebox.showerror("Error", f"Unable to elevate privileges: {e}")
                sys.exit(1)  # Exit if unable to elevate
        else:
            # Unix/Linux/Mac
            try:
                subprocess.call(['sudo', sys.executable] + sys.argv)
            except Exception as e:
                messagebox.showerror("Error", f"Unable to elevate privileges: {e}")
                sys.exit(1)  # Exit if unable to elevate

    def show_context_menu(self, event):
        # Get the item under the cursor
        item_id = self.tree.identify_row(event.y)
        if item_id:
            self.tree.selection_set(item_id)
            self.context_menu.post(event.x_root, event.y_root)

    def open_in_explorer(self):
        # Get selected item
        selected_item = self.tree.selection()
        if selected_item:
            folder = self.tree.item(selected_item, 'values')[0]
            if folder == 'Free Space':
                messagebox.showinfo("Info", "Cannot open Free Space in Explorer.")
                return
            try:
                if platform.system() == "Windows":
                    os.startfile(folder)
                else:
                    subprocess.Popen(['xdg-open', folder])
            except Exception as e:
                messagebox.showerror("Error", f"Unable to open folder: {e}")

    def delete_folder(self):
        # Get selected item
        selected_item = self.tree.selection()
        if selected_item:
            folder = self.tree.item(selected_item, 'values')[0]
            if folder == 'Free Space':
                messagebox.showinfo("Info", "Cannot delete Free Space.")
                return
            # Show confirmation dialog
            dialog = tk.Toplevel(self)
            dialog.title("Confirmation")
            dialog.geometry("300x150")
            dialog.resizable(False, False)
            dialog.transient(self)
            dialog.grab_set()

            label = tk.Label(dialog, text=f"Are you sure you want to delete?\n{folder}", wraplength=280)
            label.pack(pady=10)

            button_frame = tk.Frame(dialog)
            button_frame.pack(pady=10)

            yes_button = tk.Button(button_frame, text="Yes", state=tk.DISABLED, command=lambda: self.confirm_delete(folder, dialog))
            yes_button.pack(side=tk.LEFT, padx=5)

            no_button = tk.Button(button_frame, text="No", command=dialog.destroy)
            no_button.pack(side=tk.LEFT, padx=5)

            # Enable the Yes button after 3 seconds
            self.after(3000, lambda: yes_button.config(state=tk.NORMAL))

    def confirm_delete(self, folder, dialog):
        dialog.destroy()
        try:
            if os.path.isdir(folder):
                # Use send2trash for safer deletion (requires 'send2trash' package)
                # import send2trash
                # send2trash.send2trash(folder)
                # For permanent deletion:
                import shutil
                shutil.rmtree(folder)
                messagebox.showinfo("Deleted", f"Folder deleted:\n{folder}")
                # Remove the folder from the results
                self.folder_sizes.pop(folder, None)
                self.update_results()
            else:
                messagebox.showerror("Error", f"Folder does not exist:\n{folder}")
        except Exception as e:
            messagebox.showerror("Error", f"Unable to delete folder:\n{folder}\nError: {e}")

if __name__ == "__main__":
    app = FolderSizeScanner()
    app.mainloop()
