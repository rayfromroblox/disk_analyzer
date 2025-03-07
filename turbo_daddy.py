import os
import threading
from heapq import heappush, heappop, heappushpop
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed

def human_size(size):
    """Convert bytes to human-readable format."""
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"  # Fallback for very large sizes

class Scanner:
    def __init__(self, root_dir, top_n=10):
        """Initialize the Scanner with directory and top N settings."""
        self.root_dir = root_dir
        self.top_n = top_n
        self.heap = []  # Min-heap to store top N largest files
        self.lock = threading.Lock()
        self.total_files = 0
        self.bytes_scanned = 0  # Total size of all scanned files
        self.stop_event = threading.Event()
        self.count_batch_size = 10000  # Batch size for updating counts
        self.futures = []  # Store futures for cancellation
        
        # Optimized worker count: twice the CPU cores, max 32, min 4
        worker_count = min(32, os.cpu_count() * 2 or 4)
        self.executor = ThreadPoolExecutor(max_workers=worker_count, 
                                           thread_name_prefix="scanner")

    def scan_dir(self, dirpath):
        """Scan a directory recursively, maintaining a local heap of top N files."""
        local_heap = []  # Local min-heap to limit memory usage per thread
        local_count = 0
        local_bytes = 0
        stack = [dirpath]  # DFS stack for directory traversal

        while stack and not self.stop_event.is_set():
            current_dir = stack.pop()
            try:
                # Use os.scandir for efficient directory iteration
                with os.scandir(current_dir) as it:
                    for entry in it:
                        if self.stop_event.is_set():
                            return
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                stat = entry.stat(follow_symlinks=False)
                                size = stat.st_size
                                
                                # Maintain top N files in local heap
                                if len(local_heap) < self.top_n:
                                    heappush(local_heap, (size, entry.path))
                                elif size > local_heap[0][0]:
                                    heappushpop(local_heap, (size, entry.path))
                                    
                                local_count += 1
                                local_bytes += size

                                # Update counts in batches to reduce lock contention
                                if local_count >= self.count_batch_size:
                                    self._update_count(local_count, local_bytes)
                                    local_count = 0
                                    local_bytes = 0
                        except (OSError, PermissionError):
                            continue  # Skip inaccessible files
            except (OSError, PermissionError):
                continue  # Skip inaccessible directories

        # Process remaining items
        self._process_batch(local_heap)
        self._update_count(local_count, local_bytes)

    def _process_batch(self, batch):
        """Merge local heap into global heap efficiently."""
        if not batch:
            return
            
        # Optimize by pre-sorting only if necessary
        if len(batch) > self.top_n:
            batch.sort(reverse=True)
            batch = batch[:self.top_n]
            
        with self.lock:
            for size, path in batch:
                if len(self.heap) < self.top_n:
                    heappush(self.heap, (size, path))
                elif size > self.heap[0][0]:
                    heappop(self.heap)
                    heappush(self.heap, (size, path))

    def _update_count(self, count, bytes_scanned):
        """Update total files and bytes scanned with thread safety."""
        if count == 0:
            return
        with self.lock:
            self.total_files += count
            self.bytes_scanned += bytes_scanned

    def start_scan(self):
        """Start scanning the root directory and its subdirectories."""
        if not os.path.exists(self.root_dir):
            return
            
        top_dirs = []
        try:
            with os.scandir(self.root_dir) as it:
                top_dirs = [entry.path for entry in it if entry.is_dir(follow_symlinks=False)]
        except OSError:
            top_dirs = [self.root_dir]  # Fallback to scanning root

        if not top_dirs:
            top_dirs = [self.root_dir]  # Scan root if no subdirs

        self.futures = [self.executor.submit(self.scan_dir, dirpath) for dirpath in top_dirs]

    def is_scan_complete(self):
        """Check if all scanning tasks are complete."""
        return all(future.done() for future in self.futures)

class App:
    def __init__(self, master):
        """Initialize the GUI application."""
        self.master = master
        master.title("Disk Space Analyzer")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Directory selection
        self.dir_label = ttk.Label(master, text="Directory to scan:")
        self.dir_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        self.dir_entry = ttk.Entry(master, width=50)
        self.dir_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        self.browse_button = ttk.Button(master, text="Browse", command=self.browse_dir)
        self.browse_button.grid(row=0, column=2, padx=5, pady=5)

        # Top N selection
        self.n_label = ttk.Label(master, text="Number of top files:")
        self.n_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        self.n_spinbox = ttk.Spinbox(master, from_=1, to=100, width=5)
        self.n_spinbox.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        self.n_spinbox.set("10")

        # Control buttons
        self.button_frame = ttk.Frame(master)
        self.button_frame.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        
        self.start_button = ttk.Button(self.button_frame, text="Start Scan", command=self.start_scan)
        self.start_button.pack(side=LEFT, padx=5)
        
        self.cancel_button = ttk.Button(self.button_frame, text="Cancel", command=self.cancel_scan, state=DISABLED)
        self.cancel_button.pack(side=LEFT, padx=5)
        
        self.export_button = ttk.Button(self.button_frame, text="Export Results", command=self.export_results, state=DISABLED)
        self.export_button.pack(side=LEFT, padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(master, orient="horizontal", mode="indeterminate", length=200)
        self.progress.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky="ew")

        # Results table
        self.tree_frame = ttk.Frame(master)
        self.tree_frame.grid(row=4, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")
        
        self.vsb = ttk.Scrollbar(self.tree_frame, orient="vertical")
        self.hsb = ttk.Scrollbar(self.tree_frame, orient="horizontal")
        
        self.tree = ttk.Treeview(self.tree_frame, columns=("Path", "Size"), show="headings",
                                 yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)
        
        self.vsb.config(command=self.tree.yview)
        self.hsb.config(command=self.tree.xview)
        
        self.tree.heading("Path", text="File Path")
        self.tree.heading("Size", text="Size")
        self.tree.column("Path", width=400, minwidth=200)
        self.tree.column("Size", width=100, minwidth=80)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.vsb.grid(row=0, column=1, sticky="ns")
        self.hsb.grid(row=1, column=0, sticky="ew")
        
        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<Double-1>", self.open_file_location)

        # Status bar
        self.status_frame = ttk.Frame(master, relief=SUNKEN)
        self.status_frame.grid(row=5, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        
        self.status_label = ttk.Label(self.status_frame, text="Ready", anchor=W)
        self.status_label.pack(side=LEFT, fill=X, expand=True, padx=5)

        # Layout configuration
        master.grid_rowconfigure(4, weight=1)
        master.grid_columnconfigure(1, weight=1)
        master.minsize(600, 400)

        self.scanner = None
        self.update_id = None

    def browse_dir(self):
        """Open a directory selection dialog."""
        dirpath = filedialog.askdirectory()
        if dirpath:
            self.dir_entry.delete(0, "end")
            self.dir_entry.insert(0, dirpath)

    def start_scan(self):
        """Initiate the directory scan."""
        dirpath = self.dir_entry.get()
        if not os.path.exists(dirpath):
            messagebox.showerror("Error", "Invalid directory")
            return
            
        try:
            top_n = int(self.n_spinbox.get())
            if top_n < 1 or top_n > 1000:
                messagebox.showerror("Error", "Number of files must be between 1 and 1000")
                return
        except ValueError:
            messagebox.showerror("Error", "Invalid number")
            return
            
        self.scanner = Scanner(dirpath, top_n)
        self.scanner.start_scan()
        self.start_button.config(state=DISABLED)
        self.cancel_button.config(state=NORMAL)
        self.export_button.config(state=DISABLED)
        self.status_label.config(text="Scanning...")
        self.progress.start()
        self.update_ui()

    def cancel_scan(self):
        """Cancel the ongoing scan."""
        if self.scanner:
            self.scanner.stop_event.set()
            for future in self.scanner.futures:
                if not future.done():
                    future.cancel()
            self.scanner.executor.shutdown(wait=False)
            
        self.start_button.config(state=NORMAL)
        self.cancel_button.config(state=DISABLED)
        self.status_label.config(text="Scan canceled")
        self.progress.stop()
        
        if self.update_id:
            self.master.after_cancel(self.update_id)

    def update_ui(self):
        """Update the GUI with scan progress and results."""
        if self.scanner and not self.scanner.is_scan_complete():
            with self.scanner.lock:
                heap_copy = list(self.scanner.heap)
                total_files = self.scanner.total_files
                bytes_scanned = self.scanner.bytes_scanned

            sorted_files = sorted(heap_copy, key=lambda x: x[0], reverse=True)
            self.tree.delete(*self.tree.get_children())
            for size, path in sorted_files:
                self.tree.insert("", "end", values=(path, human_size(size)))
                    
            self.status_label.config(text=f"Scanned {total_files:,} files ({human_size(bytes_scanned)})...")
            self.update_id = self.master.after(500, self.update_ui)
        else:
            if self.scanner:
                with self.scanner.lock:
                    top_files = sorted(self.scanner.heap, key=lambda x: x[0], reverse=True)
                    
                self.tree.delete(*self.tree.get_children())
                for size, path in top_files:
                    if os.path.exists(path):
                        self.tree.insert("", "end", values=(path, human_size(size)))
                        
                self.status_label.config(text=f"Scan complete. Found {self.scanner.total_files:,} files.")
                    
            self.start_button.config(state=NORMAL)
            self.cancel_button.config(state=DISABLED)
            self.export_button.config(state=NORMAL)
            self.progress.stop()

    def open_file_location(self, event):
        """Open the directory of the selected file in Explorer."""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            path = item["values"][0]
            dir_path = os.path.dirname(path)
            try:
                if os.path.exists(dir_path):
                    os.startfile(dir_path)
                else:
                    messagebox.showwarning("Directory not found", "The directory no longer exists.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not open directory: {e}")

    def export_results(self):
        """Export scan results to a text file."""
        if not self.scanner or not self.scanner.heap:
            messagebox.showwarning("No Data", "No scan results to export.")
            return
            
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Results As"
        )
        if not filepath:
            return
            
        try:
            with self.scanner.lock:
                sorted_files = sorted(self.scanner.heap, key=lambda x: x[0], reverse=True)

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"Top {len(sorted_files)} Largest Files:\n")
                f.write("="*50 + "\n")
                for idx, (size, path) in enumerate(sorted_files, 1):
                    f.write(f"{idx}. {human_size(size)}: {path}\n")
                    
                f.write("\nScan Summary:\n")
                f.write(f"Total Files Scanned: {self.scanner.total_files:,}\n")
                f.write(f"Total Bytes Scanned: {human_size(self.scanner.bytes_scanned)}\n")
            
            messagebox.showinfo("Export Successful", f"Results exported to:\n{filepath}")
        except PermissionError:
            messagebox.showerror("Permission Denied", "Please choose a different location.")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Error exporting results:\n{str(e)}")

if __name__ == "__main__":
    root = Tk()
    app = App(root)
    root.mainloop()