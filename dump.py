import tkinter as tk
from tkinter import ttk
import subprocess
from threading import Thread
from datetime import datetime

class KddFeatureExtractorGUI:
    def __init__(self, root: tk.Tk):
        self.col_width = 175
        self.root = root
        self.root.geometry()
        self.root.title("KDD Feature Extractor")

        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.scrollbar = ttk.Scrollbar(self.main_frame, orient="vertical")
        self.scrollbar.pack(side="right", fill="y")
        self.style = ttk.Style()
        self.style.configure('Treeview',rowheight=25)
        self.treeview = ttk.Treeview(self.main_frame, show=['headings'], yscrollcommand=self.scrollbar.set)
        self.treeview["columns"] = ["Time", "Source IP", "Source port", "Destination IP", "Destination port", "Label"]
        
        for col in self.treeview["columns"]:
            self.treeview.heading(col, text=col)
            self.treeview.column(col, minwidth=self.col_width, anchor="center")
            
        self.treeview.pack(fill=tk.BOTH, expand=True)
        self.treeview.tag_configure('oddrow', background="white")
        self.treeview.tag_configure('evenrow', background="lightblue")
        
        self.scrollbar.config(command=self.treeview.yview)
        
        self.root.minsize(self.col_width*len(self.treeview["columns"]), 600)
        
        self.kdd_feature_extractor = subprocess.Popen(['./kdd99extractor', '-e'], stdout=subprocess.PIPE, universal_newlines=True)
        self.root.protocol("WM_DELETE_WINDOW", self.close_window)
        self.thread = Thread(target=self.update_gui)
        self.thread.start()

    def update_gui(self):
        
        count = 0
        while True:
            output = self.kdd_feature_extractor.stdout.readline().strip()
            if not output:
                break
            tag = 'evenrow' if count%2 ==0 else 'oddrow'
            count += 1
            # Splitting the output and getting the last four elements
            data = output.split(',')[-5:]
            data.insert(0, data.pop(-1))
            
            datetime_obj = datetime.fromisoformat(data[0])
            data[0] = datetime_obj.strftime("%Y-%m-%d %I:%M:%S %p")

            # Inserting the data into the treeview
            self.treeview.insert("", "end", values=data, tags=(tag,))

            self.treeview.yview_moveto(1)
            self.root.update_idletasks()

    def close_window(self):
        self.kdd_feature_extractor.kill()  # Kill the subprocess
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = KddFeatureExtractorGUI(root)
    root.mainloop()
