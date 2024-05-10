import tkinter as tk
from tkinter import ttk
import subprocess
from threading import Thread
from datetime import datetime
from predictor import SignatureDetector, AnomalyDetector
import socket


class KddFeatureExtractorGUI:

    def __init__(self, root: tk.Tk, threshold: float = 0.7):
        COL_WIDTH = 175
        self.threshold = threshold
        self.root = root
        self.root.geometry()
        self.root.title("Intrusion Detection System Using KD99 Dataset")

        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.scrollbar = ttk.Scrollbar(self.main_frame, orient="vertical")
        self.scrollbar.pack(side="right", fill="y")
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("Treeview", rowheight=25)
        self.style.configure(
            "Treeview.Heading", font=("Helvetica", 10, "bold"), background="PowderBlue"
        )
        self.style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        self.treeview = ttk.Treeview(
            self.main_frame, show=["headings"], yscrollcommand=self.scrollbar.set
        )
        self.treeview["columns"] = [
            "Time",
            "Source IP",
            "Source port",
            "Destination IP",
            "Destination port",
            "Signature label",
            "Confidence",
        ]

        for col in self.treeview["columns"]:
            self.treeview.heading(col, text=col)
            self.treeview.column(col, minwidth=COL_WIDTH, anchor="center")

        self.treeview.pack(fill=tk.BOTH, expand=True)
        self.treeview.tag_configure("normal", background="white")
        self.treeview.tag_configure("abnormal conf", background="lightcoral")
        self.treeview.tag_configure("abnormal unconf", background="lightyellow")

        self.scrollbar.config(command=self.treeview.yview)

        self.root.minsize(COL_WIDTH * len(self.treeview["columns"]), 600)

        self.kdd_feature_extractor = subprocess.Popen(
            ["./kdd99extractor", "-e"], stdout=subprocess.PIPE, universal_newlines=True
        )
        self.root.protocol("WM_DELETE_WINDOW", self.close_window)
        self.thread = Thread(target=self.update_gui)
        self.thread.start()

        self.sd = SignatureDetector(
            "signature_detection/X_signature_detection.h5",
            "signature_detection/X_SD_scaler.pkl",
            "signature_detection/X_SD_cat_input_codes.pkl",
        )

        # self.ad = AnomalyDetector(
        #     "anomaly_detection/encoder.h5",
        #     "anomaly_detection/AD_scaler.pkl",
        #     "anomaly_detection/AD_cat_input_codes.pkl",
        #     "anomaly_detection/AD_lof.pkl",
        # )

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        self.ip = s.getsockname()[0]
        s.close()

    def update_gui(self):

        while True:
            output = self.kdd_feature_extractor.stdout.readline().strip()
            output = output.split(",")
            output[9] = str(min(int(output[9]), 511))
            output[10] = str(min(int(output[10]), 511))
            output[18] = str(min(int(output[18]), 255))
            output[19] = str(min(int(output[19]), 255))
            if not output:
                break

            display_data = output[-5:]

            if display_data[0] == self.ip:
                continue
            
            output = ",".join(output[:-5])
            print(output)
            display_data.insert(0, display_data.pop(-1))

            datetime_obj = datetime.fromisoformat(display_data[0])
            display_data[0] = datetime_obj.strftime("%Y-%m-%d %I:%M:%S %p")

            try:
                sd_output, prob = self.sd.predict(output)
                sd_output = sd_output[0]
            except:
                continue
            if sd_output == "normal":
                tag = "normal"
            elif prob > self.threshold:
                tag = "abnormal conf"
            else:
                tag = "abnormal unconf"

            display_data.extend([sd_output, prob])

            current_scroll_position = self.treeview.yview()[1]

            self.treeview.insert("", "end", values=display_data, tags=(tag,))
            # if at the bottm of the treeview scroll down
            if current_scroll_position == 1.0:
                self.treeview.yview_moveto(1)

            self.root.update_idletasks()

    def close_window(self):
        self.kdd_feature_extractor.kill()  # Kill the subprocess
        self.thread.join()
        self.root.destroy()


if __name__ == "__main__":

    root = tk.Tk()
    app = KddFeatureExtractorGUI(root)
    root.mainloop()
