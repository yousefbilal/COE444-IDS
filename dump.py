import subprocess
from io import BytesIO
import time
import sys
from predictor import SignatureDetector, AnomalyDetector
tcpdump_process = subprocess.Popen(['tcpdump', '-w', '-'], stdout=subprocess.PIPE)
kdd_feature_extractor = subprocess.Popen('./kdd99extractor', stdin=tcpdump_process.stdout, stdout = subprocess.PIPE)

sd = SignatureDetector('signature_detection/signature_detection.keras', 'signature_detection/SD_scaler.pkl', 'signature_detection/SD_cat_input_codes.pkl')

while True:
    if tcpdump_process.poll() is not None and tcpdump_process.returncode != 0:
        print("tcpdump exited with code:", tcpdump_process.returncode)
        sys.exit(1)
    if kdd_feature_extractor.poll() is not None and kdd_feature_extractor.returncode != 0:
        print("kdd_feature_extractor exited with code:", kdd_feature_extractor.returncode)
        sys.exit(1)

    
    data = kdd_feature_extractor.stdout.readline()
    print(data)
    pred = sd.predict(data)
    print(pred)
    
    time.sleep(5)
