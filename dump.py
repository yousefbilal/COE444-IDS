import subprocess
import time
import sys
from predictor import SignatureDetector, AnomalyDetector


kdd_feature_extractor = subprocess.Popen('./kdd99extractor', stdout=subprocess.PIPE, stderr=sys.stdout)

# print(kdd_feature_extractor.communicate(b))
while True:
    pass
