import os

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
from keras.models import load_model
import numpy as np
from keras.optimizers import Adam
from keras.layers import Layer
from tensorflow import math
import pandas as pd
import pickle
from io import StringIO
from abc import ABC, abstractmethod


class Predictor(ABC):

    columns = [
        "duration",
        "protocol_type",
        "service",
        "flag",
        "src_bytes",
        "dst_bytes",
        "land",
        "wrong_fragment",
        "urgent",
        "count",
        "srv_count",
        "serror_rate",
        "srv_serror_rate",
        "rerror_rate",
        "srv_rerror_rate",
        "same_srv_rate",
        "diff_srv_rate",
        "srv_diff_host_rate",
        "dst_host_count",
        "dst_host_srv_count",
        "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate",
        "dst_host_srv_serror_rate",
        "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate",
    ]

    cat_inputs = ["protocol_type", "land", "flag", "service"]

    def __init__(
        self, model_path, scaler_path, cat_input_codes_path, custom_objest=None
    ):
        self.model = load_model(model_path, custom_objects=custom_objest)
        self.scaler = pickle.load(open(scaler_path, "rb"))
        self.cat_input_codes = pickle.load(open(cat_input_codes_path, "rb"))

    def preprocess(self, data):
        data = pd.read_csv(StringIO(data), names=Predictor.columns)
        data[Predictor.cat_inputs] = data[Predictor.cat_inputs].astype("category")
        X_numeric = data.select_dtypes(exclude=["category"])
        X_cat = data.select_dtypes(include=["category"])

        for col in X_cat.columns:
            X_cat[col] = [self.cat_input_codes[col].index(i) for i in X_cat[col]]

        X_numeric = pd.DataFrame(
            self.scaler.transform(X_numeric), columns=X_numeric.columns
        )

        return [X_numeric] + [X_cat[col] for col in X_cat.columns]

    @abstractmethod
    def predict(self, data):
        pass


class SignatureDetector(Predictor):

    attack_labels = ["DoS", "R2L", "U2R", "normal", "probe"]

    def __init__(self, model_path, scaler_path, cat_input_codes_path):
        super().__init__(model_path, scaler_path, cat_input_codes_path)

    @staticmethod
    def to_ordinal(y):
        return np.argmax(y, axis=1)

    @staticmethod
    def to_nominal(y):
        return [
            SignatureDetector.attack_labels[i] for i in SignatureDetector.to_ordinal(y)
        ]

    def predict(self, data):
        X = self.preprocess(data)
        prediction = self.model.predict(X, verbose=0)
        return SignatureDetector.to_nominal(prediction), np.max(prediction)


class ReverseCategoryEncodingLayer(Layer):
    def __init__(self, num_classes, **kwargs):
        super().__init__(**kwargs)
        self.num_classes = num_classes
        self.trainable = False

    def call(self, inputs):
        # Assuming inputs are one-hot encoded probabilities
        # Convert back to class indices
        predicted_indices = math.argmax(inputs, axis=-1)
        return predicted_indices

    def get_config(self):
        config = super(ReverseCategoryEncodingLayer, self).get_config()
        config.update({"num_classes": self.num_classes})
        return config


class AnomalyDetector(Predictor):

    def __init__(self, model_path, scaler_path, cat_input_codes_path, lof_path):
        super().__init__(
            model_path,
            scaler_path,
            cat_input_codes_path,
            custom_objest={
                "ReverseCategoryEncodingLayer": ReverseCategoryEncodingLayer
            },
        )
        self.model.compile(optimizer=Adam(0.0001), loss="mse")
        self.lof = pickle.load(open(lof_path, "rb"))

    @staticmethod
    def to_nominal(y):
        return ["abnormal" if i == -1 else "normal" for i in y]

    def predict(self, data):
        X = self.preprocess(data)
        embeddings = self.model.predict(X, verbose=0)
        return AnomalyDetector.to_nominal(self.lof.predict(embeddings))
