# GNU Affero General Public License v3.0
#
# Copyright (C) 2024 AGPL Neural Network Project
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

import pickle

import numpy as np


class AGPLNeuralNetwork:
    def __init__(self, layers):
        self.layers = layers
        self.weights = [np.random.randn(layers[i], layers[i + 1]) for i in range(len(layers) - 1)]

    def forward(self, x):
        for w in self.weights:
            x = np.tanh(x @ w)
        return x


# Save the model
model = AGPLNeuralNetwork([784, 128, 64, 10])

with open("integration_test_data/agpl_component/agpl_model.pkl", "wb") as f:
    pickle.dump(model, f)
