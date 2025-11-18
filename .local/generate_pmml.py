import pandas as pd
from sklearn.datasets import load_iris
from sklearn.ensemble import RandomForestClassifier
from sklearn2pmml import sklearn2pmml
from sklearn2pmml.pipeline import PMMLPipeline

# 1. Load Data (Using Pandas helps the PMML know the column names automatically)
iris = load_iris()
X = pd.DataFrame(iris.data, columns=iris.feature_names)
y = pd.Series(iris.target_names[iris.target], name="species")

# 2. Create a Pipeline
# Note: We use PMMLPipeline instead of the standard sklearn Pipeline
pipeline = PMMLPipeline([
    ("classifier", RandomForestClassifier(n_estimators=10))
])

# 3. Train the model
pipeline.fit(X, y)

# 4. Export to PMML
# This creates the file 'iris_model.pmml' in your folder
sklearn2pmml(pipeline, "iris_model.pmml", with_repr=True)

print("Success! 'iris_model.pmml' has been created.")
