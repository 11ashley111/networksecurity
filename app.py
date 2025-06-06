import sys
import os
import certifi
ca = certifi.where()

from dotenv import load_dotenv
load_dotenv()
mongo_db_url = os.getenv("MONGO_DB_URL")

import pymongo
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, File, UploadFile, Request, Form
from fastapi.responses import Response, RedirectResponse
from fastapi.templating import Jinja2Templates
from uvicorn import run as app_run
import pandas as pd

from networksecurity.pipeline.training_pipeline import TrainingPipeline
from networksecurity.utils.main_utils.utils import load_object
from networksecurity.utils.ml_utils.model.estimator import NetworkModel
from networksecurity.utils.feature_extractor import extract_features_from_url
from networksecurity.exception.exception import NetworkSecurityException

client = pymongo.MongoClient(mongo_db_url, tlsCAFile=ca)

app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="./templates")

@app.get("/", tags=["authentication"])
async def index():
    return RedirectResponse(url="/predict")

@app.get("/train")
async def train_route():
    try:
        train_pipeline = TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except Exception as e:
        raise NetworkSecurityException(e, sys)

# GET + POST route for CSV prediction
@app.get("/predict")
async def predict_form(request: Request):
    # Render empty form page
    return templates.TemplateResponse("table.html", {"request": request})

@app.post("/predict")
async def predict_route(request: Request, file: UploadFile = File(...)):
    try:
        df = pd.read_csv(file.file)
        preprocessor = load_object("final_model/preprocessor.pkl")
        final_model = load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocessor, model=final_model)
        y_pred = network_model.predict(df)
        df['predicted_column'] = y_pred
        df.to_csv('prediction_output/output.csv', index=False)
        table_html = df.to_html(classes='table table-striped')
        return templates.TemplateResponse("table.html", {"request": request, "table": table_html})
    except Exception as e:
        raise NetworkSecurityException(e, sys)

# GET + POST for single URL prediction
@app.get("/predict_url")
async def predict_url_form(request: Request):
    return templates.TemplateResponse("table.html", {"request": request})

@app.post("/predict_url")
async def predict_url(request: Request, url: str = Form(...)):
    try:
        feature_names = [
            "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
            "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
            "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
            "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
            "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
            "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page",
            "Statistical_report"
        ]
        features = extract_features_from_url(url)
        df = pd.DataFrame([features], columns=feature_names)

        preprocessor = load_object("final_model/preprocessor.pkl")
        final_model = load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocessor, model=final_model)

        pred = network_model.predict(df)[0]
        prediction_label = "Legitimate" if pred == 1 else "Phishing"

        return templates.TemplateResponse("table.html", {
            "request": request,
            "url": url,
            "prediction": prediction_label
        })
    except Exception as e:
        return templates.TemplateResponse("table.html", {
            "request": request,
            "url": url,
            "prediction": f"Error: {str(e)}"
        })

if __name__ == "__main__":
    app_run(app, host="localhost", port=8000)
